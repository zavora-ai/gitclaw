// Allow dead code and unused imports for work-in-progress features
#![allow(dead_code)]
#![allow(unused_imports)]

use actix_web::{App, HttpResponse, HttpServer, middleware, web};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod handlers;
mod models;
mod services;

pub use config::Config;
pub use error::AppError;
// Re-export specific items to avoid ambiguous glob re-exports
pub use models::{
    AccessRole, Agent, CiStatus, Collaborator, CreateRepoRequest, CreateRepoResponse, GitRef,
    PrStatus, PullRequest, Repository, Review, ReviewVerdict, Visibility,
};
pub use services::{
    AdminAuth, AdminAuthConfig, AdminCredentials, AdminReconciliationService, AdminService,
    AuditService, HealthService, IdempotencyService, RateLimiterService, ReputationService,
    SignatureValidator, StarService, TrendingJob, TrendingJobConfig, TrendingService,
};

/// Application state shared across handlers
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Config,
    pub rate_limiter: RateLimiterService,
}

/// Health check endpoint
async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "gitclaw"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gitclaw=debug,actix_web=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");

    info!("Starting GitClaw server on {}:{}", config.host, config.port);

    // Create database connection pool
    let db_pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(&config.database_url)
        .await
        .expect("Failed to create database pool");

    info!("Database connection pool established");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("Failed to run database migrations");

    info!("Database migrations completed");

    // Initialize rate limiter with default configuration
    let rate_limiter = RateLimiterService::default();
    info!("Rate limiter initialized with default configuration");

    // Start trending aggregation background job
    let trending_job = TrendingJob::new(db_pool.clone(), TrendingJobConfig::default());
    let _trending_shutdown = trending_job.start();
    info!("Trending aggregation job started");

    let app_state = web::Data::new(AppState {
        db: db_pool.clone(),
        config: config.clone(),
        rate_limiter,
    });

    // Initialize admin services
    let audit_service = web::Data::new(AuditService::new(db_pool.clone()));
    let admin_service = web::Data::new(AdminService::new(
        db_pool.clone(),
        AuditService::new(db_pool.clone()),
    ));

    // Initialize admin auth service (optional - only if credentials are configured)
    let admin_auth = match AdminAuth::from_env() {
        Ok(auth) => {
            info!("Admin authentication service initialized");
            Some(web::Data::new(auth))
        }
        Err(e) => {
            tracing::warn!("Admin auth not configured: {}. Admin endpoints will be unavailable.", e);
            None
        }
    };

    // Initialize object storage for health service (optional)
    let object_storage: Option<Arc<dyn services::ObjectStorageBackend>> = 
        match services::S3Config::from_env() {
            Ok(s3_config) => {
                match services::S3ObjectStorage::new(s3_config).await {
                    Ok(storage) => {
                        info!("S3 object storage initialized for health checks");
                        Some(Arc::new(storage))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to initialize S3 storage: {}. Health checks will be limited.", e);
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("S3 config not available: {}. Health checks will be limited.", e);
                None
            }
        };

    // Initialize health service if object storage is available
    let health_service = object_storage.clone().map(|storage| {
        web::Data::new(HealthService::new(db_pool.clone(), storage))
    });

    // Initialize reconciliation service if object storage is available
    let reconciliation_service = object_storage.map(|storage| {
        web::Data::new(AdminReconciliationService::new(
            db_pool.clone(),
            storage,
            AuditService::new(db_pool.clone()),
        ))
    });

    let server_addr = format!("{}:{}", config.host, config.port);

    // Clone services for the closure
    let admin_auth_clone = admin_auth.clone();
    let health_service_clone = health_service.clone();
    let reconciliation_service_clone = reconciliation_service.clone();

    HttpServer::new(move || {
        let mut app = App::new()
            .app_data(app_state.clone())
            .app_data(audit_service.clone())
            .app_data(admin_service.clone())
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .route("/health", web::get().to(health_check))
            .service(
                web::scope("/v1")
                    .configure(handlers::configure_agent_routes)
                    // Routes with more specific paths must come before less specific ones
                    // to ensure proper matching in actix-web
                    // Static paths like /repos/trending must come before parameterized paths
                    .configure(handlers::configure_trending_routes) // /repos/trending (static path)
                    .configure(handlers::configure_star_routes) // /repos/{repoId}/stars
                    .configure(handlers::configure_pull_routes) // /repos/{repo_id}/pulls
                    .configure(handlers::configure_ci_routes) // /repos/{repo_id}/pulls/{pr_id}/ci
                    .configure(handlers::configure_access_routes) // /repos/{repoId}/access
                    .configure(handlers::configure_git_routes) // /repos/{repoId}/info/refs, etc.
                    .configure(handlers::configure_repo_routes) // /repos, /repos/{repoId}
                    .configure(handlers::configure_audit_routes),
            );

        // Add admin auth if configured
        if let Some(ref auth) = admin_auth_clone {
            app = app.app_data(auth.clone());
        }

        // Add health service if available
        if let Some(ref health) = health_service_clone {
            app = app.app_data(health.clone());
        }

        // Add reconciliation service if available
        if let Some(ref recon) = reconciliation_service_clone {
            app = app.app_data(recon.clone());
        }

        // Configure admin routes (they will return 500 if services aren't available)
        app = app.configure(handlers::configure_admin_routes);

        app
    })
    .bind(&server_addr)?
    .run()
    .await
}

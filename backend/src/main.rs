use actix_web::{web, App, HttpResponse, HttpServer, middleware};
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod handlers;
mod models;
mod services;

pub use config::Config;
pub use error::AppError;
pub use models::*;
pub use services::*;

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
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "gitclaw=debug,actix_web=info".into()))
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
        db: db_pool,
        config: config.clone(),
        rate_limiter,
    });

    let server_addr = format!("{}:{}", config.host, config.port);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .route("/health", web::get().to(health_check))
            .service(
                web::scope("/v1")
                    .configure(handlers::configure_agent_routes)
                    .configure(handlers::configure_repo_routes)
                    .configure(handlers::configure_git_routes)
                    .configure(handlers::configure_pull_routes)
                    .configure(handlers::configure_ci_routes)
                    .configure(handlers::configure_star_routes)
                    .configure(handlers::configure_trending_routes)
                    .configure(handlers::configure_audit_routes)
            )
    })
    .bind(&server_addr)?
    .run()
    .await
}

//! Trending handlers
//!
//! HTTP handlers for trending repository discovery.
//! Design Reference: DR-12.1 (Trending Service)

use actix_web::{HttpResponse, web};
use serde::Serialize;

use crate::AppState;
use crate::error::AppError;
use crate::models::{TrendingQuery, TrendingWindow};
use crate::services::TrendingService;
use crate::services::trending::TrendingError;

/// Standard API response wrapper
#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    data: T,
    meta: ResponseMeta,
}

#[derive(Serialize)]
struct ResponseMeta {
    request_id: String,
}

impl<T: Serialize> ApiResponse<T> {
    fn new(data: T) -> Self {
        Self {
            data,
            meta: ResponseMeta {
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        }
    }
}

/// GET /v1/repos/trending
///
/// Get trending repositories for a given time window.
/// Reads from precomputed repo_trending_scores table.
///
/// Query Parameters:
/// - window: Time window (1h, 24h, 7d, 30d). Default: 24h
/// - limit: Maximum number of results. Default: 50, Max: 100
///
/// Requirements: 17.1, 17.5
/// Design: DR-12.1 (Trending Service)
pub async fn get_trending(
    state: web::Data<AppState>,
    query: web::Query<TrendingQuery>,
) -> Result<HttpResponse, AppError> {
    // Parse and validate window parameter (Requirement 17.1)
    let window = match &query.window {
        Some(w) => w.parse::<TrendingWindow>().map_err(|e| {
            AppError::Validation(format!(
                "Invalid window parameter: {e}. Valid values are: 1h, 24h, 7d, 30d"
            ))
        })?,
        None => TrendingWindow::default(),
    };

    let trending_service = TrendingService::new(state.db.clone());

    let response = trending_service
        .get_trending(window, query.limit)
        .await
        .map_err(map_trending_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// Map trending errors to application errors
fn map_trending_error(e: TrendingError) -> AppError {
    match e {
        TrendingError::InvalidWindow(msg) => AppError::Validation(msg),
        TrendingError::Database(e) => AppError::Database(e),
    }
}

/// Configure trending routes
pub fn configure_trending_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/repos/trending").route(web::get().to(get_trending)));
}

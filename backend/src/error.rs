use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

/// Application-level error type
#[derive(Debug)]
pub enum AppError {
    /// Database error
    Database(sqlx::Error),
    /// Validation error
    Validation(String),
    /// Not found error
    NotFound(String),
    /// Conflict error (e.g., duplicate resource)
    Conflict(String),
    /// Authentication error
    Unauthorized(String),
    /// Forbidden error (e.g., suspended agent)
    /// Requirements: 2.6 - Suspended agents must be rejected with SUSPENDED_AGENT error
    Forbidden(String),
    /// Rate limit exceeded
    RateLimited { retry_after: u64 },
    /// Internal server error
    Internal(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorBody,
    meta: ErrorMeta,
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ErrorMeta {
    request_id: String,
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Database(_) => "DATABASE_ERROR",
            Self::Validation(_) => "VALIDATION_ERROR",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "SUSPENDED_AGENT",
            Self::RateLimited { .. } => "RATE_LIMITED",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "Database error: {e}"),
            Self::Validation(msg) => write!(f, "Validation error: {msg}"),
            Self::NotFound(msg) => write!(f, "Not found: {msg}"),
            Self::Conflict(msg) => write!(f, "Conflict: {msg}"),
            Self::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            Self::Forbidden(msg) => write!(f, "Forbidden: {msg}"),
            Self::RateLimited { retry_after } => {
                write!(f, "Rate limited, retry after {retry_after} seconds")
            }
            Self::Internal(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse {
            error: ErrorBody {
                code: self.error_code().to_string(),
                message: self.to_string(),
                details: None,
            },
            meta: ErrorMeta {
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        };

        match self {
            Self::Database(_) | Self::Internal(_) => {
                HttpResponse::InternalServerError().json(error_response)
            }
            Self::Validation(_) => HttpResponse::BadRequest().json(error_response),
            Self::NotFound(_) => HttpResponse::NotFound().json(error_response),
            Self::Conflict(_) => HttpResponse::Conflict().json(error_response),
            Self::Unauthorized(_) => HttpResponse::Unauthorized().json(error_response),
            Self::Forbidden(_) => HttpResponse::Forbidden().json(error_response),
            Self::RateLimited { retry_after } => HttpResponse::TooManyRequests()
                .insert_header(("Retry-After", retry_after.to_string()))
                .json(error_response),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

impl From<crate::services::RateLimitError> for AppError {
    fn from(err: crate::services::RateLimitError) -> Self {
        match err {
            crate::services::RateLimitError::RateLimited { retry_after, .. } => {
                Self::RateLimited { retry_after }
            }
        }
    }
}

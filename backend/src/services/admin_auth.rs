//! Admin Authentication Service
//!
//! Provides authentication and session management for admin users.
//! Supports login, logout, and token validation with in-memory session storage.
//!
//! Design Reference: Admin Auth Middleware (design.md)
//! Requirements: 6.1, 6.2, 6.3, 6.5

use std::collections::HashMap;
use std::future::{Ready, ready};
use std::sync::Arc;

use actix_web::{FromRequest, HttpRequest, HttpResponse, dev::Payload, web};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Default session duration in hours
const DEFAULT_SESSION_DURATION_HOURS: i64 = 24;

/// Errors that can occur during admin authentication
#[derive(Debug, Error)]
pub enum AuthError {
    /// Invalid credentials provided
    #[error("Invalid admin credentials")]
    InvalidCredentials,

    /// Session has expired
    #[error("Admin session expired")]
    SessionExpired,

    /// Session token not found
    #[error("Session not found")]
    SessionNotFound,

    /// Admin credentials not configured
    #[error("Admin credentials not configured: {0}")]
    NotConfigured(String),
}

/// Admin session information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSession {
    /// Unique identifier for the admin (username)
    pub admin_id: String,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// When the session expires
    pub expires_at: DateTime<Utc>,
}

impl AdminSession {
    /// Create a new admin session
    pub fn new(admin_id: impl Into<String>, duration_hours: i64) -> Self {
        let now = Utc::now();
        Self {
            admin_id: admin_id.into(),
            created_at: now,
            expires_at: now + Duration::hours(duration_hours),
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Admin credentials loaded from environment
#[derive(Debug, Clone)]
pub struct AdminCredentials {
    /// Admin username
    pub username: String,
    /// SHA256 hash of the admin password
    pub password_hash: String,
}

impl AdminCredentials {
    /// Load admin credentials from environment variables
    ///
    /// Expects:
    /// - `ADMIN_USERNAME`: The admin username
    /// - `ADMIN_PASSWORD_HASH`: SHA256 hash of the admin password (hex-encoded)
    ///
    /// Requirements: 6.5
    pub fn from_env() -> Result<Self, AuthError> {
        let username = std::env::var("ADMIN_USERNAME")
            .map_err(|_| AuthError::NotConfigured("ADMIN_USERNAME not set".to_string()))?;

        let password_hash = std::env::var("ADMIN_PASSWORD_HASH")
            .map_err(|_| AuthError::NotConfigured("ADMIN_PASSWORD_HASH not set".to_string()))?;

        Ok(Self {
            username,
            password_hash,
        })
    }

    /// Create credentials with explicit values (useful for testing)
    pub fn new(username: impl Into<String>, password_hash: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password_hash: password_hash.into(),
        }
    }

    /// Hash a password using SHA256
    pub fn hash_password(password: &str) -> String {
        let hash = Sha256::digest(password.as_bytes());
        hex::encode(hash)
    }

    /// Verify a password against the stored hash
    pub fn verify_password(&self, password: &str) -> bool {
        let provided_hash = Self::hash_password(password);
        // Use constant-time comparison to prevent timing attacks
        constant_time_eq(&provided_hash, &self.password_hash)
    }
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Configuration for the AdminAuth service
#[derive(Debug, Clone)]
pub struct AdminAuthConfig {
    /// Session duration in hours
    pub session_duration_hours: i64,
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            session_duration_hours: DEFAULT_SESSION_DURATION_HOURS,
        }
    }
}

/// Admin authentication service with session management
///
/// Provides:
/// - Login with username/password validation
/// - Session token generation and validation
/// - Logout (session invalidation)
/// - In-memory session storage with expiration
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// Valid admin session tokens (in production, use Redis or DB)
    sessions: Arc<RwLock<HashMap<String, AdminSession>>>,
    /// Admin credentials from environment
    admin_credentials: AdminCredentials,
    /// Configuration
    config: AdminAuthConfig,
}

impl AdminAuth {
    /// Create a new AdminAuth service with credentials from environment
    ///
    /// Requirements: 6.5
    pub fn from_env() -> Result<Self, AuthError> {
        let credentials = AdminCredentials::from_env()?;
        Ok(Self::new(credentials, AdminAuthConfig::default()))
    }

    /// Create a new AdminAuth service with explicit credentials
    pub fn new(credentials: AdminCredentials, config: AdminAuthConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            admin_credentials: credentials,
            config,
        }
    }

    /// Create a new session for valid credentials
    ///
    /// Returns a tuple of (session_token, AdminSession) on success.
    ///
    /// Requirements: 6.2
    pub async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(String, AdminSession), AuthError> {
        // Validate username
        if username != self.admin_credentials.username {
            return Err(AuthError::InvalidCredentials);
        }

        // Validate password
        if !self.admin_credentials.verify_password(password) {
            return Err(AuthError::InvalidCredentials);
        }

        // Generate session token
        let token = Self::generate_token();

        // Create session
        let session = AdminSession::new(username, self.config.session_duration_hours);

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(token.clone(), session.clone());
        }

        Ok((token, session))
    }

    /// Validate a session token and return the admin session if valid
    ///
    /// Requirements: 6.1, 6.3
    pub async fn validate_token(&self, token: &str) -> Result<AdminSession, AuthError> {
        let sessions = self.sessions.read().await;

        let session = sessions
            .get(token)
            .ok_or(AuthError::SessionNotFound)?
            .clone();

        // Check if session has expired
        if session.is_expired() {
            // Drop the read lock before acquiring write lock
            drop(sessions);
            // Remove expired session
            self.sessions.write().await.remove(token);
            return Err(AuthError::SessionExpired);
        }

        Ok(session)
    }

    /// Invalidate a session (logout)
    pub async fn logout(&self, token: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(token);
    }

    /// Generate a secure random session token
    fn generate_token() -> String {
        // Use UUID v4 for session tokens
        Uuid::new_v4().to_string()
    }

    /// Clean up expired sessions (can be called periodically)
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| !session.is_expired());
    }

    /// Get the number of active sessions (useful for monitoring)
    pub async fn active_session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.values().filter(|s| !s.is_expired()).count()
    }

    /// Get the admin username (useful for audit logging)
    pub fn admin_username(&self) -> &str {
        &self.admin_credentials.username
    }
}

// ============================================================================
// Admin Auth Middleware - FromRequest Implementation
// ============================================================================
//
// This implementation allows handlers to extract AdminSession directly from
// requests by including it as a parameter. The middleware:
// 1. Extracts Bearer token from Authorization header
// 2. Validates token using AdminAuth service
// 3. Returns 401 Unauthorized for missing/invalid/expired tokens
// 4. Makes AdminSession available to handlers
//
// Requirements: 6.1, 6.3
// Design Reference: Admin Auth Middleware (design.md)

/// Error response for authentication failures
#[derive(Debug, Serialize)]
struct AuthErrorResponse {
    error: AuthErrorBody,
    meta: AuthErrorMeta,
}

#[derive(Debug, Serialize)]
struct AuthErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct AuthErrorMeta {
    request_id: String,
}

impl AuthErrorResponse {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: AuthErrorBody {
                code: code.into(),
                message: message.into(),
            },
            meta: AuthErrorMeta {
                request_id: Uuid::new_v4().to_string(),
            },
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new("UNAUTHORIZED", message)
    }

    fn session_expired() -> Self {
        Self::new("SESSION_EXPIRED", "Admin session has expired")
    }

    fn invalid_token() -> Self {
        Self::new("INVALID_TOKEN", "Invalid or missing authentication token")
    }
}

/// Extract Bearer token from Authorization header
///
/// Expected format: "Bearer <token>"
fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    // Check for "Bearer " prefix (case-insensitive)
    if auth_str.len() > 7 && auth_str[..7].eq_ignore_ascii_case("Bearer ") {
        Some(auth_str[7..].to_string())
    } else {
        None
    }
}

/// Implement FromRequest for AdminSession to enable automatic extraction
/// from HTTP requests in handlers.
///
/// Usage in handlers:
/// ```rust,ignore
/// pub async fn protected_handler(
///     admin: AdminSession,  // Automatically extracted and validated
/// ) -> Result<HttpResponse, AppError> {
///     // admin.admin_id contains the authenticated admin's ID
/// }
/// ```
///
/// Requirements: 6.1, 6.3
impl FromRequest for AdminSession {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Clone what we need for the async block
        let req = req.clone();

        Box::pin(async move {
            // Get AdminAuth from app data
            let admin_auth = req
                .app_data::<web::Data<AdminAuth>>()
                .ok_or_else(|| {
                    tracing::error!("AdminAuth not configured in app data");
                    actix_web::error::InternalError::from_response(
                        "Internal server error",
                        HttpResponse::InternalServerError().json(AuthErrorResponse::new(
                            "INTERNAL_ERROR",
                            "Authentication service not configured",
                        )),
                    )
                })?;

            // Extract Bearer token from Authorization header
            let token = extract_bearer_token(&req).ok_or_else(|| {
                tracing::debug!("Missing or invalid Authorization header");
                actix_web::error::InternalError::from_response(
                    "Unauthorized",
                    HttpResponse::Unauthorized().json(AuthErrorResponse::invalid_token()),
                )
            })?;

            // Validate the token
            let session = admin_auth.validate_token(&token).await.map_err(|e| {
                match e {
                    AuthError::SessionExpired => {
                        tracing::debug!("Admin session expired");
                        actix_web::error::InternalError::from_response(
                            "Session expired",
                            HttpResponse::Unauthorized().json(AuthErrorResponse::session_expired()),
                        )
                    }
                    AuthError::SessionNotFound => {
                        tracing::debug!("Admin session not found");
                        actix_web::error::InternalError::from_response(
                            "Unauthorized",
                            HttpResponse::Unauthorized().json(AuthErrorResponse::invalid_token()),
                        )
                    }
                    _ => {
                        tracing::warn!("Admin auth error: {}", e);
                        actix_web::error::InternalError::from_response(
                            "Unauthorized",
                            HttpResponse::Unauthorized()
                                .json(AuthErrorResponse::unauthorized(e.to_string())),
                        )
                    }
                }
            })?;

            Ok(session)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_credentials() -> AdminCredentials {
        let password = "test-password-123";
        let password_hash = AdminCredentials::hash_password(password);
        AdminCredentials::new("admin", password_hash)
    }

    fn create_test_auth() -> AdminAuth {
        AdminAuth::new(create_test_credentials(), AdminAuthConfig::default())
    }

    #[test]
    fn test_password_hashing() {
        let password = "my-secret-password";
        let hash = AdminCredentials::hash_password(password);

        // Hash should be 64 hex characters (SHA256 = 32 bytes = 64 hex chars)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Same password should produce same hash
        let hash2 = AdminCredentials::hash_password(password);
        assert_eq!(hash, hash2);

        // Different password should produce different hash
        let hash3 = AdminCredentials::hash_password("different-password");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_password_verification() {
        let password = "test-password";
        let hash = AdminCredentials::hash_password(password);
        let credentials = AdminCredentials::new("admin", hash);

        assert!(credentials.verify_password(password));
        assert!(!credentials.verify_password("wrong-password"));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hell"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_admin_session_creation() {
        let session = AdminSession::new("admin", 24);

        assert_eq!(session.admin_id, "admin");
        assert!(!session.is_expired());
        assert!(session.expires_at > session.created_at);
    }

    #[test]
    fn test_admin_session_expiration() {
        let mut session = AdminSession::new("admin", 24);

        // Session should not be expired initially
        assert!(!session.is_expired());

        // Manually set expires_at to the past
        session.expires_at = Utc::now() - Duration::hours(1);
        assert!(session.is_expired());
    }

    #[tokio::test]
    async fn test_login_success() {
        let auth = create_test_auth();

        let result = auth.login("admin", "test-password-123").await;
        assert!(result.is_ok());

        let (token, session) = result.unwrap();
        assert!(!token.is_empty());
        assert_eq!(session.admin_id, "admin");
        assert!(!session.is_expired());
    }

    #[tokio::test]
    async fn test_login_invalid_username() {
        let auth = create_test_auth();

        let result = auth.login("wrong-user", "test-password-123").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        let auth = create_test_auth();

        let result = auth.login("admin", "wrong-password").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_validate_token_success() {
        let auth = create_test_auth();

        // Login first
        let (token, _) = auth.login("admin", "test-password-123").await.unwrap();

        // Validate the token
        let result = auth.validate_token(&token).await;
        assert!(result.is_ok());

        let session = result.unwrap();
        assert_eq!(session.admin_id, "admin");
    }

    #[tokio::test]
    async fn test_validate_token_not_found() {
        let auth = create_test_auth();

        let result = auth.validate_token("non-existent-token").await;
        assert!(matches!(result, Err(AuthError::SessionNotFound)));
    }

    #[tokio::test]
    async fn test_validate_token_expired() {
        let credentials = create_test_credentials();
        let config = AdminAuthConfig {
            session_duration_hours: 0, // Immediate expiration
        };
        let auth = AdminAuth::new(credentials, config);

        // Login
        let (token, _) = auth.login("admin", "test-password-123").await.unwrap();

        // Wait a tiny bit to ensure expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Token should be expired
        let result = auth.validate_token(&token).await;
        assert!(matches!(result, Err(AuthError::SessionExpired)));
    }

    #[tokio::test]
    async fn test_logout() {
        let auth = create_test_auth();

        // Login
        let (token, _) = auth.login("admin", "test-password-123").await.unwrap();

        // Verify token is valid
        assert!(auth.validate_token(&token).await.is_ok());

        // Logout
        auth.logout(&token).await;

        // Token should no longer be valid
        let result = auth.validate_token(&token).await;
        assert!(matches!(result, Err(AuthError::SessionNotFound)));
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let auth = create_test_auth();

        // Create multiple sessions
        let (token1, _) = auth.login("admin", "test-password-123").await.unwrap();
        let (token2, _) = auth.login("admin", "test-password-123").await.unwrap();

        // Both tokens should be different
        assert_ne!(token1, token2);

        // Both tokens should be valid
        assert!(auth.validate_token(&token1).await.is_ok());
        assert!(auth.validate_token(&token2).await.is_ok());

        // Logout one session
        auth.logout(&token1).await;

        // Only token2 should be valid
        assert!(matches!(
            auth.validate_token(&token1).await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(auth.validate_token(&token2).await.is_ok());
    }

    #[tokio::test]
    async fn test_active_session_count() {
        let auth = create_test_auth();

        assert_eq!(auth.active_session_count().await, 0);

        // Create sessions
        let (token1, _) = auth.login("admin", "test-password-123").await.unwrap();
        assert_eq!(auth.active_session_count().await, 1);

        let (_, _) = auth.login("admin", "test-password-123").await.unwrap();
        assert_eq!(auth.active_session_count().await, 2);

        // Logout one
        auth.logout(&token1).await;
        assert_eq!(auth.active_session_count().await, 1);
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        let credentials = create_test_credentials();
        let config = AdminAuthConfig {
            session_duration_hours: 0, // Immediate expiration
        };
        let auth = AdminAuth::new(credentials, config);

        // Create sessions
        let (_, _) = auth.login("admin", "test-password-123").await.unwrap();
        let (_, _) = auth.login("admin", "test-password-123").await.unwrap();

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Sessions should be expired but still in storage
        {
            let sessions = auth.sessions.read().await;
            assert_eq!(sessions.len(), 2);
        }

        // Cleanup
        auth.cleanup_expired_sessions().await;

        // Sessions should be removed
        {
            let sessions = auth.sessions.read().await;
            assert_eq!(sessions.len(), 0);
        }
    }

    #[test]
    fn test_admin_username() {
        let auth = create_test_auth();
        assert_eq!(auth.admin_username(), "admin");
    }

    #[test]
    fn test_credentials_from_env_missing() {
        // Clear any existing env vars
        // SAFETY: This test is single-threaded and we're only modifying test-specific env vars
        unsafe {
            std::env::remove_var("ADMIN_USERNAME");
            std::env::remove_var("ADMIN_PASSWORD_HASH");
        }

        let result = AdminCredentials::from_env();
        assert!(matches!(result, Err(AuthError::NotConfigured(_))));
    }

    // ========================================================================
    // Middleware Tests
    // ========================================================================

    #[test]
    fn test_extract_bearer_token_valid() {
        use actix_web::test::TestRequest;

        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer my-token-123"))
            .to_http_request();

        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("my-token-123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_case_insensitive() {
        use actix_web::test::TestRequest;

        // Test lowercase "bearer"
        let req = TestRequest::default()
            .insert_header(("Authorization", "bearer my-token-123"))
            .to_http_request();
        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("my-token-123".to_string()));

        // Test mixed case "BEARER"
        let req = TestRequest::default()
            .insert_header(("Authorization", "BEARER my-token-456"))
            .to_http_request();
        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("my-token-456".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_missing_header() {
        use actix_web::test::TestRequest;

        let req = TestRequest::default().to_http_request();
        let token = extract_bearer_token(&req);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        use actix_web::test::TestRequest;

        // Basic auth instead of Bearer
        let req = TestRequest::default()
            .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
            .to_http_request();
        let token = extract_bearer_token(&req);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_empty_token() {
        use actix_web::test::TestRequest;

        // "Bearer " with no token after should return None (invalid)
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer "))
            .to_http_request();
        let token = extract_bearer_token(&req);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_with_spaces() {
        use actix_web::test::TestRequest;

        // Token with spaces (should preserve them)
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer token with spaces"))
            .to_http_request();
        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("token with spaces".to_string()));
    }

    #[test]
    fn test_auth_error_response_serialization() {
        let response = AuthErrorResponse::unauthorized("Test message");
        let json = serde_json::to_string(&response).unwrap();

        // Verify it contains expected fields
        assert!(json.contains("\"code\":\"UNAUTHORIZED\""));
        assert!(json.contains("\"message\":\"Test message\""));
        assert!(json.contains("\"request_id\""));
    }

    #[test]
    fn test_auth_error_response_session_expired() {
        let response = AuthErrorResponse::session_expired();
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"code\":\"SESSION_EXPIRED\""));
        assert!(json.contains("Admin session has expired"));
    }

    #[test]
    fn test_auth_error_response_invalid_token() {
        let response = AuthErrorResponse::invalid_token();
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"code\":\"INVALID_TOKEN\""));
        assert!(json.contains("Invalid or missing authentication token"));
    }
}

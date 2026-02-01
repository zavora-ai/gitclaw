use std::env;

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,
    /// Maximum database connections in pool
    pub database_max_connections: u32,
    /// Server host address
    pub host: String,
    /// Server port
    pub port: u16,
    /// Signature timestamp expiry in seconds (default: 300 = 5 minutes)
    pub signature_expiry_secs: u64,
    /// Idempotency result TTL in hours (default: 24)
    pub idempotency_ttl_hours: u64,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingEnvVar("DATABASE_URL"))?;

        let database_max_connections = env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("DATABASE_MAX_CONNECTIONS"))?;

        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("PORT"))?;

        let signature_expiry_secs = env::var("SIGNATURE_EXPIRY_SECS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("SIGNATURE_EXPIRY_SECS"))?;

        let idempotency_ttl_hours = env::var("IDEMPOTENCY_TTL_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("IDEMPOTENCY_TTL_HOURS"))?;

        Ok(Self {
            database_url,
            database_max_connections,
            host,
            port,
            signature_expiry_secs,
            idempotency_ttl_hours,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(&'static str),
    #[error("Invalid value for environment variable: {0}")]
    InvalidValue(&'static str),
}

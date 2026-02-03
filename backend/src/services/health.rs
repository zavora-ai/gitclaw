//! Health Service
//!
//! Provides system health monitoring for the admin dashboard.
//! Checks database connectivity, object storage status, and event outbox queue depths.
//!
//! Design Reference: Admin Dashboard Design Document - Health Service
//! Requirements: 5.1, 5.2, 5.3, 5.5

use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::services::object_storage::ObjectStorageBackend;

/// Overall system health status
///
/// Requirements: 5.5
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All components are functioning normally
    Healthy,
    /// Some components have issues but system is operational
    Degraded,
    /// Critical components are failing
    Unhealthy,
}

/// Overall system health status
///
/// Requirements: 5.1, 5.2, 5.3, 5.5
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemHealth {
    /// Overall system status (derived from component statuses)
    pub status: HealthStatus,
    /// Database health information
    pub database: DatabaseHealth,
    /// Object storage health information
    pub object_storage: ObjectStorageHealth,
    /// Event outbox health information
    pub outbox: OutboxHealth,
    /// Timestamp when health check was performed
    pub checked_at: DateTime<Utc>,
}

/// Database health information
///
/// Requirements: 5.1
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseHealth {
    /// Database component status
    pub status: HealthStatus,
    /// Number of active connections in the pool
    pub active_connections: u32,
    /// Number of idle connections in the pool
    pub idle_connections: u32,
    /// Maximum connections configured for the pool
    pub max_connections: u32,
    /// Latency of a simple query in milliseconds
    pub latency_ms: Option<u64>,
    /// Error message if health check failed
    pub error: Option<String>,
}

/// Object storage health information
///
/// Requirements: 5.2
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectStorageHealth {
    /// Object storage component status
    pub status: HealthStatus,
    /// Whether the bucket is accessible
    pub bucket_accessible: bool,
    /// Latency of connectivity test in milliseconds
    pub latency_ms: Option<u64>,
    /// Error message if health check failed
    pub error: Option<String>,
}

/// Event outbox health information
///
/// Requirements: 5.3
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxHealth {
    /// Outbox component status
    pub status: HealthStatus,
    /// Number of pending events waiting to be processed
    pub pending_count: i64,
    /// Number of events currently being processed
    pub processing_count: i64,
    /// Number of dead-lettered events (failed max retries)
    pub dead_count: i64,
    /// Age of the oldest pending event in seconds
    pub oldest_pending_age_seconds: Option<i64>,
}

/// Health service for system monitoring
///
/// Design Reference: Admin Dashboard Design Document - Health Service
/// Requirements: 5.1, 5.2, 5.3, 5.5
#[derive(Clone)]
pub struct HealthService {
    pool: PgPool,
    object_storage: Arc<dyn ObjectStorageBackend>,
}

impl HealthService {
    /// Create a new HealthService instance
    ///
    /// # Arguments
    /// * `pool` - PostgreSQL connection pool for database health checks
    /// * `object_storage` - Object storage backend for S3 health checks
    pub fn new(pool: PgPool, object_storage: Arc<dyn ObjectStorageBackend>) -> Self {
        Self {
            pool,
            object_storage,
        }
    }

    /// Perform comprehensive health check of all system components
    ///
    /// Requirements: 5.1, 5.2, 5.3, 5.5
    ///
    /// Checks database, object storage, and event outbox health.
    /// The overall status is determined by the worst component status:
    /// - If any component is Unhealthy, overall is Unhealthy
    /// - If any component is Degraded (and none Unhealthy), overall is Degraded
    /// - Otherwise, overall is Healthy
    pub async fn check_health(&self) -> SystemHealth {
        // Run all health checks concurrently
        let (database, object_storage, outbox) = tokio::join!(
            self.check_database(),
            self.check_object_storage(),
            self.check_outbox()
        );

        // Determine overall status based on component statuses
        let status = Self::determine_overall_status(&database, &object_storage, &outbox);

        SystemHealth {
            status,
            database,
            object_storage,
            outbox,
            checked_at: Utc::now(),
        }
    }

    /// Check database connectivity and pool status
    ///
    /// Requirements: 5.1
    ///
    /// Returns pool statistics (active, idle, max connections) and
    /// measures latency by executing a simple query.
    pub async fn check_database(&self) -> DatabaseHealth {
        // Get pool statistics
        let pool_size = self.pool.size();
        let pool_options = self.pool.options();
        let max_connections = pool_options.get_max_connections();

        // Calculate active and idle connections
        // SQLx pool.size() returns total acquired connections
        // We estimate idle as total - active (approximation)
        let num_idle = self.pool.num_idle();
        let active_connections = pool_size.saturating_sub(num_idle as u32);
        let idle_connections = num_idle as u32;

        // Measure latency with a simple query
        let start = Instant::now();
        let query_result = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match query_result {
            Ok(_) => {
                // Determine status based on connection pool utilization
                let utilization = if max_connections > 0 {
                    (active_connections as f64) / (max_connections as f64)
                } else {
                    0.0
                };

                let status = if utilization > 0.9 {
                    // Over 90% utilization is degraded
                    HealthStatus::Degraded
                } else {
                    HealthStatus::Healthy
                };

                DatabaseHealth {
                    status,
                    active_connections,
                    idle_connections,
                    max_connections,
                    latency_ms: Some(latency_ms),
                    error: None,
                }
            }
            Err(e) => DatabaseHealth {
                status: HealthStatus::Unhealthy,
                active_connections,
                idle_connections,
                max_connections,
                latency_ms: None,
                error: Some(format!("Database query failed: {e}")),
            },
        }
    }

    /// Check object storage connectivity
    ///
    /// Requirements: 5.2
    ///
    /// Tests bucket accessibility by attempting to list objects with a
    /// non-existent prefix. This verifies connectivity without requiring
    /// any actual objects to exist.
    pub async fn check_object_storage(&self) -> ObjectStorageHealth {
        let start = Instant::now();

        // Test connectivity by listing objects with a health-check prefix
        // This tests bucket access without requiring any actual objects
        let result = self
            .object_storage
            .list_objects("__health_check__", None, None)
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(_) => ObjectStorageHealth {
                status: HealthStatus::Healthy,
                bucket_accessible: true,
                latency_ms: Some(latency_ms),
                error: None,
            },
            Err(e) => {
                // Check if it's a "not found" error (which is actually OK for health check)
                // vs a connectivity/permission error
                let error_str = e.to_string();
                let is_access_error = error_str.contains("AccessDenied")
                    || error_str.contains("access denied")
                    || error_str.contains("BucketNotFound")
                    || error_str.contains("bucket not found")
                    || error_str.contains("ConnectionError")
                    || error_str.contains("connection");

                if is_access_error {
                    ObjectStorageHealth {
                        status: HealthStatus::Unhealthy,
                        bucket_accessible: false,
                        latency_ms: Some(latency_ms),
                        error: Some(format!("Object storage error: {e}")),
                    }
                } else {
                    // NotFound errors for the health check prefix are expected
                    // and indicate the bucket is accessible
                    ObjectStorageHealth {
                        status: HealthStatus::Healthy,
                        bucket_accessible: true,
                        latency_ms: Some(latency_ms),
                        error: None,
                    }
                }
            }
        }
    }

    /// Check event outbox status
    ///
    /// Requirements: 5.3
    ///
    /// Returns queue depths for pending, processing, and dead-lettered events,
    /// as well as the age of the oldest pending event.
    pub async fn check_outbox(&self) -> OutboxHealth {
        // Query outbox statistics
        let stats_result = sqlx::query_as::<_, OutboxStatsRow>(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
                COUNT(*) FILTER (WHERE status = 'processing') as processing_count,
                COUNT(*) FILTER (WHERE status = 'dead') as dead_count,
                EXTRACT(EPOCH FROM (NOW() - MIN(created_at) FILTER (WHERE status = 'pending')))::BIGINT as oldest_pending_age_seconds
            FROM event_outbox
            "#,
        )
        .fetch_one(&self.pool)
        .await;

        match stats_result {
            Ok(stats) => {
                let pending_count = stats.pending_count.unwrap_or(0);
                let processing_count = stats.processing_count.unwrap_or(0);
                let dead_count = stats.dead_count.unwrap_or(0);
                let oldest_pending_age_seconds = stats.oldest_pending_age_seconds;

                // Determine status based on queue health
                let status = Self::determine_outbox_status(
                    pending_count,
                    dead_count,
                    oldest_pending_age_seconds,
                );

                OutboxHealth {
                    status,
                    pending_count,
                    processing_count,
                    dead_count,
                    oldest_pending_age_seconds,
                }
            }
            Err(_e) => OutboxHealth {
                status: HealthStatus::Unhealthy,
                pending_count: 0,
                processing_count: 0,
                dead_count: 0,
                oldest_pending_age_seconds: None,
            },
        }
    }

    /// Determine outbox health status based on queue metrics
    ///
    /// - Unhealthy: Dead letter queue has items (processing failures)
    /// - Degraded: Large pending queue (>1000) or old pending items (>1 hour)
    /// - Healthy: Otherwise
    fn determine_outbox_status(
        pending_count: i64,
        dead_count: i64,
        oldest_pending_age_seconds: Option<i64>,
    ) -> HealthStatus {
        // Dead letters indicate processing failures - this is unhealthy
        if dead_count > 0 {
            return HealthStatus::Unhealthy;
        }

        // Large pending queue or old pending items indicate degraded performance
        const PENDING_THRESHOLD: i64 = 1000;
        const AGE_THRESHOLD_SECONDS: i64 = 3600; // 1 hour

        if pending_count > PENDING_THRESHOLD {
            return HealthStatus::Degraded;
        }

        if let Some(age) = oldest_pending_age_seconds {
            if age > AGE_THRESHOLD_SECONDS {
                return HealthStatus::Degraded;
            }
        }

        HealthStatus::Healthy
    }

    /// Determine overall system status from component statuses
    ///
    /// Requirements: 5.5
    ///
    /// The overall status is the worst of all component statuses:
    /// - If any component is Unhealthy, overall is Unhealthy
    /// - If any component is Degraded, overall is Degraded
    /// - Otherwise, overall is Healthy
    fn determine_overall_status(
        database: &DatabaseHealth,
        object_storage: &ObjectStorageHealth,
        outbox: &OutboxHealth,
    ) -> HealthStatus {
        let statuses = [database.status, object_storage.status, outbox.status];

        if statuses.contains(&HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if statuses.contains(&HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
}

/// Internal row type for outbox statistics query
#[derive(Debug, sqlx::FromRow)]
struct OutboxStatsRow {
    pending_count: Option<i64>,
    processing_count: Option<i64>,
    dead_count: Option<i64>,
    oldest_pending_age_seconds: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_serialization() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    #[test]
    fn test_determine_outbox_status_healthy() {
        let status = HealthService::determine_outbox_status(0, 0, None);
        assert_eq!(status, HealthStatus::Healthy);

        let status = HealthService::determine_outbox_status(100, 0, Some(60));
        assert_eq!(status, HealthStatus::Healthy);
    }

    #[test]
    fn test_determine_outbox_status_degraded_large_queue() {
        let status = HealthService::determine_outbox_status(1001, 0, None);
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_determine_outbox_status_degraded_old_pending() {
        // 2 hours old
        let status = HealthService::determine_outbox_status(10, 0, Some(7200));
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_determine_outbox_status_unhealthy_dead_letters() {
        let status = HealthService::determine_outbox_status(0, 1, None);
        assert_eq!(status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_determine_overall_status_all_healthy() {
        let db = DatabaseHealth {
            status: HealthStatus::Healthy,
            active_connections: 5,
            idle_connections: 10,
            max_connections: 20,
            latency_ms: Some(1),
            error: None,
        };
        let storage = ObjectStorageHealth {
            status: HealthStatus::Healthy,
            bucket_accessible: true,
            latency_ms: Some(10),
            error: None,
        };
        let outbox = OutboxHealth {
            status: HealthStatus::Healthy,
            pending_count: 0,
            processing_count: 0,
            dead_count: 0,
            oldest_pending_age_seconds: None,
        };

        let status = HealthService::determine_overall_status(&db, &storage, &outbox);
        assert_eq!(status, HealthStatus::Healthy);
    }

    #[test]
    fn test_determine_overall_status_one_degraded() {
        let db = DatabaseHealth {
            status: HealthStatus::Degraded,
            active_connections: 18,
            idle_connections: 2,
            max_connections: 20,
            latency_ms: Some(1),
            error: None,
        };
        let storage = ObjectStorageHealth {
            status: HealthStatus::Healthy,
            bucket_accessible: true,
            latency_ms: Some(10),
            error: None,
        };
        let outbox = OutboxHealth {
            status: HealthStatus::Healthy,
            pending_count: 0,
            processing_count: 0,
            dead_count: 0,
            oldest_pending_age_seconds: None,
        };

        let status = HealthService::determine_overall_status(&db, &storage, &outbox);
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_determine_overall_status_one_unhealthy() {
        let db = DatabaseHealth {
            status: HealthStatus::Healthy,
            active_connections: 5,
            idle_connections: 10,
            max_connections: 20,
            latency_ms: Some(1),
            error: None,
        };
        let storage = ObjectStorageHealth {
            status: HealthStatus::Unhealthy,
            bucket_accessible: false,
            latency_ms: None,
            error: Some("Connection refused".to_string()),
        };
        let outbox = OutboxHealth {
            status: HealthStatus::Degraded,
            pending_count: 1500,
            processing_count: 0,
            dead_count: 0,
            oldest_pending_age_seconds: None,
        };

        let status = HealthService::determine_overall_status(&db, &storage, &outbox);
        assert_eq!(status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_database_health_serialization() {
        let health = DatabaseHealth {
            status: HealthStatus::Healthy,
            active_connections: 5,
            idle_connections: 10,
            max_connections: 20,
            latency_ms: Some(1),
            error: None,
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"activeConnections\":5"));
        assert!(json.contains("\"idleConnections\":10"));
        assert!(json.contains("\"maxConnections\":20"));
        assert!(json.contains("\"latencyMs\":1"));
    }

    #[test]
    fn test_system_health_serialization() {
        let health = SystemHealth {
            status: HealthStatus::Healthy,
            database: DatabaseHealth {
                status: HealthStatus::Healthy,
                active_connections: 5,
                idle_connections: 10,
                max_connections: 20,
                latency_ms: Some(1),
                error: None,
            },
            object_storage: ObjectStorageHealth {
                status: HealthStatus::Healthy,
                bucket_accessible: true,
                latency_ms: Some(10),
                error: None,
            },
            outbox: OutboxHealth {
                status: HealthStatus::Healthy,
                pending_count: 0,
                processing_count: 0,
                dead_count: 0,
                oldest_pending_age_seconds: None,
            },
            checked_at: Utc::now(),
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"database\""));
        assert!(json.contains("\"objectStorage\""));
        assert!(json.contains("\"outbox\""));
        assert!(json.contains("\"checkedAt\""));
    }
}

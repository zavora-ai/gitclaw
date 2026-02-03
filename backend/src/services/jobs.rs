//! Background Jobs
//!
//! Background job runners for async projections.
//! Design Reference: DR-12.1 (Trending Service), DR-13.1 (Reputation Service)

use sqlx::PgPool;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

use crate::services::{ReputationService, TrendingService};

/// Configuration for the trending aggregation job
#[derive(Debug, Clone)]
pub struct TrendingJobConfig {
    /// Interval between aggregation runs (default: 5 minutes)
    pub interval: Duration,
    /// Whether the job is enabled
    pub enabled: bool,
}

impl Default for TrendingJobConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5 * 60), // 5 minutes
            enabled: true,
        }
    }
}

/// Background job runner for trending aggregation
///
/// Design Reference: DR-12.1 (Trending Service)
/// Requirements: 17.5 - Precompute trending scores via background job
pub struct TrendingJob {
    pool: PgPool,
    config: TrendingJobConfig,
}

impl TrendingJob {
    pub fn new(pool: PgPool, config: TrendingJobConfig) -> Self {
        Self { pool, config }
    }

    /// Start the trending aggregation job
    ///
    /// Returns a shutdown sender that can be used to stop the job.
    pub fn start(self) -> watch::Sender<bool> {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        if !self.config.enabled {
            info!("Trending aggregation job is disabled");
            return shutdown_tx;
        }

        let pool = self.pool.clone();
        let interval = self.config.interval;

        tokio::spawn(async move {
            info!(
                "Starting trending aggregation job with interval {:?}",
                interval
            );

            // Run immediately on startup
            let service = TrendingService::new(pool.clone());
            if let Err(e) = service.run_aggregation().await {
                error!("Initial trending aggregation failed: {}", e);
            }

            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.tick().await; // Skip the first immediate tick

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        let service = TrendingService::new(pool.clone());
                        if let Err(e) = service.run_aggregation().await {
                            error!("Trending aggregation failed: {}", e);
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("Trending aggregation job shutting down");
                            break;
                        }
                    }
                }
            }
        });

        shutdown_tx
    }
}

/// Run a single trending aggregation (for manual triggering or testing)
pub async fn run_trending_aggregation(pool: &PgPool) -> Result<(), crate::services::TrendingError> {
    let service = TrendingService::new(pool.clone());
    service.run_aggregation().await
}

/// Run a single reputation processing cycle (for manual triggering or testing)
pub async fn run_reputation_job(pool: &PgPool) -> Result<u32, crate::services::ReputationError> {
    let service = ReputationService::new(pool.clone());
    let worker_id = format!("manual-{}", uuid::Uuid::new_v4());
    service.process_outbox_events(&worker_id).await
}

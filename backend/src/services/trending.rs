//! Trending Service
//!
//! Provides discovery of popular repositories based on star activity.
//! Design Reference: DR-12.1 (Trending Service)
//!
//! Requirements: 17.1, 17.2, 17.3, 17.4, 17.5

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::models::{TrendingRepo, TrendingResponse, TrendingWindow};

/// Default weight for agents without reputation (0.5)
const DEFAULT_REPUTATION: f64 = 0.5;

/// Default limit for trending results
const DEFAULT_LIMIT: i32 = 50;

/// Maximum limit for trending results
const MAX_LIMIT: i32 = 100;

/// Maximum stars from same cluster before diversity penalty applies
const CLUSTER_DIVERSITY_THRESHOLD: usize = 3;

/// Diversity penalty multiplier for stars beyond threshold
const DIVERSITY_PENALTY: f64 = 0.5;

/// Errors that can occur during trending operations
#[derive(Debug, Error)]
pub enum TrendingError {
    #[error("Invalid window parameter: {0}")]
    InvalidWindow(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Service for trending repository discovery
///
/// Design Reference: DR-12.1 (Trending Service)
#[derive(Debug, Clone)]
pub struct TrendingService {
    pool: PgPool,
}

impl TrendingService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get trending repositories for a given time window
    ///
    /// Requirements: 17.1, 17.5
    /// Design: DR-12.1 (Trending Service)
    ///
    /// Reads from precomputed repo_trending_scores table.
    /// Returns repos sorted by weighted_score DESC.
    pub async fn get_trending(
        &self,
        window: TrendingWindow,
        limit: Option<i32>,
    ) -> Result<TrendingResponse, TrendingError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

        // Query precomputed trending scores joined with repository info
        // Requirement 17.1: Return repos sorted by weighted score descending
        let rows = sqlx::query(
            r#"
            SELECT 
                ts.repo_id,
                CAST(ts.weighted_score AS DOUBLE PRECISION) as weighted_score,
                ts.stars_delta,
                ts.computed_at,
                r.name,
                r.owner_id,
                r.description,
                r.created_at,
                a.agent_name as owner_name,
                COALESCE(sc.stars, 0) as stars
            FROM repo_trending_scores ts
            JOIN repositories r ON ts.repo_id = r.repo_id
            JOIN agents a ON r.owner_id = a.agent_id
            LEFT JOIN repo_star_counts sc ON ts.repo_id = sc.repo_id
            WHERE ts."window" = $1
            ORDER BY ts.weighted_score DESC
            LIMIT $2
            "#,
        )
        .bind(window)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        // Get the most recent computed_at timestamp
        let computed_at: Option<DateTime<Utc>> = if !rows.is_empty() {
            Some(rows[0].get("computed_at"))
        } else {
            None
        };

        let repos: Vec<TrendingRepo> = rows
            .into_iter()
            .map(|row| TrendingRepo {
                repo_id: row.get("repo_id"),
                name: row.get("name"),
                owner_id: row.get("owner_id"),
                owner_name: row.get("owner_name"),
                description: row.get("description"),
                stars: row.get("stars"),
                stars_delta: row.get("stars_delta"),
                weighted_score: row.get("weighted_score"),
                created_at: row.get("created_at"),
            })
            .collect();

        Ok(TrendingResponse {
            window: window.to_string(),
            repos,
            computed_at,
        })
    }

    /// Run the trending aggregation job for all windows
    ///
    /// Requirements: 17.2, 17.3, 17.4
    /// Design: DR-12.1 (Trending Service)
    ///
    /// This should be called periodically (every 1-5 minutes) by a background job.
    pub async fn run_aggregation(&self) -> Result<(), TrendingError> {
        let windows = [
            TrendingWindow::OneHour,
            TrendingWindow::TwentyFourHours,
            TrendingWindow::SevenDays,
            TrendingWindow::ThirtyDays,
        ];

        for window in windows {
            if let Err(e) = self.aggregate_window(window).await {
                warn!("Failed to aggregate trending for window {}: {}", window, e);
            }
        }

        Ok(())
    }

    /// Aggregate trending scores for a specific window
    ///
    /// Requirements: 17.2, 17.3, 17.4
    async fn aggregate_window(&self, window: TrendingWindow) -> Result<(), TrendingError> {
        let now = Utc::now();
        let window_start = now - Duration::hours(window.hours());

        debug!(
            "Aggregating trending for window {} (from {} to {})",
            window, window_start, now
        );

        // Get all stars within the window with agent reputation and cluster info
        let stars = sqlx::query(
            r#"
            SELECT 
                rs.repo_id,
                rs.agent_id,
                rs.created_at,
                COALESCE(rep.score, $1) as reputation,
                COALESCE(rep.cluster_ids, '[]'::jsonb) as cluster_ids
            FROM repo_stars rs
            LEFT JOIN reputation rep ON rs.agent_id = rep.agent_id
            WHERE rs.created_at >= $2 AND rs.created_at <= $3
            ORDER BY rs.repo_id, rs.created_at DESC
            "#,
        )
        .bind(DEFAULT_REPUTATION)
        .bind(window_start)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        // Group stars by repo and calculate weighted scores
        let mut repo_scores: HashMap<String, RepoScoreData> = HashMap::new();

        for row in stars {
            let repo_id: String = row.get("repo_id");
            let agent_id: String = row.get("agent_id");
            let created_at: DateTime<Utc> = row.get("created_at");
            let reputation: f64 = row.get("reputation");
            let cluster_ids: serde_json::Value = row.get("cluster_ids");

            let entry = repo_scores
                .entry(repo_id.clone())
                .or_insert_with(|| RepoScoreData {
                    stars_delta: 0,
                    weighted_score: 0.0,
                    cluster_counts: HashMap::new(),
                });

            entry.stars_delta += 1;

            // Calculate base weight from reputation (Requirement 17.2)
            // Formula: 0.5 + 0.5 * reputation
            let base_weight = 0.5 + 0.5 * reputation;

            // Apply age decay (Requirement 17.3)
            // Recent stars count more - linear decay from 1.0 to 0.5 over the window
            let age_seconds = (now - created_at).num_seconds() as f64;
            let window_seconds = Duration::hours(window.hours()).num_seconds() as f64;
            let age_factor = 1.0 - 0.5 * (age_seconds / window_seconds).min(1.0);

            // Apply diversity penalty (Requirement 17.4)
            // First 3 stars from same cluster = 1.0x, subsequent = 0.5x
            let diversity_factor =
                self.calculate_diversity_factor(&cluster_ids, &mut entry.cluster_counts);

            let final_weight = base_weight * age_factor * diversity_factor;
            entry.weighted_score += final_weight;

            debug!(
                "Star from {} on {}: base={:.3}, age={:.3}, diversity={:.3}, final={:.3}",
                agent_id, repo_id, base_weight, age_factor, diversity_factor, final_weight
            );
        }

        // Write results atomically to repo_trending_scores
        let mut tx = self.pool.begin().await?;

        // Delete existing scores for this window
        sqlx::query(r#"DELETE FROM repo_trending_scores WHERE "window" = $1"#)
            .bind(window)
            .execute(&mut *tx)
            .await?;

        // Insert new scores
        for (repo_id, data) in repo_scores {
            sqlx::query(
                r#"
                INSERT INTO repo_trending_scores ("window", repo_id, weighted_score, stars_delta, computed_at)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(window)
            .bind(&repo_id)
            .bind(data.weighted_score)
            .bind(data.stars_delta)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        info!(
            "Completed trending aggregation for window {} at {}",
            window, now
        );

        Ok(())
    }

    /// Calculate diversity factor based on cluster membership
    ///
    /// Requirement 17.4: First 3 stars from same cluster = 1.0x, subsequent = 0.5x
    fn calculate_diversity_factor(
        &self,
        cluster_ids: &serde_json::Value,
        cluster_counts: &mut HashMap<String, usize>,
    ) -> f64 {
        // Extract cluster IDs from JSON array
        let clusters: Vec<String> = match cluster_ids.as_array() {
            Some(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            None => vec![],
        };

        // If no clusters, treat as unique (no penalty)
        if clusters.is_empty() {
            return 1.0;
        }

        // Check if any cluster has exceeded the threshold
        let mut min_factor = 1.0;
        for cluster_id in &clusters {
            let count = cluster_counts.entry(cluster_id.clone()).or_insert(0);
            *count += 1;

            if *count > CLUSTER_DIVERSITY_THRESHOLD {
                min_factor = DIVERSITY_PENALTY;
            }
        }

        min_factor
    }
}

/// Internal struct for accumulating repo score data
struct RepoScoreData {
    stars_delta: i32,
    weighted_score: f64,
    cluster_counts: HashMap<String, usize>,
}

//! Storage Metrics Service
//!
//! Provides observability for S3 object storage operations.
//! Design Reference: DR-S3-6.1
//!
//! Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info, warn, Span};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default slow operation threshold in milliseconds
const DEFAULT_SLOW_OPERATION_THRESHOLD_MS: u64 = 1000;

/// Environment variable for slow operation threshold
const ENV_SLOW_OPERATION_THRESHOLD_MS: &str = "S3_SLOW_OPERATION_THRESHOLD_MS";

/// Number of buckets for latency histogram
const HISTOGRAM_BUCKETS: usize = 20;

/// Histogram bucket boundaries in milliseconds
/// Covers range from 1ms to ~30s with exponential growth
const HISTOGRAM_BUCKET_BOUNDARIES_MS: [u64; HISTOGRAM_BUCKETS] = [
    1, 2, 5, 10, 20, 50, 100, 200, 500, 1000,
    2000, 5000, 10000, 15000, 20000, 25000, 30000, 45000, 60000, u64::MAX,
];

// ============================================================================
// Operation Types
// ============================================================================

/// S3 operation types for metrics categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum S3OperationType {
    /// Put object operation
    PutObject,
    /// Get object operation
    GetObject,
    /// Delete object operation
    DeleteObject,
    /// List objects operation
    ListObjects,
    /// Head object operation
    HeadObject,
    /// Put packfile operation
    PutPackfile,
    /// Get packfile operation
    GetPackfile,
    /// Delete repository objects operation
    DeleteRepositoryObjects,
    /// Copy repository objects operation
    CopyRepositoryObjects,
}

impl S3OperationType {
    /// Get string representation for metrics labels
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PutObject => "put_object",
            Self::GetObject => "get_object",
            Self::DeleteObject => "delete_object",
            Self::ListObjects => "list_objects",
            Self::HeadObject => "head_object",
            Self::PutPackfile => "put_packfile",
            Self::GetPackfile => "get_packfile",
            Self::DeleteRepositoryObjects => "delete_repository_objects",
            Self::CopyRepositoryObjects => "copy_repository_objects",
        }
    }
}

impl std::fmt::Display for S3OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Error Types for Metrics
// ============================================================================

/// S3 error types for metrics categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum S3ErrorType {
    /// Connection error
    ConnectionError,
    /// Access denied
    AccessDenied,
    /// Not found
    NotFound,
    /// Rate limited (503 SlowDown)
    RateLimited,
    /// Upload failed
    UploadFailed,
    /// Download failed
    DownloadFailed,
    /// Delete failed
    DeleteFailed,
    /// Object corrupted
    ObjectCorrupted,
    /// Internal error
    Internal,
    /// Timeout
    Timeout,
}

impl S3ErrorType {
    /// Get string representation for metrics labels
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectionError => "connection_error",
            Self::AccessDenied => "access_denied",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::UploadFailed => "upload_failed",
            Self::DownloadFailed => "download_failed",
            Self::DeleteFailed => "delete_failed",
            Self::ObjectCorrupted => "object_corrupted",
            Self::Internal => "internal",
            Self::Timeout => "timeout",
        }
    }

    /// Classify error from StorageError
    pub fn from_error_message(msg: &str) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("timeout") {
            Self::Timeout
        } else if lower.contains("503") || lower.contains("slowdown") || lower.contains("rate") {
            Self::RateLimited
        } else if lower.contains("connection") {
            Self::ConnectionError
        } else if lower.contains("access denied") || lower.contains("forbidden") {
            Self::AccessDenied
        } else if lower.contains("not found") || lower.contains("no such key") {
            Self::NotFound
        } else if lower.contains("upload") {
            Self::UploadFailed
        } else if lower.contains("download") {
            Self::DownloadFailed
        } else if lower.contains("delete") {
            Self::DeleteFailed
        } else if lower.contains("corrupt") || lower.contains("mismatch") {
            Self::ObjectCorrupted
        } else {
            Self::Internal
        }
    }
}

impl std::fmt::Display for S3ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Latency Histogram
// ============================================================================

/// A simple histogram for tracking latency distributions
///
/// Requirements: 10.1
#[derive(Debug)]
pub struct LatencyHistogram {
    /// Bucket counts
    buckets: [AtomicU64; HISTOGRAM_BUCKETS],
    /// Total count of observations
    count: AtomicU64,
    /// Sum of all observations in microseconds
    sum_us: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    /// Create a new histogram
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    /// Record a latency observation
    pub fn observe(&self, duration: Duration) {
        let ms = duration.as_millis() as u64;
        let us = duration.as_micros() as u64;

        // Find the appropriate bucket
        let bucket_idx = HISTOGRAM_BUCKET_BOUNDARIES_MS
            .iter()
            .position(|&boundary| ms <= boundary)
            .unwrap_or(HISTOGRAM_BUCKETS - 1);

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// Get the total count of observations
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Get the sum of all observations in microseconds
    pub fn sum_us(&self) -> u64 {
        self.sum_us.load(Ordering::Relaxed)
    }

    /// Get the mean latency in milliseconds
    pub fn mean_ms(&self) -> f64 {
        let count = self.count();
        if count == 0 {
            return 0.0;
        }
        (self.sum_us() as f64 / count as f64) / 1000.0
    }

    /// Calculate percentile (0.0 to 1.0)
    ///
    /// Requirements: 10.1 - p50, p95, p99
    pub fn percentile(&self, p: f64) -> f64 {
        let count = self.count();
        if count == 0 {
            return 0.0;
        }

        let target = (count as f64 * p).ceil() as u64;
        let mut cumulative = 0u64;

        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                // Return the upper bound of this bucket
                return HISTOGRAM_BUCKET_BOUNDARIES_MS[i] as f64;
            }
        }

        // Return max if we somehow didn't find it
        HISTOGRAM_BUCKET_BOUNDARIES_MS[HISTOGRAM_BUCKETS - 1] as f64
    }

    /// Get p50 latency in milliseconds
    pub fn p50(&self) -> f64 {
        self.percentile(0.50)
    }

    /// Get p95 latency in milliseconds
    pub fn p95(&self) -> f64 {
        self.percentile(0.95)
    }

    /// Get p99 latency in milliseconds
    pub fn p99(&self) -> f64 {
        self.percentile(0.99)
    }

    /// Get bucket counts for detailed analysis
    pub fn bucket_counts(&self) -> Vec<(u64, u64)> {
        HISTOGRAM_BUCKET_BOUNDARIES_MS
            .iter()
            .zip(self.buckets.iter())
            .map(|(&boundary, count)| (boundary, count.load(Ordering::Relaxed)))
            .collect()
    }
}

// ============================================================================
// Operation Counter
// ============================================================================

/// Counter for tracking operation counts by type
#[derive(Debug, Default)]
pub struct OperationCounter {
    counts: [AtomicU64; 9], // One for each S3OperationType
}

impl OperationCounter {
    /// Create a new operation counter
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment counter for an operation type
    pub fn increment(&self, op_type: S3OperationType) {
        let idx = op_type as usize;
        if idx < self.counts.len() {
            self.counts[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get count for an operation type
    pub fn get(&self, op_type: S3OperationType) -> u64 {
        let idx = op_type as usize;
        if idx < self.counts.len() {
            self.counts[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Get total count across all operation types
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Get all counts as a map
    pub fn all_counts(&self) -> HashMap<S3OperationType, u64> {
        use S3OperationType::*;
        let ops = [
            PutObject, GetObject, DeleteObject, ListObjects, HeadObject,
            PutPackfile, GetPackfile, DeleteRepositoryObjects, CopyRepositoryObjects,
        ];
        ops.iter().map(|&op| (op, self.get(op))).collect()
    }
}

// ============================================================================
// Error Counter
// ============================================================================

/// Counter for tracking error counts by type
#[derive(Debug, Default)]
pub struct ErrorCounter {
    counts: [AtomicU64; 10], // One for each S3ErrorType
}

impl ErrorCounter {
    /// Create a new error counter
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment counter for an error type
    pub fn increment(&self, error_type: S3ErrorType) {
        let idx = error_type as usize;
        if idx < self.counts.len() {
            self.counts[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get count for an error type
    pub fn get(&self, error_type: S3ErrorType) -> u64 {
        let idx = error_type as usize;
        if idx < self.counts.len() {
            self.counts[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Get total error count
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Get all counts as a map
    pub fn all_counts(&self) -> HashMap<S3ErrorType, u64> {
        use S3ErrorType::*;
        let types = [
            ConnectionError, AccessDenied, NotFound, RateLimited, UploadFailed,
            DownloadFailed, DeleteFailed, ObjectCorrupted, Internal, Timeout,
        ];
        types.iter().map(|&t| (t, self.get(t))).collect()
    }
}

// ============================================================================
// Storage Metrics
// ============================================================================

/// Storage metrics for S3 operations
///
/// Design Reference: DR-S3-6.1
/// Requirements: 10.1
///
/// Tracks:
/// - Request latency histograms (p50, p95, p99)
/// - Request count by operation type
/// - Error count by error type
#[derive(Debug)]
pub struct StorageMetrics {
    /// Latency histograms per operation type
    latency_histograms: HashMap<S3OperationType, LatencyHistogram>,

    /// Request counts by operation type
    request_counts: OperationCounter,

    /// Error counts by error type
    error_counts: ErrorCounter,

    /// Slow operation threshold in milliseconds
    slow_operation_threshold_ms: u64,
}

impl Default for StorageMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageMetrics {
    /// Create new storage metrics
    pub fn new() -> Self {
        Self::with_threshold(DEFAULT_SLOW_OPERATION_THRESHOLD_MS)
    }

    /// Create storage metrics with custom slow operation threshold
    pub fn with_threshold(slow_operation_threshold_ms: u64) -> Self {
        use S3OperationType::*;
        let ops = [
            PutObject, GetObject, DeleteObject, ListObjects, HeadObject,
            PutPackfile, GetPackfile, DeleteRepositoryObjects, CopyRepositoryObjects,
        ];

        let latency_histograms = ops
            .iter()
            .map(|&op| (op, LatencyHistogram::new()))
            .collect();

        Self {
            latency_histograms,
            request_counts: OperationCounter::new(),
            error_counts: ErrorCounter::new(),
            slow_operation_threshold_ms,
        }
    }

    /// Create storage metrics from environment configuration
    pub fn from_env() -> Self {
        let threshold = std::env::var(ENV_SLOW_OPERATION_THRESHOLD_MS)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SLOW_OPERATION_THRESHOLD_MS);

        Self::with_threshold(threshold)
    }

    /// Record S3 operation latency
    ///
    /// Requirements: 10.1
    pub fn record_latency(&self, operation: S3OperationType, duration: Duration) {
        // Record in histogram
        if let Some(histogram) = self.latency_histograms.get(&operation) {
            histogram.observe(duration);
        }

        // Increment request count
        self.request_counts.increment(operation);

        // Log at DEBUG level
        debug!(
            operation = %operation,
            latency_ms = duration.as_millis(),
            "S3 operation completed"
        );
    }

    /// Record S3 operation latency and check for slow operations
    ///
    /// Requirements: 10.1, 10.6
    pub fn record_latency_with_slow_check(
        &self,
        operation: S3OperationType,
        duration: Duration,
        request_id: Option<&str>,
    ) {
        self.record_latency(operation, duration);

        // Check for slow operation
        let latency_ms = duration.as_millis() as u64;
        if latency_ms > self.slow_operation_threshold_ms {
            self.log_slow_operation(operation, duration, request_id);
        }
    }

    /// Log a slow operation warning
    ///
    /// Requirements: 10.6
    fn log_slow_operation(
        &self,
        operation: S3OperationType,
        duration: Duration,
        request_id: Option<&str>,
    ) {
        warn!(
            operation = %operation,
            latency_ms = duration.as_millis(),
            threshold_ms = self.slow_operation_threshold_ms,
            request_id = request_id.unwrap_or("unknown"),
            "S3 operation exceeded latency threshold"
        );
    }

    /// Record S3 error
    ///
    /// Requirements: 10.1
    pub fn record_error(&self, error_type: S3ErrorType) {
        self.error_counts.increment(error_type);
    }

    /// Record S3 error from error message
    pub fn record_error_from_message(&self, error_msg: &str) {
        let error_type = S3ErrorType::from_error_message(error_msg);
        self.record_error(error_type);
    }

    /// Get latency histogram for an operation type
    pub fn get_latency_histogram(&self, operation: S3OperationType) -> Option<&LatencyHistogram> {
        self.latency_histograms.get(&operation)
    }

    /// Get p50 latency for an operation type
    pub fn p50(&self, operation: S3OperationType) -> f64 {
        self.latency_histograms
            .get(&operation)
            .map(|h| h.p50())
            .unwrap_or(0.0)
    }

    /// Get p95 latency for an operation type
    pub fn p95(&self, operation: S3OperationType) -> f64 {
        self.latency_histograms
            .get(&operation)
            .map(|h| h.p95())
            .unwrap_or(0.0)
    }

    /// Get p99 latency for an operation type
    pub fn p99(&self, operation: S3OperationType) -> f64 {
        self.latency_histograms
            .get(&operation)
            .map(|h| h.p99())
            .unwrap_or(0.0)
    }

    /// Get request count for an operation type
    pub fn request_count(&self, operation: S3OperationType) -> u64 {
        self.request_counts.get(operation)
    }

    /// Get total request count
    pub fn total_request_count(&self) -> u64 {
        self.request_counts.total()
    }

    /// Get error count for an error type
    pub fn error_count(&self, error_type: S3ErrorType) -> u64 {
        self.error_counts.get(error_type)
    }

    /// Get total error count
    pub fn total_error_count(&self) -> u64 {
        self.error_counts.total()
    }

    /// Get all request counts
    pub fn all_request_counts(&self) -> HashMap<S3OperationType, u64> {
        self.request_counts.all_counts()
    }

    /// Get all error counts
    pub fn all_error_counts(&self) -> HashMap<S3ErrorType, u64> {
        self.error_counts.all_counts()
    }

    /// Get slow operation threshold
    pub fn slow_operation_threshold_ms(&self) -> u64 {
        self.slow_operation_threshold_ms
    }

    /// Get a summary of all metrics
    pub fn summary(&self) -> MetricsSummary {
        use S3OperationType::*;
        let ops = [
            PutObject, GetObject, DeleteObject, ListObjects, HeadObject,
            PutPackfile, GetPackfile, DeleteRepositoryObjects, CopyRepositoryObjects,
        ];

        let latencies: HashMap<S3OperationType, LatencySummary> = ops
            .iter()
            .filter_map(|&op| {
                self.latency_histograms.get(&op).map(|h| {
                    (op, LatencySummary {
                        count: h.count(),
                        mean_ms: h.mean_ms(),
                        p50_ms: h.p50(),
                        p95_ms: h.p95(),
                        p99_ms: h.p99(),
                    })
                })
            })
            .collect();

        MetricsSummary {
            total_requests: self.total_request_count(),
            total_errors: self.total_error_count(),
            request_counts: self.all_request_counts(),
            error_counts: self.all_error_counts(),
            latencies,
        }
    }
}

// ============================================================================
// Metrics Summary Types
// ============================================================================

/// Summary of latency metrics for an operation
#[derive(Debug, Clone)]
pub struct LatencySummary {
    /// Total count of observations
    pub count: u64,
    /// Mean latency in milliseconds
    pub mean_ms: f64,
    /// p50 latency in milliseconds
    pub p50_ms: f64,
    /// p95 latency in milliseconds
    pub p95_ms: f64,
    /// p99 latency in milliseconds
    pub p99_ms: f64,
}

/// Complete metrics summary
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    /// Total request count
    pub total_requests: u64,
    /// Total error count
    pub total_errors: u64,
    /// Request counts by operation type
    pub request_counts: HashMap<S3OperationType, u64>,
    /// Error counts by error type
    pub error_counts: HashMap<S3ErrorType, u64>,
    /// Latency summaries by operation type
    pub latencies: HashMap<S3OperationType, LatencySummary>,
}



// ============================================================================
// Cache Metrics (Enhanced)
// ============================================================================

/// Enhanced cache metrics for observability
///
/// Requirements: 10.2
///
/// Tracks:
/// - Cache hit/miss rate
/// - Cache size
/// - Eviction count
#[derive(Debug, Default)]
pub struct EnhancedCacheMetrics {
    /// Number of cache hits
    hits: AtomicU64,
    /// Number of cache misses
    misses: AtomicU64,
    /// Number of evictions
    evictions: AtomicU64,
    /// Current cache size in bytes
    size_bytes: AtomicU64,
    /// Number of entries in cache
    entry_count: AtomicU64,
}

impl EnhancedCacheMetrics {
    /// Create new cache metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cache hit
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an eviction
    pub fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record multiple evictions
    pub fn record_evictions(&self, count: u64) {
        self.evictions.fetch_add(count, Ordering::Relaxed);
    }

    /// Update cache size
    pub fn set_size_bytes(&self, size: u64) {
        self.size_bytes.store(size, Ordering::Relaxed);
    }

    /// Update entry count
    pub fn set_entry_count(&self, count: u64) {
        self.entry_count.store(count, Ordering::Relaxed);
    }

    /// Get hit count
    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get miss count
    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get eviction count
    pub fn eviction_count(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Get cache size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes.load(Ordering::Relaxed)
    }

    /// Get entry count
    pub fn entry_count(&self) -> u64 {
        self.entry_count.load(Ordering::Relaxed)
    }

    /// Calculate hit rate (0.0 to 1.0)
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count();
        let misses = self.miss_count();
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Get a summary of cache metrics
    pub fn summary(&self) -> CacheMetricsSummary {
        CacheMetricsSummary {
            hits: self.hit_count(),
            misses: self.miss_count(),
            hit_rate: self.hit_rate(),
            evictions: self.eviction_count(),
            size_bytes: self.size_bytes(),
            entry_count: self.entry_count(),
        }
    }
}

/// Summary of cache metrics
#[derive(Debug, Clone)]
pub struct CacheMetricsSummary {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Hit rate (0.0 to 1.0)
    pub hit_rate: f64,
    /// Number of evictions
    pub evictions: u64,
    /// Current cache size in bytes
    pub size_bytes: u64,
    /// Number of entries in cache
    pub entry_count: u64,
}

// ============================================================================
// Repository Storage Metrics
// ============================================================================

/// Metrics for repository storage
///
/// Requirements: 10.3
///
/// Tracks:
/// - Object count per repository
/// - Storage size per repository
#[derive(Debug)]
pub struct RepositoryStorageMetrics {
    /// Object counts per repository
    object_counts: RwLock<HashMap<String, u64>>,
    /// Storage sizes per repository in bytes
    storage_sizes: RwLock<HashMap<String, u64>>,
}

impl Default for RepositoryStorageMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RepositoryStorageMetrics {
    /// Create new repository storage metrics
    pub fn new() -> Self {
        Self {
            object_counts: RwLock::new(HashMap::new()),
            storage_sizes: RwLock::new(HashMap::new()),
        }
    }

    /// Update object count for a repository
    pub async fn set_object_count(&self, repo_id: &str, count: u64) {
        let mut counts = self.object_counts.write().await;
        counts.insert(repo_id.to_string(), count);
    }

    /// Increment object count for a repository
    pub async fn increment_object_count(&self, repo_id: &str, delta: u64) {
        let mut counts = self.object_counts.write().await;
        let current = counts.get(repo_id).copied().unwrap_or(0);
        counts.insert(repo_id.to_string(), current + delta);
    }

    /// Decrement object count for a repository
    pub async fn decrement_object_count(&self, repo_id: &str, delta: u64) {
        let mut counts = self.object_counts.write().await;
        let current = counts.get(repo_id).copied().unwrap_or(0);
        counts.insert(repo_id.to_string(), current.saturating_sub(delta));
    }

    /// Update storage size for a repository
    pub async fn set_storage_size(&self, repo_id: &str, size: u64) {
        let mut sizes = self.storage_sizes.write().await;
        sizes.insert(repo_id.to_string(), size);
    }

    /// Add to storage size for a repository
    pub async fn add_storage_size(&self, repo_id: &str, delta: u64) {
        let mut sizes = self.storage_sizes.write().await;
        let current = sizes.get(repo_id).copied().unwrap_or(0);
        sizes.insert(repo_id.to_string(), current + delta);
    }

    /// Subtract from storage size for a repository
    pub async fn subtract_storage_size(&self, repo_id: &str, delta: u64) {
        let mut sizes = self.storage_sizes.write().await;
        let current = sizes.get(repo_id).copied().unwrap_or(0);
        sizes.insert(repo_id.to_string(), current.saturating_sub(delta));
    }

    /// Get object count for a repository
    pub async fn get_object_count(&self, repo_id: &str) -> u64 {
        let counts = self.object_counts.read().await;
        counts.get(repo_id).copied().unwrap_or(0)
    }

    /// Get storage size for a repository
    pub async fn get_storage_size(&self, repo_id: &str) -> u64 {
        let sizes = self.storage_sizes.read().await;
        sizes.get(repo_id).copied().unwrap_or(0)
    }

    /// Remove metrics for a repository (e.g., on deletion)
    pub async fn remove_repository(&self, repo_id: &str) {
        {
            let mut counts = self.object_counts.write().await;
            counts.remove(repo_id);
        }
        {
            let mut sizes = self.storage_sizes.write().await;
            sizes.remove(repo_id);
        }
    }

    /// Get all object counts
    pub async fn all_object_counts(&self) -> HashMap<String, u64> {
        self.object_counts.read().await.clone()
    }

    /// Get all storage sizes
    pub async fn all_storage_sizes(&self) -> HashMap<String, u64> {
        self.storage_sizes.read().await.clone()
    }

    /// Get total object count across all repositories
    pub async fn total_object_count(&self) -> u64 {
        self.object_counts.read().await.values().sum()
    }

    /// Get total storage size across all repositories
    pub async fn total_storage_size(&self) -> u64 {
        self.storage_sizes.read().await.values().sum()
    }

    /// Get summary of repository storage metrics
    pub async fn summary(&self) -> RepositoryStorageMetricsSummary {
        let object_counts = self.object_counts.read().await;
        let storage_sizes = self.storage_sizes.read().await;

        RepositoryStorageMetricsSummary {
            repository_count: object_counts.len(),
            total_objects: object_counts.values().sum(),
            total_storage_bytes: storage_sizes.values().sum(),
            object_counts: object_counts.clone(),
            storage_sizes: storage_sizes.clone(),
        }
    }
}

/// Summary of repository storage metrics
#[derive(Debug, Clone)]
pub struct RepositoryStorageMetricsSummary {
    /// Number of repositories tracked
    pub repository_count: usize,
    /// Total object count across all repositories
    pub total_objects: u64,
    /// Total storage size across all repositories in bytes
    pub total_storage_bytes: u64,
    /// Object counts per repository
    pub object_counts: HashMap<String, u64>,
    /// Storage sizes per repository in bytes
    pub storage_sizes: HashMap<String, u64>,
}

// ============================================================================
// Operation Timer
// ============================================================================

/// Timer for measuring operation duration
///
/// Automatically records latency when dropped.
pub struct OperationTimer<'a> {
    metrics: &'a StorageMetrics,
    operation: S3OperationType,
    start: Instant,
    request_id: Option<String>,
    recorded: bool,
}

impl<'a> OperationTimer<'a> {
    /// Create a new operation timer
    pub fn new(metrics: &'a StorageMetrics, operation: S3OperationType) -> Self {
        Self {
            metrics,
            operation,
            start: Instant::now(),
            request_id: None,
            recorded: false,
        }
    }

    /// Set the request ID for logging
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    /// Get elapsed duration
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Manually record the latency and mark as recorded
    pub fn record(mut self) {
        if !self.recorded {
            let duration = self.start.elapsed();
            self.metrics.record_latency_with_slow_check(
                self.operation,
                duration,
                self.request_id.as_deref(),
            );
            self.recorded = true;
        }
    }

    /// Record an error
    pub fn record_error(&self, error_type: S3ErrorType) {
        self.metrics.record_error(error_type);
    }
}

impl<'a> Drop for OperationTimer<'a> {
    fn drop(&mut self) {
        if !self.recorded {
            let duration = self.start.elapsed();
            self.metrics.record_latency_with_slow_check(
                self.operation,
                duration,
                self.request_id.as_deref(),
            );
        }
    }
}

// ============================================================================
// Unified Observability Service
// ============================================================================

/// Unified observability service for storage operations
///
/// Design Reference: DR-S3-6.1
/// Requirements: 10.1, 10.2, 10.3, 10.6
///
/// Combines:
/// - S3 operation metrics
/// - Cache metrics
/// - Repository storage metrics
#[derive(Debug)]
pub struct StorageObservability {
    /// S3 operation metrics
    pub storage_metrics: StorageMetrics,
    /// Cache metrics
    pub cache_metrics: EnhancedCacheMetrics,
    /// Repository storage metrics
    pub repository_metrics: RepositoryStorageMetrics,
}

impl Default for StorageObservability {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageObservability {
    /// Create new observability service
    pub fn new() -> Self {
        Self {
            storage_metrics: StorageMetrics::new(),
            cache_metrics: EnhancedCacheMetrics::new(),
            repository_metrics: RepositoryStorageMetrics::new(),
        }
    }

    /// Create observability service from environment configuration
    pub fn from_env() -> Self {
        Self {
            storage_metrics: StorageMetrics::from_env(),
            cache_metrics: EnhancedCacheMetrics::new(),
            repository_metrics: RepositoryStorageMetrics::new(),
        }
    }

    /// Start timing an operation
    pub fn start_operation(&self, operation: S3OperationType) -> OperationTimer<'_> {
        OperationTimer::new(&self.storage_metrics, operation)
    }

    /// Log all metrics at INFO level
    pub async fn log_metrics_summary(&self) {
        let storage_summary = self.storage_metrics.summary();
        let cache_summary = self.cache_metrics.summary();
        let repo_summary = self.repository_metrics.summary().await;

        info!(
            total_requests = storage_summary.total_requests,
            total_errors = storage_summary.total_errors,
            cache_hit_rate = cache_summary.hit_rate,
            cache_size_bytes = cache_summary.size_bytes,
            total_repositories = repo_summary.repository_count,
            total_objects = repo_summary.total_objects,
            total_storage_bytes = repo_summary.total_storage_bytes,
            "Storage observability summary"
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_histogram_basic() {
        let histogram = LatencyHistogram::new();

        // Record some observations
        histogram.observe(Duration::from_millis(10));
        histogram.observe(Duration::from_millis(20));
        histogram.observe(Duration::from_millis(30));

        assert_eq!(histogram.count(), 3);
        assert!(histogram.mean_ms() > 0.0);
    }

    #[test]
    fn test_latency_histogram_percentiles() {
        let histogram = LatencyHistogram::new();

        // Record 100 observations from 1ms to 100ms
        for i in 1..=100 {
            histogram.observe(Duration::from_millis(i));
        }

        assert_eq!(histogram.count(), 100);

        // p50 should be around 50ms
        let p50 = histogram.p50();
        assert!(p50 >= 50.0 && p50 <= 100.0, "p50 was {}", p50);

        // p95 should be around 95ms
        let p95 = histogram.p95();
        assert!(p95 >= 95.0 && p95 <= 200.0, "p95 was {}", p95);

        // p99 should be around 99ms
        let p99 = histogram.p99();
        assert!(p99 >= 99.0 && p99 <= 200.0, "p99 was {}", p99);
    }

    #[test]
    fn test_operation_counter() {
        let counter = OperationCounter::new();

        counter.increment(S3OperationType::PutObject);
        counter.increment(S3OperationType::PutObject);
        counter.increment(S3OperationType::GetObject);

        assert_eq!(counter.get(S3OperationType::PutObject), 2);
        assert_eq!(counter.get(S3OperationType::GetObject), 1);
        assert_eq!(counter.get(S3OperationType::DeleteObject), 0);
        assert_eq!(counter.total(), 3);
    }

    #[test]
    fn test_error_counter() {
        let counter = ErrorCounter::new();

        counter.increment(S3ErrorType::RateLimited);
        counter.increment(S3ErrorType::RateLimited);
        counter.increment(S3ErrorType::Timeout);

        assert_eq!(counter.get(S3ErrorType::RateLimited), 2);
        assert_eq!(counter.get(S3ErrorType::Timeout), 1);
        assert_eq!(counter.total(), 3);
    }

    #[test]
    fn test_error_type_classification() {
        assert_eq!(
            S3ErrorType::from_error_message("connection refused"),
            S3ErrorType::ConnectionError
        );
        assert_eq!(
            S3ErrorType::from_error_message("503 SlowDown"),
            S3ErrorType::RateLimited
        );
        assert_eq!(
            S3ErrorType::from_error_message("request timeout"),
            S3ErrorType::Timeout
        );
        assert_eq!(
            S3ErrorType::from_error_message("NoSuchKey: not found"),
            S3ErrorType::NotFound
        );
    }

    #[test]
    fn test_storage_metrics() {
        let metrics = StorageMetrics::new();

        // Record some operations
        metrics.record_latency(S3OperationType::PutObject, Duration::from_millis(50));
        metrics.record_latency(S3OperationType::PutObject, Duration::from_millis(100));
        metrics.record_latency(S3OperationType::GetObject, Duration::from_millis(30));

        assert_eq!(metrics.request_count(S3OperationType::PutObject), 2);
        assert_eq!(metrics.request_count(S3OperationType::GetObject), 1);
        assert_eq!(metrics.total_request_count(), 3);

        // Record errors
        metrics.record_error(S3ErrorType::RateLimited);
        assert_eq!(metrics.error_count(S3ErrorType::RateLimited), 1);
        assert_eq!(metrics.total_error_count(), 1);
    }

    #[test]
    fn test_cache_metrics() {
        let metrics = EnhancedCacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        assert_eq!(metrics.hit_count(), 2);
        assert_eq!(metrics.miss_count(), 1);
        assert!((metrics.hit_rate() - 0.666).abs() < 0.01);

        metrics.record_eviction();
        assert_eq!(metrics.eviction_count(), 1);

        metrics.set_size_bytes(1024);
        assert_eq!(metrics.size_bytes(), 1024);
    }

    #[tokio::test]
    async fn test_repository_storage_metrics() {
        let metrics = RepositoryStorageMetrics::new();

        metrics.set_object_count("repo1", 100).await;
        metrics.set_storage_size("repo1", 1024 * 1024).await;

        assert_eq!(metrics.get_object_count("repo1").await, 100);
        assert_eq!(metrics.get_storage_size("repo1").await, 1024 * 1024);

        metrics.increment_object_count("repo1", 10).await;
        assert_eq!(metrics.get_object_count("repo1").await, 110);

        metrics.add_storage_size("repo1", 1024).await;
        assert_eq!(metrics.get_storage_size("repo1").await, 1024 * 1024 + 1024);

        // Test removal
        metrics.remove_repository("repo1").await;
        assert_eq!(metrics.get_object_count("repo1").await, 0);
        assert_eq!(metrics.get_storage_size("repo1").await, 0);
    }

    #[test]
    fn test_metrics_summary() {
        let metrics = StorageMetrics::new();

        metrics.record_latency(S3OperationType::PutObject, Duration::from_millis(50));
        metrics.record_error(S3ErrorType::RateLimited);

        let summary = metrics.summary();
        assert_eq!(summary.total_requests, 1);
        assert_eq!(summary.total_errors, 1);
        assert!(summary.latencies.contains_key(&S3OperationType::PutObject));
    }
}


// ============================================================================
// OpenTelemetry Tracing Integration
// ============================================================================

/// OpenTelemetry tracing configuration
///
/// Requirements: 10.5
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Whether OpenTelemetry tracing is enabled
    pub enabled: bool,
    /// OTLP endpoint URL
    pub otlp_endpoint: Option<String>,
    /// Service name for tracing
    pub service_name: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: None,
            service_name: "gitclaw-storage".to_string(),
        }
    }
}

impl TracingConfig {
    /// Load configuration from environment variables
    ///
    /// Environment variables:
    /// - `OTEL_ENABLED`: Enable OpenTelemetry tracing (true/false)
    /// - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint URL
    /// - `OTEL_SERVICE_NAME`: Service name for tracing
    pub fn from_env() -> Self {
        let enabled = std::env::var("OTEL_ENABLED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

        let service_name = std::env::var("OTEL_SERVICE_NAME")
            .unwrap_or_else(|_| "gitclaw-storage".to_string());

        Self {
            enabled,
            otlp_endpoint,
            service_name,
        }
    }
}

/// Span attributes for S3 operations
///
/// Requirements: 10.5
pub struct S3SpanAttributes {
    /// Operation type
    pub operation: S3OperationType,
    /// Repository ID
    pub repo_id: Option<String>,
    /// Object ID (OID)
    pub oid: Option<String>,
    /// Pack hash for packfile operations
    pub pack_hash: Option<String>,
    /// S3 bucket name
    pub bucket: Option<String>,
    /// S3 request ID
    pub request_id: Option<String>,
}

impl S3SpanAttributes {
    /// Create new span attributes for an operation
    pub fn new(operation: S3OperationType) -> Self {
        Self {
            operation,
            repo_id: None,
            oid: None,
            pack_hash: None,
            bucket: None,
            request_id: None,
        }
    }

    /// Set repository ID
    pub fn with_repo_id(mut self, repo_id: &str) -> Self {
        self.repo_id = Some(repo_id.to_string());
        self
    }

    /// Set object ID
    pub fn with_oid(mut self, oid: &str) -> Self {
        self.oid = Some(oid.to_string());
        self
    }

    /// Set pack hash
    pub fn with_pack_hash(mut self, pack_hash: &str) -> Self {
        self.pack_hash = Some(pack_hash.to_string());
        self
    }

    /// Set bucket name
    pub fn with_bucket(mut self, bucket: &str) -> Self {
        self.bucket = Some(bucket.to_string());
        self
    }

    /// Set request ID
    pub fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_string());
        self
    }
}

/// Create a tracing span for an S3 operation
///
/// Requirements: 10.5
///
/// This macro creates a span with standard S3 operation attributes.
/// Use this for distributed tracing of push/clone operations.
#[macro_export]
macro_rules! s3_span {
    // Case with additional fields
    ($operation:expr, $($field:ident = $value:expr),+ $(,)?) => {
        tracing::info_span!(
            "s3_operation",
            operation = %$operation,
            $($field = %$value,)*
            otel.kind = "client",
            otel.status_code = tracing::field::Empty,
        )
    };
    // Case with only operation
    ($operation:expr $(,)?) => {
        tracing::info_span!(
            "s3_operation",
            operation = %$operation,
            otel.kind = "client",
            otel.status_code = tracing::field::Empty,
        )
    };
}

/// Create a tracing span for a push operation
///
/// Requirements: 10.5
#[macro_export]
macro_rules! push_span {
    ($repo_id:expr, $agent_id:expr) => {
        tracing::info_span!(
            "git_push",
            repo_id = %$repo_id,
            agent_id = %$agent_id,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
        )
    };
}

/// Create a tracing span for a clone/fetch operation
///
/// Requirements: 10.5
#[macro_export]
macro_rules! clone_span {
    ($repo_id:expr, $agent_id:expr) => {
        tracing::info_span!(
            "git_clone",
            repo_id = %$repo_id,
            agent_id = %$agent_id,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
        )
    };
}

/// Helper to record span status on completion
pub fn record_span_success(span: &Span) {
    span.record("otel.status_code", "OK");
}

/// Helper to record span error status
pub fn record_span_error(span: &Span, error: &str) {
    span.record("otel.status_code", "ERROR");
    tracing::error!(parent: span, error = %error, "Operation failed");
}

/// Traced operation wrapper
///
/// Requirements: 10.5
///
/// Wraps an async operation with OpenTelemetry tracing.
pub struct TracedOperation<'a> {
    span: Span,
    metrics: Option<&'a StorageMetrics>,
    operation: S3OperationType,
    start: Instant,
}

impl<'a> TracedOperation<'a> {
    /// Create a new traced operation
    pub fn new(operation: S3OperationType, repo_id: Option<&str>) -> Self {
        let span = match repo_id {
            Some(rid) => s3_span!(operation, repo_id = rid),
            None => s3_span!(operation),
        };

        Self {
            span,
            metrics: None,
            operation,
            start: Instant::now(),
        }
    }

    /// Attach metrics recording
    pub fn with_metrics(mut self, metrics: &'a StorageMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get the span for entering
    pub fn span(&self) -> &Span {
        &self.span
    }

    /// Record success and return duration
    pub fn success(self) -> Duration {
        let duration = self.start.elapsed();
        record_span_success(&self.span);

        if let Some(metrics) = self.metrics {
            metrics.record_latency(self.operation, duration);
        }

        duration
    }

    /// Record error
    pub fn error(self, error: &str) -> Duration {
        let duration = self.start.elapsed();
        record_span_error(&self.span, error);

        if let Some(metrics) = self.metrics {
            metrics.record_latency(self.operation, duration);
            metrics.record_error_from_message(error);
        }

        duration
    }
}

// Re-export tracing macros for convenience
pub use tracing::{debug_span, error_span, info_span, trace_span, warn_span};

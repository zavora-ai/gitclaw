//! Object Cache Service
//!
//! Provides caching layer for Git object storage operations.
//! Design Reference: DR-S3-2.1, DR-S3-2.2
//!
//! Requirements: 6.1-6.7

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::object_storage::{
    CopyResult, DeleteResult, GitObjectType, ObjectList, ObjectMetadata, ObjectStorageBackend,
    PackfileData, StorageError, StoredObject,
};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default maximum cache size in bytes (1 GB)
const DEFAULT_MAX_CACHE_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

/// Default cache directory name
const DEFAULT_CACHE_DIR: &str = ".gitclaw-cache";

/// Environment variable for cache directory
const ENV_CACHE_DIR: &str = "GITCLAW_CACHE_DIR";

/// Environment variable for max cache size
const ENV_MAX_CACHE_SIZE: &str = "GITCLAW_MAX_CACHE_SIZE_BYTES";

/// Environment variable to enable/disable caching
const ENV_CACHE_ENABLED: &str = "GITCLAW_CACHE_ENABLED";

// ============================================================================
// Error Types
// ============================================================================

/// Cache operation errors
///
/// Design Reference: DR-S3-2.1
#[derive(Debug, Error)]
pub enum CacheError {
    /// IO error during cache operation
    #[error("Cache IO error: {0}")]
    IoError(String),

    /// Cache entry not found
    #[error("Cache entry not found: {0}")]
    NotFound(String),

    /// Cache is disabled
    #[error("Cache is disabled")]
    Disabled,

    /// Cache configuration error
    #[error("Cache configuration error: {0}")]
    ConfigError(String),
}

impl From<std::io::Error> for CacheError {
    fn from(err: std::io::Error) -> Self {
        CacheError::IoError(err.to_string())
    }
}

// ============================================================================
// Cache Configuration
// ============================================================================

/// Cache configuration
///
/// Design Reference: DR-S3-2.1
/// Requirements: 6.7
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Whether caching is enabled
    pub enabled: bool,

    /// Directory for disk cache
    pub cache_dir: PathBuf,

    /// Maximum cache size in bytes
    pub max_size_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_dir: PathBuf::from(DEFAULT_CACHE_DIR),
            max_size_bytes: DEFAULT_MAX_CACHE_SIZE_BYTES,
        }
    }
}

impl CacheConfig {
    /// Load configuration from environment variables
    ///
    /// Requirements: 6.7
    pub fn from_env() -> Result<Self, CacheError> {
        let enabled = env::var(ENV_CACHE_ENABLED)
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let cache_dir = env::var(ENV_CACHE_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CACHE_DIR));

        let max_size_bytes = env::var(ENV_MAX_CACHE_SIZE)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_CACHE_SIZE_BYTES);

        Ok(Self {
            enabled,
            cache_dir,
            max_size_bytes,
        })
    }
}

// ============================================================================
// LRU Cache Entry
// ============================================================================

/// Entry in the LRU cache tracking access time and size
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Key for this entry
    pub key: String,

    /// Size of the cached data in bytes
    pub size: u64,

    /// Last access time
    pub last_accessed: Instant,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(key: String, size: u64) -> Self {
        Self {
            key,
            size,
            last_accessed: Instant::now(),
        }
    }

    /// Update the last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }
}

// ============================================================================
// Disk Cache Implementation
// ============================================================================

/// Local disk cache for packfiles
///
/// Design Reference: DR-S3-2.2
/// Requirements: 6.1, 6.6
pub struct DiskCache {
    /// Cache directory path
    cache_dir: PathBuf,

    /// Maximum cache size in bytes
    max_size_bytes: u64,

    /// Current cache size in bytes
    current_size: AtomicU64,

    /// LRU index mapping keys to cache entries
    index: RwLock<HashMap<String, CacheEntry>>,
}

impl DiskCache {
    /// Create a new disk cache
    ///
    /// Requirements: 6.1
    pub async fn new(cache_dir: PathBuf, max_size_bytes: u64) -> Result<Self, CacheError> {
        // Create cache directory if it doesn't exist
        fs::create_dir_all(&cache_dir).await?;

        let cache = Self {
            cache_dir,
            max_size_bytes,
            current_size: AtomicU64::new(0),
            index: RwLock::new(HashMap::new()),
        };

        // Scan existing cache entries
        cache.scan_existing_entries().await?;

        Ok(cache)
    }

    /// Scan existing cache entries on startup
    async fn scan_existing_entries(&self) -> Result<(), CacheError> {
        let mut total_size = 0u64;
        let mut entries = HashMap::new();

        let mut dir = fs::read_dir(&self.cache_dir).await?;
        while let Some(entry) = dir.next_entry().await? {
            if let Ok(metadata) = entry.metadata().await {
                if metadata.is_file() {
                    let key = entry.file_name().to_string_lossy().to_string();
                    let size = metadata.len();
                    total_size += size;
                    entries.insert(key.clone(), CacheEntry::new(key, size));
                }
            }
        }

        let entry_count = entries.len();
        self.current_size.store(total_size, Ordering::SeqCst);
        *self.index.write().await = entries;

        debug!(
            cache_dir = %self.cache_dir.display(),
            entries = entry_count,
            total_size = total_size,
            "Disk cache initialized"
        );

        Ok(())
    }

    /// Get the file path for a cache key
    fn get_path(&self, key: &str) -> PathBuf {
        // Sanitize key to be filesystem-safe
        let safe_key = key.replace(['/', '\\'], "_");
        self.cache_dir.join(safe_key)
    }

    /// Get packfile from disk cache
    ///
    /// Requirements: 6.3
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let path = self.get_path(key);

        // Check if entry exists in index
        {
            let mut index = self.index.write().await;
            if let Some(entry) = index.get_mut(key) {
                entry.touch();
            } else {
                return None;
            }
        }

        // Read from disk
        match fs::read(&path).await {
            Ok(data) => {
                debug!(key = key, size = data.len(), "Cache hit");
                Some(data)
            }
            Err(e) => {
                warn!(key = key, error = %e, "Failed to read from cache");
                // Remove stale entry from index
                self.index.write().await.remove(key);
                None
            }
        }
    }

    /// Store packfile in disk cache
    ///
    /// Requirements: 6.4, 6.6
    pub async fn put(&self, key: &str, data: &[u8]) -> Result<(), CacheError> {
        let size = data.len() as u64;

        // Evict entries if needed to make room
        self.evict_if_needed(size).await;

        let path = self.get_path(key);

        // Write to disk
        let mut file = fs::File::create(&path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;

        // Update index
        {
            let mut index = self.index.write().await;
            if let Some(old_entry) = index.get(key) {
                // Update existing entry
                self.current_size
                    .fetch_sub(old_entry.size, Ordering::SeqCst);
            }
            index.insert(key.to_string(), CacheEntry::new(key.to_string(), size));
        }

        self.current_size.fetch_add(size, Ordering::SeqCst);

        debug!(key = key, size = size, "Stored in cache");
        Ok(())
    }

    /// Remove entry from cache
    pub async fn remove(&self, key: &str) -> Result<(), CacheError> {
        let path = self.get_path(key);

        // Remove from index first
        let size = {
            let mut index = self.index.write().await;
            index.remove(key).map(|e| e.size)
        };

        // Update size counter
        if let Some(size) = size {
            self.current_size.fetch_sub(size, Ordering::SeqCst);
        }

        // Remove from disk (ignore errors if file doesn't exist)
        let _ = fs::remove_file(&path).await;

        debug!(key = key, "Removed from cache");
        Ok(())
    }

    /// Evict entries to make room for new data
    ///
    /// Requirements: 6.6
    async fn evict_if_needed(&self, needed_bytes: u64) {
        let current = self.current_size.load(Ordering::SeqCst);
        let target = self.max_size_bytes.saturating_sub(needed_bytes);

        if current <= target {
            return;
        }

        let bytes_to_free = current - target;
        let mut freed = 0u64;

        // Get entries sorted by last access time (oldest first)
        let entries_to_evict: Vec<String> = {
            let index = self.index.read().await;
            let mut entries: Vec<_> = index.values().collect();
            entries.sort_by_key(|e| e.last_accessed);

            entries
                .iter()
                .take_while(|e| {
                    if freed < bytes_to_free {
                        freed += e.size;
                        true
                    } else {
                        false
                    }
                })
                .map(|e| e.key.clone())
                .collect()
        };

        // Evict entries
        for key in entries_to_evict {
            if let Err(e) = self.remove(&key).await {
                warn!(key = key, error = %e, "Failed to evict cache entry");
            }
        }

        info!(
            freed_bytes = freed,
            target_bytes = bytes_to_free,
            "LRU cache eviction completed"
        );
    }

    /// Invalidate all entries for a repository
    ///
    /// Requirements: 6.5
    pub async fn invalidate_repository(&self, repo_id: &str) -> Result<usize, CacheError> {
        let prefix = format!("{}_", repo_id);

        // Find all entries for this repository
        let keys_to_remove: Vec<String> = {
            let index = self.index.read().await;
            index
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect()
        };

        let count = keys_to_remove.len();

        // Remove each entry
        for key in keys_to_remove {
            if let Err(e) = self.remove(&key).await {
                warn!(key = key, error = %e, "Failed to invalidate cache entry");
            }
        }

        debug!(repo_id = repo_id, invalidated = count, "Repository cache invalidated");
        Ok(count)
    }

    /// Get current cache size in bytes
    pub fn current_size(&self) -> u64 {
        self.current_size.load(Ordering::SeqCst)
    }

    /// Get maximum cache size in bytes
    pub fn max_size(&self) -> u64 {
        self.max_size_bytes
    }

    /// Get number of entries in cache
    pub async fn entry_count(&self) -> usize {
        self.index.read().await.len()
    }
}

// ============================================================================
// Redis Cache Implementation (Metadata Cache)
// ============================================================================

/// Environment variable for Redis URL
const ENV_REDIS_URL: &str = "GITCLAW_REDIS_URL";

/// Environment variable for Redis cache TTL in seconds
const ENV_REDIS_TTL: &str = "GITCLAW_REDIS_TTL_SECS";

/// Default TTL for Redis cache entries (1 hour)
const DEFAULT_REDIS_TTL_SECS: u64 = 3600;

/// Redis cache configuration
///
/// Requirements: 6.2
#[derive(Debug, Clone)]
pub struct RedisCacheConfig {
    /// Redis connection URL
    pub url: String,

    /// TTL for cache entries in seconds
    pub ttl_secs: u64,

    /// Whether Redis caching is enabled
    pub enabled: bool,
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            enabled: false,
            ttl_secs: DEFAULT_REDIS_TTL_SECS,
        }
    }
}

impl RedisCacheConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let url = env::var(ENV_REDIS_URL).unwrap_or_default();
        let enabled = !url.is_empty();

        let ttl_secs = env::var(ENV_REDIS_TTL)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_REDIS_TTL_SECS);

        Self {
            url,
            enabled,
            ttl_secs,
        }
    }
}

/// Cached object metadata entry
///
/// Requirements: 6.2
#[derive(Debug, Clone)]
pub struct CachedMetadata {
    /// Object ID
    pub oid: String,

    /// Object type
    pub object_type: String,

    /// Object size in bytes
    pub size: usize,

    /// When this entry was cached
    pub cached_at: Instant,

    /// TTL for this entry
    pub ttl_secs: u64,
}

impl CachedMetadata {
    /// Create a new cached metadata entry
    pub fn new(oid: String, object_type: String, size: usize, ttl_secs: u64) -> Self {
        Self {
            oid,
            object_type,
            size,
            cached_at: Instant::now(),
            ttl_secs,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > Duration::from_secs(self.ttl_secs)
    }

    /// Convert to ObjectMetadata
    pub fn to_object_metadata(&self) -> ObjectMetadata {
        let object_type = GitObjectType::from_str(&self.object_type)
            .unwrap_or(GitObjectType::Blob);
        ObjectMetadata {
            oid: self.oid.clone(),
            object_type,
            size: self.size,
        }
    }
}

/// In-memory metadata cache with TTL support
///
/// This provides a simple in-memory implementation that can be used
/// when Redis is not available. For production use with Redis,
/// this can be replaced with a Redis-backed implementation.
///
/// Requirements: 6.2
pub struct MetadataCache {
    /// Cache entries
    entries: RwLock<HashMap<String, CachedMetadata>>,

    /// TTL for cache entries
    ttl_secs: u64,

    /// Maximum number of entries
    max_entries: usize,
}

impl MetadataCache {
    /// Create a new metadata cache
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl_secs,
            max_entries,
        }
    }

    /// Build cache key for object metadata
    fn cache_key(repo_id: &str, oid: &str) -> String {
        format!("meta:{}:{}", repo_id, oid)
    }

    /// Get metadata from cache
    pub async fn get(&self, repo_id: &str, oid: &str) -> Option<CachedMetadata> {
        let key = Self::cache_key(repo_id, oid);
        let entries = self.entries.read().await;

        entries.get(&key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.clone())
            }
        })
    }

    /// Store metadata in cache
    pub async fn put(&self, repo_id: &str, metadata: &ObjectMetadata) {
        let key = Self::cache_key(repo_id, &metadata.oid);

        let entry = CachedMetadata::new(
            metadata.oid.clone(),
            metadata.object_type.as_str().to_string(),
            metadata.size,
            self.ttl_secs,
        );

        let mut entries = self.entries.write().await;

        // Evict expired entries if we're at capacity
        if entries.len() >= self.max_entries {
            self.evict_expired(&mut entries);
        }

        // If still at capacity, evict oldest entries
        if entries.len() >= self.max_entries {
            let to_evict = entries.len() - self.max_entries + 1;
            self.evict_oldest(&mut entries, to_evict);
        }

        entries.insert(key, entry);
    }

    /// Remove metadata from cache
    pub async fn remove(&self, repo_id: &str, oid: &str) {
        let key = Self::cache_key(repo_id, oid);
        self.entries.write().await.remove(&key);
    }

    /// Invalidate all entries for a repository
    pub async fn invalidate_repository(&self, repo_id: &str) -> usize {
        let prefix = format!("meta:{}:", repo_id);
        let mut entries = self.entries.write().await;

        let keys_to_remove: Vec<String> = entries
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            entries.remove(&key);
        }

        count
    }

    /// Evict expired entries
    fn evict_expired(&self, entries: &mut HashMap<String, CachedMetadata>) {
        entries.retain(|_, v| !v.is_expired());
    }

    /// Evict oldest entries
    fn evict_oldest(&self, entries: &mut HashMap<String, CachedMetadata>, count: usize) {
        if count == 0 {
            return;
        }

        // Sort by cached_at and remove oldest
        let mut sorted: Vec<_> = entries.iter().collect();
        sorted.sort_by_key(|(_, v)| v.cached_at);

        let keys_to_remove: Vec<String> = sorted
            .iter()
            .take(count)
            .map(|(k, _)| (*k).clone())
            .collect();

        for key in keys_to_remove {
            entries.remove(&key);
        }
    }

    /// Get number of entries in cache
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if cache is empty
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}


// ============================================================================
// Cache Metrics
// ============================================================================

/// Metrics for cache operations
///
/// Requirements: 10.2
#[derive(Debug, Default)]
pub struct CacheMetrics {
    /// Number of cache hits
    pub hits: AtomicU64,

    /// Number of cache misses
    pub misses: AtomicU64,

    /// Number of evictions
    pub evictions: AtomicU64,
}

impl CacheMetrics {
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
}

// ============================================================================
// ObjectCache - Cache-Through Wrapper
// ============================================================================

/// Caching layer for object storage
///
/// Design Reference: DR-S3-2.1
/// Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
///
/// This wrapper implements a cache-through pattern:
/// - On read: Check cache first, fall back to backend, populate cache on miss
/// - On write: Write to backend, then cache
/// - Packfiles are cached on local disk
/// - Object metadata can be cached in memory (or Redis when available)
pub struct ObjectCache {
    /// Underlying storage backend
    backend: Arc<dyn ObjectStorageBackend>,

    /// Disk cache for packfiles
    disk_cache: Option<DiskCache>,

    /// Metadata cache for object metadata (TTL-based)
    metadata_cache: Option<MetadataCache>,

    /// Cache configuration
    config: CacheConfig,

    /// Cache metrics
    metrics: Arc<CacheMetrics>,
}

impl ObjectCache {
    /// Create a new object cache wrapper
    ///
    /// Requirements: 6.1, 6.2, 6.7
    pub async fn new(
        backend: Arc<dyn ObjectStorageBackend>,
        config: CacheConfig,
    ) -> Result<Self, CacheError> {
        let disk_cache = if config.enabled {
            Some(DiskCache::new(config.cache_dir.clone(), config.max_size_bytes).await?)
        } else {
            None
        };

        // Create metadata cache if enabled (default: 10000 entries, 1 hour TTL)
        let metadata_cache = if config.enabled {
            Some(MetadataCache::new(DEFAULT_REDIS_TTL_SECS, 10000))
        } else {
            None
        };

        Ok(Self {
            backend,
            disk_cache,
            metadata_cache,
            config,
            metrics: Arc::new(CacheMetrics::new()),
        })
    }

    /// Create a new object cache with metadata cache configuration
    ///
    /// Requirements: 6.2
    pub async fn with_metadata_cache(
        backend: Arc<dyn ObjectStorageBackend>,
        config: CacheConfig,
        metadata_ttl_secs: u64,
        metadata_max_entries: usize,
    ) -> Result<Self, CacheError> {
        let disk_cache = if config.enabled {
            Some(DiskCache::new(config.cache_dir.clone(), config.max_size_bytes).await?)
        } else {
            None
        };

        let metadata_cache = if config.enabled {
            Some(MetadataCache::new(metadata_ttl_secs, metadata_max_entries))
        } else {
            None
        };

        Ok(Self {
            backend,
            disk_cache,
            metadata_cache,
            config,
            metrics: Arc::new(CacheMetrics::new()),
        })
    }

    /// Create a new object cache with default configuration from environment
    pub async fn from_env(backend: Arc<dyn ObjectStorageBackend>) -> Result<Self, CacheError> {
        let config = CacheConfig::from_env()?;
        Self::new(backend, config).await
    }

    /// Check if caching is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.disk_cache.is_some()
    }

    /// Get cache metrics
    pub fn metrics(&self) -> Arc<CacheMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Get a reference to the underlying backend
    pub fn backend(&self) -> &Arc<dyn ObjectStorageBackend> {
        &self.backend
    }

    /// Build cache key for packfile
    fn packfile_cache_key(repo_id: &str, pack_hash: &str) -> String {
        format!("{}_pack_{}", repo_id, pack_hash)
    }

    /// Build cache key for packfile index
    fn packfile_index_cache_key(repo_id: &str, pack_hash: &str) -> String {
        format!("{}_idx_{}", repo_id, pack_hash)
    }

    /// Invalidate cache entries for a repository
    ///
    /// Requirements: 6.5
    pub async fn invalidate_repository(&self, repo_id: &str) -> Result<(), CacheError> {
        // Invalidate disk cache
        if let Some(ref cache) = self.disk_cache {
            cache.invalidate_repository(repo_id).await?;
        }

        // Invalidate metadata cache
        if let Some(ref cache) = self.metadata_cache {
            cache.invalidate_repository(repo_id).await;
        }

        Ok(())
    }

    /// Invalidate cache after a push operation
    ///
    /// Requirements: 6.5
    ///
    /// This should be called after a successful push to ensure
    /// subsequent reads fetch fresh data from S3.
    pub async fn invalidate_on_push(&self, repo_id: &str) {
        if let Err(e) = self.invalidate_repository(repo_id).await {
            warn!(
                error = %e,
                repo_id = repo_id,
                "Failed to invalidate cache after push"
            );
        } else {
            debug!(repo_id = repo_id, "Cache invalidated after push");
        }
    }

    /// Get current cache size in bytes
    pub fn cache_size(&self) -> u64 {
        self.disk_cache
            .as_ref()
            .map(|c| c.current_size())
            .unwrap_or(0)
    }

    /// Get number of cached entries
    pub async fn cache_entry_count(&self) -> usize {
        match &self.disk_cache {
            Some(cache) => cache.entry_count().await,
            None => 0,
        }
    }
}

#[async_trait]
impl ObjectStorageBackend for ObjectCache {
    /// Store a Git object (pass-through to backend)
    ///
    /// Loose objects are not cached as they are content-addressable
    /// and rarely re-read.
    async fn put_object(
        &self,
        repo_id: &str,
        oid: &str,
        object_type: GitObjectType,
        data: &[u8],
    ) -> Result<(), StorageError> {
        self.backend.put_object(repo_id, oid, object_type, data).await
    }

    /// Retrieve a Git object (pass-through to backend)
    ///
    /// Loose objects are not cached as they are content-addressable
    /// and rarely re-read.
    async fn get_object(&self, repo_id: &str, oid: &str) -> Result<StoredObject, StorageError> {
        self.backend.get_object(repo_id, oid).await
    }

    /// Delete a Git object (pass-through to backend)
    async fn delete_object(&self, repo_id: &str, oid: &str) -> Result<(), StorageError> {
        self.backend.delete_object(repo_id, oid).await
    }

    /// List objects in a repository (pass-through to backend)
    async fn list_objects(
        &self,
        repo_id: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
    ) -> Result<ObjectList, StorageError> {
        self.backend
            .list_objects(repo_id, prefix, continuation_token)
            .await
    }

    /// Check if an object exists with metadata caching
    ///
    /// Requirements: 6.2
    ///
    /// Checks metadata cache first, falls back to backend, populates cache on miss.
    async fn head_object(
        &self,
        repo_id: &str,
        oid: &str,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        // Check metadata cache first
        if let Some(ref cache) = self.metadata_cache {
            if let Some(cached) = cache.get(repo_id, oid).await {
                self.metrics.record_hit();
                return Ok(Some(cached.to_object_metadata()));
            }
        }

        // Cache miss - fetch from backend
        self.metrics.record_miss();
        let result = self.backend.head_object(repo_id, oid).await?;

        // Populate cache on miss
        if let (Some(cache), Some(metadata)) = (&self.metadata_cache, &result) {
            cache.put(repo_id, metadata).await;
        }

        Ok(result)
    }

    /// Store a packfile with its index
    ///
    /// Requirements: 6.4
    ///
    /// Writes to backend first, then caches on success.
    async fn put_packfile(
        &self,
        repo_id: &str,
        pack_hash: &str,
        packfile: &[u8],
        index: &[u8],
    ) -> Result<(), StorageError> {
        // Write to backend first
        self.backend
            .put_packfile(repo_id, pack_hash, packfile, index)
            .await?;

        // Cache on success (best effort, don't fail if cache fails)
        if let Some(ref cache) = self.disk_cache {
            let pack_key = Self::packfile_cache_key(repo_id, pack_hash);
            let idx_key = Self::packfile_index_cache_key(repo_id, pack_hash);

            if let Err(e) = cache.put(&pack_key, packfile).await {
                warn!(error = %e, key = pack_key, "Failed to cache packfile");
            }
            if let Err(e) = cache.put(&idx_key, index).await {
                warn!(error = %e, key = idx_key, "Failed to cache packfile index");
            }
        }

        Ok(())
    }

    /// Retrieve a packfile with its index
    ///
    /// Requirements: 6.3, 6.4
    ///
    /// Checks cache first, falls back to backend, populates cache on miss.
    async fn get_packfile(
        &self,
        repo_id: &str,
        pack_hash: &str,
    ) -> Result<PackfileData, StorageError> {
        let pack_key = Self::packfile_cache_key(repo_id, pack_hash);
        let idx_key = Self::packfile_index_cache_key(repo_id, pack_hash);

        // Try cache first
        if let Some(ref cache) = self.disk_cache {
            if let (Some(packfile), Some(index)) =
                (cache.get(&pack_key).await, cache.get(&idx_key).await)
            {
                self.metrics.record_hit();
                debug!(
                    repo_id = repo_id,
                    pack_hash = pack_hash,
                    "Packfile cache hit"
                );
                return Ok(PackfileData {
                    pack_hash: pack_hash.to_string(),
                    packfile,
                    index,
                });
            }
        }

        // Cache miss - fetch from backend
        self.metrics.record_miss();
        debug!(
            repo_id = repo_id,
            pack_hash = pack_hash,
            "Packfile cache miss, fetching from backend"
        );

        let data = self.backend.get_packfile(repo_id, pack_hash).await?;

        // Populate cache on miss (best effort)
        if let Some(ref cache) = self.disk_cache {
            if let Err(e) = cache.put(&pack_key, &data.packfile).await {
                warn!(error = %e, key = pack_key, "Failed to cache packfile on miss");
            }
            if let Err(e) = cache.put(&idx_key, &data.index).await {
                warn!(error = %e, key = idx_key, "Failed to cache packfile index on miss");
            }
        }

        Ok(data)
    }

    /// Delete all objects for a repository
    ///
    /// Requirements: 6.5
    ///
    /// Invalidates cache entries before deleting from backend.
    async fn delete_repository_objects(&self, repo_id: &str) -> Result<DeleteResult, StorageError> {
        // Invalidate cache first
        if let Some(ref cache) = self.disk_cache {
            if let Err(e) = cache.invalidate_repository(repo_id).await {
                warn!(error = %e, repo_id = repo_id, "Failed to invalidate cache during delete");
            }
        }

        // Delete from backend
        self.backend.delete_repository_objects(repo_id).await
    }

    /// Copy all objects from one repository to another
    ///
    /// Pass-through to backend - cache is not populated for copied objects
    /// as they may not be accessed immediately.
    async fn copy_repository_objects(
        &self,
        source_repo_id: &str,
        target_repo_id: &str,
    ) -> Result<CopyResult, StorageError> {
        self.backend
            .copy_repository_objects(source_repo_id, target_repo_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tempfile::TempDir;

    // Mock backend for testing
    struct MockBackend {
        get_packfile_calls: AtomicUsize,
        put_packfile_calls: AtomicUsize,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                get_packfile_calls: AtomicUsize::new(0),
                put_packfile_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ObjectStorageBackend for MockBackend {
        async fn put_object(
            &self,
            _repo_id: &str,
            _oid: &str,
            _object_type: GitObjectType,
            _data: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn get_object(
            &self,
            _repo_id: &str,
            _oid: &str,
        ) -> Result<StoredObject, StorageError> {
            Err(StorageError::NotFound("mock".to_string()))
        }

        async fn delete_object(&self, _repo_id: &str, _oid: &str) -> Result<(), StorageError> {
            Ok(())
        }

        async fn list_objects(
            &self,
            _repo_id: &str,
            _prefix: Option<&str>,
            _continuation_token: Option<&str>,
        ) -> Result<ObjectList, StorageError> {
            Ok(ObjectList {
                objects: vec![],
                continuation_token: None,
                is_truncated: false,
            })
        }

        async fn head_object(
            &self,
            _repo_id: &str,
            _oid: &str,
        ) -> Result<Option<ObjectMetadata>, StorageError> {
            Ok(None)
        }

        async fn put_packfile(
            &self,
            _repo_id: &str,
            _pack_hash: &str,
            _packfile: &[u8],
            _index: &[u8],
        ) -> Result<(), StorageError> {
            self.put_packfile_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn get_packfile(
            &self,
            _repo_id: &str,
            pack_hash: &str,
        ) -> Result<PackfileData, StorageError> {
            self.get_packfile_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(PackfileData {
                pack_hash: pack_hash.to_string(),
                packfile: vec![1, 2, 3, 4],
                index: vec![5, 6, 7, 8],
            })
        }

        async fn delete_repository_objects(
            &self,
            _repo_id: &str,
        ) -> Result<DeleteResult, StorageError> {
            Ok(DeleteResult {
                deleted_count: 0,
                failed: vec![],
            })
        }

        async fn copy_repository_objects(
            &self,
            _source_repo_id: &str,
            _target_repo_id: &str,
        ) -> Result<CopyResult, StorageError> {
            Ok(CopyResult {
                copied_count: 0,
                failed: vec![],
            })
        }
    }

    #[tokio::test]
    async fn test_disk_cache_put_get() {
        let temp_dir = TempDir::new().unwrap();
        let cache = DiskCache::new(temp_dir.path().to_path_buf(), 1024 * 1024)
            .await
            .unwrap();

        let key = "test_key";
        let data = b"test data";

        // Put data
        cache.put(key, data).await.unwrap();

        // Get data
        let retrieved = cache.get(key).await.unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_disk_cache_miss() {
        let temp_dir = TempDir::new().unwrap();
        let cache = DiskCache::new(temp_dir.path().to_path_buf(), 1024 * 1024)
            .await
            .unwrap();

        let result = cache.get("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_disk_cache_remove() {
        let temp_dir = TempDir::new().unwrap();
        let cache = DiskCache::new(temp_dir.path().to_path_buf(), 1024 * 1024)
            .await
            .unwrap();

        let key = "test_key";
        let data = b"test data";

        cache.put(key, data).await.unwrap();
        assert!(cache.get(key).await.is_some());

        cache.remove(key).await.unwrap();
        assert!(cache.get(key).await.is_none());
    }

    #[tokio::test]
    async fn test_disk_cache_invalidate_repository() {
        let temp_dir = TempDir::new().unwrap();
        let cache = DiskCache::new(temp_dir.path().to_path_buf(), 1024 * 1024)
            .await
            .unwrap();

        // Add entries for two repositories
        cache.put("repo1_pack_abc", b"data1").await.unwrap();
        cache.put("repo1_idx_abc", b"data2").await.unwrap();
        cache.put("repo2_pack_def", b"data3").await.unwrap();

        // Invalidate repo1
        let count = cache.invalidate_repository("repo1").await.unwrap();
        assert_eq!(count, 2);

        // repo1 entries should be gone
        assert!(cache.get("repo1_pack_abc").await.is_none());
        assert!(cache.get("repo1_idx_abc").await.is_none());

        // repo2 entry should still exist
        assert!(cache.get("repo2_pack_def").await.is_some());
    }

    #[tokio::test]
    async fn test_object_cache_packfile_caching() {
        let temp_dir = TempDir::new().unwrap();
        let backend = Arc::new(MockBackend::new());

        let config = CacheConfig {
            enabled: true,
            cache_dir: temp_dir.path().to_path_buf(),
            max_size_bytes: 1024 * 1024,
        };

        let cache = ObjectCache::new(backend.clone(), config).await.unwrap();

        // First get - should hit backend
        let result = cache.get_packfile("repo1", "hash1").await.unwrap();
        assert_eq!(result.pack_hash, "hash1");
        assert_eq!(
            backend
                .get_packfile_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // Second get - should hit cache
        let result = cache.get_packfile("repo1", "hash1").await.unwrap();
        assert_eq!(result.pack_hash, "hash1");
        assert_eq!(
            backend
                .get_packfile_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        ); // Still 1, cache hit

        // Verify metrics
        assert_eq!(cache.metrics().hit_count(), 1);
        assert_eq!(cache.metrics().miss_count(), 1);
    }

    #[tokio::test]
    async fn test_cache_metrics_hit_rate() {
        let metrics = CacheMetrics::new();

        // No accesses
        assert_eq!(metrics.hit_rate(), 0.0);

        // 1 hit, 1 miss = 50%
        metrics.record_hit();
        metrics.record_miss();
        assert!((metrics.hit_rate() - 0.5).abs() < 0.001);

        // 2 hits, 1 miss = 66.67%
        metrics.record_hit();
        assert!((metrics.hit_rate() - 0.666).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_disk_cache_lru_eviction() {
        let temp_dir = TempDir::new().unwrap();
        // Small cache: 100 bytes max
        let cache = DiskCache::new(temp_dir.path().to_path_buf(), 100)
            .await
            .unwrap();

        // Add first entry (40 bytes)
        let data1 = vec![1u8; 40];
        cache.put("key1", &data1).await.unwrap();
        assert_eq!(cache.current_size(), 40);

        // Small delay to ensure different timestamps
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Add second entry (40 bytes) - should fit
        let data2 = vec![2u8; 40];
        cache.put("key2", &data2).await.unwrap();
        assert_eq!(cache.current_size(), 80);

        // Small delay
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Access key1 to make it more recently used
        let _ = cache.get("key1").await;

        // Add third entry (40 bytes) - should evict key2 (LRU)
        let data3 = vec![3u8; 40];
        cache.put("key3", &data3).await.unwrap();

        // key2 should be evicted (LRU), key1 should remain
        // Note: key1 was accessed more recently than key2
        assert!(cache.get("key2").await.is_none(), "key2 should be evicted as LRU");
        assert!(cache.get("key1").await.is_some(), "key1 should remain (recently accessed)");
        assert!(cache.get("key3").await.is_some(), "key3 should exist (just added)");
    }

    #[tokio::test]
    async fn test_disk_cache_size_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let cache = DiskCache::new(temp_dir.path().to_path_buf(), 1024 * 1024)
            .await
            .unwrap();

        assert_eq!(cache.current_size(), 0);
        assert_eq!(cache.entry_count().await, 0);

        // Add entries
        cache.put("key1", b"data1").await.unwrap();
        cache.put("key2", b"data2data2").await.unwrap();

        assert_eq!(cache.current_size(), 15); // 5 + 10 bytes
        assert_eq!(cache.entry_count().await, 2);

        // Remove one
        cache.remove("key1").await.unwrap();
        assert_eq!(cache.current_size(), 10);
        assert_eq!(cache.entry_count().await, 1);
    }

    #[tokio::test]
    async fn test_cache_invalidation_on_push() {
        let temp_dir = TempDir::new().unwrap();
        let backend = Arc::new(MockBackend::new());

        let config = CacheConfig {
            enabled: true,
            cache_dir: temp_dir.path().to_path_buf(),
            max_size_bytes: 1024 * 1024,
        };

        let cache = ObjectCache::new(backend.clone(), config).await.unwrap();

        // Populate cache by fetching packfile
        let _ = cache.get_packfile("repo1", "hash1").await.unwrap();
        assert_eq!(cache.metrics().miss_count(), 1);

        // Verify cache is populated
        let _ = cache.get_packfile("repo1", "hash1").await.unwrap();
        assert_eq!(cache.metrics().hit_count(), 1);

        // Simulate push by invalidating cache
        cache.invalidate_on_push("repo1").await;

        // Next fetch should be a cache miss
        let _ = cache.get_packfile("repo1", "hash1").await.unwrap();
        assert_eq!(cache.metrics().miss_count(), 2);
    }

    #[tokio::test]
    async fn test_metadata_cache_put_get() {
        let cache = MetadataCache::new(3600, 100);

        let metadata = ObjectMetadata {
            oid: "abc123".to_string(),
            object_type: GitObjectType::Blob,
            size: 1024,
        };

        // Put metadata
        cache.put("repo1", &metadata).await;

        // Get metadata
        let cached = cache.get("repo1", "abc123").await.unwrap();
        assert_eq!(cached.oid, "abc123");
        assert_eq!(cached.object_type, "blob");
        assert_eq!(cached.size, 1024);
    }

    #[tokio::test]
    async fn test_metadata_cache_miss() {
        let cache = MetadataCache::new(3600, 100);

        let result = cache.get("repo1", "nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_metadata_cache_ttl_expiration() {
        // Very short TTL for testing
        let cache = MetadataCache::new(0, 100);

        let metadata = ObjectMetadata {
            oid: "abc123".to_string(),
            object_type: GitObjectType::Blob,
            size: 1024,
        };

        cache.put("repo1", &metadata).await;

        // Small delay to ensure expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should be expired
        let result = cache.get("repo1", "abc123").await;
        assert!(result.is_none(), "Entry should be expired");
    }

    #[tokio::test]
    async fn test_metadata_cache_invalidate_repository() {
        let cache = MetadataCache::new(3600, 100);

        let metadata1 = ObjectMetadata {
            oid: "abc123".to_string(),
            object_type: GitObjectType::Blob,
            size: 1024,
        };
        let metadata2 = ObjectMetadata {
            oid: "def456".to_string(),
            object_type: GitObjectType::Commit,
            size: 512,
        };
        let metadata3 = ObjectMetadata {
            oid: "ghi789".to_string(),
            object_type: GitObjectType::Tree,
            size: 256,
        };

        // Add entries for two repositories
        cache.put("repo1", &metadata1).await;
        cache.put("repo1", &metadata2).await;
        cache.put("repo2", &metadata3).await;

        assert_eq!(cache.len().await, 3);

        // Invalidate repo1
        let count = cache.invalidate_repository("repo1").await;
        assert_eq!(count, 2);

        // repo1 entries should be gone
        assert!(cache.get("repo1", "abc123").await.is_none());
        assert!(cache.get("repo1", "def456").await.is_none());

        // repo2 entry should still exist
        assert!(cache.get("repo2", "ghi789").await.is_some());
    }

    #[tokio::test]
    async fn test_metadata_cache_max_entries() {
        // Small cache with max 3 entries
        let cache = MetadataCache::new(3600, 3);

        for i in 0..5 {
            let metadata = ObjectMetadata {
                oid: format!("oid{}", i),
                object_type: GitObjectType::Blob,
                size: 100,
            };
            cache.put("repo1", &metadata).await;
        }

        // Should have at most 3 entries
        assert!(cache.len().await <= 3);
    }
}

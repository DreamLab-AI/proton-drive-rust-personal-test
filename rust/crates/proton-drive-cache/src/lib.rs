//! Cache contract + in-memory impl (ADR-0003).

#![forbid(unsafe_code)]

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache miss for key {0}")]
    Miss(String),
    #[error("cache backend error: {0}")]
    Backend(String),
}

/// Pluggable cache. Mirrors JS `ProtonDriveCache<T>`.
#[async_trait]
pub trait ProtonDriveCache<T>: Send + Sync
where
    T: Send + Sync + Clone + 'static,
{
    async fn get(&self, key: &str) -> Result<Option<T>, CacheError>;
    async fn set(&self, key: &str, value: T) -> Result<(), CacheError>;
    async fn remove(&self, key: &str) -> Result<(), CacheError>;
    async fn clear(&self) -> Result<(), CacheError>;
}

/// In-memory `DashMap`-backed cache. Sufficient for v1 (ADR-0003).
pub struct MemoryCache<T: Clone + Send + Sync + 'static> {
    inner: Arc<DashMap<String, T>>,
}

impl<T: Clone + Send + Sync + 'static> Default for MemoryCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Send + Sync + 'static> MemoryCache<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> ProtonDriveCache<T> for MemoryCache<T> {
    async fn get(&self, key: &str) -> Result<Option<T>, CacheError> {
        Ok(self.inner.get(key).map(|v| v.clone()))
    }

    async fn set(&self, key: &str, value: T) -> Result<(), CacheError> {
        self.inner.insert(key.to_owned(), value);
        Ok(())
    }

    async fn remove(&self, key: &str) -> Result<(), CacheError> {
        self.inner.remove(key);
        Ok(())
    }

    async fn clear(&self) -> Result<(), CacheError> {
        self.inner.clear();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    async fn run() {
        let cache: MemoryCache<String> = MemoryCache::new();
        assert!(cache.get("k").await.unwrap().is_none());
        cache.set("k", "v".into()).await.unwrap();
        assert_eq!(cache.get("k").await.unwrap().as_deref(), Some("v"));
        assert_eq!(cache.len(), 1);
        cache.remove("k").await.unwrap();
        assert!(cache.get("k").await.unwrap().is_none());
        cache.set("a", "1".into()).await.unwrap();
        cache.set("b", "2".into()).await.unwrap();
        cache.clear().await.unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn memory_cache_roundtrip() {
        futures::executor::block_on(run());
    }
}

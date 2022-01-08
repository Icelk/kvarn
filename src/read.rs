//! Utilities for reading files with or without a [`FileCache`].
//!
//! Mainly used for reading file internally in Kvarn.
//! All functions return [`Bytes`] to be used in the Kvarn cache.

use crate::prelude::{fs::*, *};

/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should only be used when a file is typically access several times or from several requests.
#[inline]
pub async fn file_cached<P: AsRef<Path>>(path: &P, cache: Option<&FileCache>) -> Option<Bytes> {
    if let Some(cache) = cache {
        if let CacheOut::Present(file) = cache.read().await.get(path.as_ref()) {
            return Some(Bytes::clone(file));
        }
    }

    let file = File::open(path).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    async_bits::read_to_end(&mut buffer, file).await.ok()?;
    let buffer = buffer.freeze();
    if let Some(cache) = cache {
        cache
            .write()
            .await
            .cache(path.as_ref().to_path_buf(), Bytes::clone(&buffer));
    }
    Some(buffer)
}

/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
#[inline]
pub async fn file<P: AsRef<Path>>(path: &P, cache: Option<&FileCache>) -> Option<Bytes> {
    if let Some(cache) = cache {
        if let CacheOut::Present(cached) = cache.read().await.get(path.as_ref()) {
            return Some(Bytes::clone(cached));
        }
    }

    let file = File::open(path).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    async_bits::read_to_end(&mut buffer, file).await.ok()?;
    Some(buffer.freeze())
}

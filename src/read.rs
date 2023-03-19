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
pub async fn file_cached<P: AsRef<str>>(path: &P, cache: Option<&FileCache>) -> Option<Bytes> {
    if let Some(cache) = cache {
        if let Some(file) = cache.cache.get(path.as_ref()) {
            return Some(file);
        }
    }

    let file = File::open(path.as_ref()).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    async_bits::read_to_end(&mut buffer, file).await.ok()?;
    let buffer = buffer.freeze();
    if let Some(cache) = cache {
        cache
            .cache
            .insert(path.as_ref().to_compact_string(), Bytes::clone(&buffer))
            .await;
    }
    Some(buffer)
}

/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
#[inline]
pub async fn file<P: AsRef<str>>(path: &P, cache: Option<&FileCache>) -> Option<Bytes> {
    if let Some(cache) = cache {
        if let Some(cached) = cache.cache.get(path.as_ref()) {
            return Some(cached);
        }
    }

    let file = File::open(path.as_ref()).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    async_bits::read_to_end(&mut buffer, file).await.ok()?;
    Some(buffer.freeze())
}

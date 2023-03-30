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

    let buffer = read(path.as_ref()).await?;

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

    let buffer = read(path.as_ref()).await?;

    Some(buffer.freeze())
}

async fn read(path: &str) -> Option<BytesMut> {
    #[cfg(feature = "uring")]
    {
        let file = File::open(path).await.ok()?;
        let stat = tokio_uring::fs::statx(path).await.ok()?;
        let len = stat.stx_size;

        #[cfg(target_pointer_width = "32")] // we assume we won't compile to 16-bit targets!
        if len > (u32::MAX / 2) as u64 {
            warn!("Tried to read file larger than representable memory (2GB)");
        }

        #[allow(clippy::cast_possible_truncation)] // we just checked above
        let buffer = BytesMut::with_capacity(len as _);
        let (r, buffer) = file.read_at(buffer, 0).await;
        r.ok()?;
        Some(buffer)
    }
    #[cfg(not(feature = "uring"))]
    {
        let file = File::open(path).await.ok()?;
        let mut buffer = BytesMut::with_capacity(4096);
        async_bits::read_to_end(&mut buffer, file).await.ok()?;
        Some(buffer)
    }
}

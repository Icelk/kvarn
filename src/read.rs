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
pub async fn file_cached<P: AsRef<str>>(path: P, cache: Option<&FileCache>) -> Option<Bytes> {
    if let Some(cache) = cache {
        if let Some(opt) = cache.cache.get(path.as_ref()) {
            let (_, file) = opt?;
            return Some(file);
        }
    }

    let buffer = read(path.as_ref()).await;

    if let Some(cache) = cache {
        if let Some(buffer) = buffer {
            let mtime = stat(path.as_ref())
                .await
                .map_or_else(OffsetDateTime::now_utc, |m| m.mtime);
            let buffer = buffer.freeze();
            cache.cache.insert(
                path.as_ref().to_compact_string(),
                Some((mtime, Bytes::clone(&buffer))),
            );
            return Some(buffer);
        }
        // else

        cache.cache.insert(path.as_ref().to_compact_string(), None);
        return None;
    }
    let buffer = buffer?.freeze();
    Some(buffer)
}

/// Like [`file_cached`], but also gives you the timestamp of the last modification to the file.
pub async fn file_cached_with_mtime<P: AsRef<str>>(
    path: P,
    cache: Option<&FileCache>,
) -> Option<(Bytes, OffsetDateTime)> {
    if let Some(cache) = cache {
        if let Some(opt) = cache.cache.get(path.as_ref()) {
            let (mtime, file) = opt?;
            return Some((file, mtime));
        }
    }

    let buffer = read(path.as_ref()).await;

    if let Some(cache) = cache {
        if let Some(buffer) = buffer {
            let meta = stat(path.as_ref()).await?;
            let buffer = buffer.freeze();
            cache.cache.insert(
                path.as_ref().to_compact_string(),
                Some((meta.mtime, Bytes::clone(&buffer))),
            );

            return Some((buffer, meta.mtime));
        }
        // else
        cache.cache.insert(path.as_ref().to_compact_string(), None);

        return None;
    }
    let buffer = buffer?.freeze();
    Some((buffer, stat(path.as_ref()).await?.mtime))
}

/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
#[inline]
pub async fn file<P: AsRef<str>>(path: P, cache: Option<&FileCache>) -> Option<Bytes> {
    if let Some(cache) = cache {
        if let Some(opt) = cache.cache.get(path.as_ref()) {
            let (_, cached) = opt?;
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

/// File metadata. See [`stat`].
#[derive(Debug)]
pub struct Metadata {
    /// Date of last modification
    pub mtime: OffsetDateTime,
    /// Date of last access. May not be accurate due to file system optimization
    pub atime: OffsetDateTime,
    /// Date of creation
    pub ctime: OffsetDateTime,

    /// Length in bytes of file.
    pub len: u64,
}
/// Get the metadata at `path`.
///
/// Uses `uring` when that feature's enabled.
#[allow(clippy::cast_possible_wrap)] // I darn hope the FS timestamps don't overflow...
pub async fn stat(path: impl AsRef<str>) -> Option<Metadata> {
    #[cfg(feature = "uring")]
    {
        // `libc` is always enabled on unix, which is the only platform supported by tokio_uring
        // (obviously).
        let stamp_to_dt = |timestamp: libc::statx_timestamp| {
            let dur = time::Duration::new(timestamp.tv_sec, timestamp.tv_nsec as i32);
            time::OffsetDateTime::UNIX_EPOCH + dur
        };
        let stat = tokio_uring::fs::statx(path.as_ref()).await.ok()?;
        Some(Metadata {
            mtime: stamp_to_dt(stat.stx_mtime),
            atime: stamp_to_dt(stat.stx_atime),
            ctime: stamp_to_dt(stat.stx_ctime),
            len: stat.stx_size,
        })
    }
    #[cfg(not(feature = "uring"))]
    {
        let systime_to_dt = |systime: std::time::SystemTime| {
            let dur = systime
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("time must be after UNIX_EPOCH");
            let dur = time::Duration::new(dur.as_secs() as i64, dur.subsec_nanos() as i32);
            time::OffsetDateTime::UNIX_EPOCH + dur
        };
        let meta = tokio::fs::metadata(path.as_ref()).await.ok()?;
        Some(Metadata {
            mtime: systime_to_dt(meta.modified().ok()?),
            atime: systime_to_dt(meta.accessed().ok()?),
            ctime: systime_to_dt(meta.created().ok()?),
            len: meta.len(),
        })
    }
}

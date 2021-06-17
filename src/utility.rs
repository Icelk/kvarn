//! Utility functions to provide solid solutions for common problems.
//!
//! This includes
//! - [`WriteableBytes`] for when you want to use [`Bytes`]
//!   as a [`Vec`], with tailored allocations
//! - [`CleanDebug`] to get the [`Display`] implementation when
//!   implementing [`Debug`] for a struct (see the Debug implementation for [`Host`])
//! - Async cached access to the file system
//! - Default errors which can be customised in `<host_dir>/errors/<status_code>.html`
//! - And several [`http`] helper functions.

use crate::prelude::{fs::*, *};

/// Reads `reader` to end into `buffer`.
/// Also see [`read_to_end_or_max()`].
///
/// # Errors
///
/// This function will return any errors emitted from `reader`.
pub async fn read_to_end(buffer: &mut BytesMut, reader: impl AsyncRead + Unpin) -> io::Result<()> {
    read_to_end_or_max(buffer, reader, usize::MAX).await
}
/// Reads from `reader` to `buffer` until it returns zero bytes or `max_length`
/// is reached. [`BytesMut::len`] is used as a starting length of `buffer`.
///
/// # Errors
///
/// Passes any errors emitted from `reader`.
pub async fn read_to_end_or_max(
    buffer: &mut BytesMut,
    mut reader: impl AsyncRead + Unpin,
    max_len: usize,
) -> io::Result<()> {
    let mut read = buffer.len();

    if read >= max_len {
        return Ok(());
    }

    // This is safe because of the trailing unsafe block.
    unsafe { buffer.set_len(buffer.capacity()) };
    loop {
        match reader.read(&mut buffer[read..]).await? {
            0 => break,
            len => {
                read += len;
                if read >= max_len {
                    unsafe { buffer.set_len(read) };
                    return Ok(());
                }
                if read > buffer.len() - 512 {
                    buffer.reserve(2048);
                    // This is safe because of the trailing unsafe block.
                    unsafe { buffer.set_len(buffer.capacity()) };
                }
            }
        }
    }
    // I have counted the length in `read`. It will *not* include uninitiated bytes.
    unsafe { buffer.set_len(read) };
    Ok(())
}

/// Turns a [`SanitizeError`] into a [`FatResponse`]
/// with `host`.
pub async fn sanitize_error_into_response(error: SanitizeError, host: &Host) -> FatResponse {
    utility::default_error_response(
        match error {
            SanitizeError::UnsafePath => StatusCode::BAD_REQUEST,
            SanitizeError::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
        },
        host,
        match error {
            SanitizeError::UnsafePath => Some("path contains illegal segments (e.g. `./`)"),
            SanitizeError::RangeNotSatisfiable => None,
        },
    )
    .await
}

/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should only be used when a file is typically access several times or from several requests.
#[cfg(not(feature = "no-fs-cache"))]
#[inline]
pub async fn read_file_cached<P: AsRef<Path>>(path: &P, cache: &FileCache) -> Option<Bytes> {
    if let CacheOut::Present(file) = cache.lock().await.get(path.as_ref()) {
        return Some(Bytes::clone(file));
    }

    let file = File::open(path).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    read_to_end(&mut buffer, file).await.ok()?;
    let buffer = buffer.freeze();
    cache
        .lock()
        .await
        .cache(path.as_ref().to_path_buf(), Bytes::clone(&buffer));
    Some(buffer)
}
/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should only be used when a file is typically access several times or from several requests.
#[cfg(feature = "no-fs-cache")]
#[inline]
pub async fn read_file_cached<P: AsRef<Path>>(path: &P, _: &FileCache) -> Option<Bytes> {
    let file = File::open(path).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    read_to_end(&mut buffer, file).await.ok()?;
    Some(buffer.freeze())
}

/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
#[cfg(not(feature = "no-fs-cache"))]
#[inline]
pub async fn read_file<P: AsRef<Path>>(path: &P, cache: &FileCache) -> Option<Bytes> {
    if let CacheOut::Present(cached) = cache.lock().await.get(path.as_ref()) {
        return Some(Bytes::clone(cached));
    }

    let file = File::open(path).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    read_to_end(&mut buffer, file).await.ok()?;
    Some(buffer.freeze())
}
/// Reads a file using a `cache`.
/// Should be used instead of [`fs::File::open()`].
///
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
#[cfg(feature = "no-fs-cache")]
#[inline]
pub async fn read_file<P: AsRef<Path>>(path: &P, _: &FileCache) -> Option<Bytes> {
    let file = File::open(path).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    read_to_end(&mut buffer, file).await.ok()?;
    Some(buffer.freeze())
}

/// Default HTTP error used in Kvarn.
///
/// Gets the default error based on `code` from the file system
/// through a cache.
#[inline]
pub async fn default_error(
    code: StatusCode,
    host: Option<&Host>,
    message: Option<&[u8]>,
) -> Response<Bytes> {
    // Error files will be used several times.
    let body = match host {
        Some(host) => {
            let path = utils::make_path(&host.path, "errors", code.as_str(), Some("html"));

            match read_file_cached(&path, &host.file_cache).await {
                Some(file) => file,
                None => utils::hardcoded_error_body(code, message),
            }
        }
        None => utils::hardcoded_error_body(code, message),
    };
    let mut builder = Response::builder()
        .status(code)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-encoding", "identity");
    if let Some(message) = message.map(HeaderValue::from_bytes).and_then(Result::ok) {
        builder = builder.header("reason", message);
    }
    // Unwrap is ok; I know it's valid
    builder.body(body).unwrap()
}

/// Get a error [`FatResponse`].
///
/// Can be very useful to return from [`extensions`].
#[inline]
pub async fn default_error_response(
    code: StatusCode,
    host: &Host,
    message: Option<&str>,
) -> FatResponse {
    FatResponse::cache(default_error(code, Some(host), message.map(str::as_bytes)).await)
        .with_server_cache(ServerCachePreference::None)
}

/// Writes HTTP/1.1 [`Response`]s and [`Request`]s to a [`AsyncWrite`].
pub mod write {
    use super::{io, AsyncWrite, AsyncWriteExt, HeaderMap, Request, Response, Version};

    async fn headers(headers: &HeaderMap, mut writer: impl AsyncWrite + Unpin) -> io::Result<()> {
        for (name, value) in headers {
            writer.write_all(name.as_str().as_bytes()).await?;
            writer.write_all(b": ").await?;
            writer.write_all(value.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
        }
        Ok(())
    }
    fn version(version: Version) -> &'static [u8] {
        match version {
            Version::HTTP_09 => &b"HTTP/0.9"[..],
            Version::HTTP_10 => &b"HTTP/1.0"[..],
            Version::HTTP_2 => &b"HTTP/2"[..],
            Version::HTTP_3 => &b"HTTP/3"[..],
            _ => &b"HTTP/1.1"[..],
        }
    }
    macro_rules! write_bytes {
        ($writer:expr, $($bytes:expr $(,)?)+) => {
            $($writer.write_all($bytes).await?;)*
        };
    }
    /// Writer should be buffered.
    ///
    /// # Errors
    ///
    /// Will pass any errors emitted from `writer`.
    pub async fn response<T>(
        response: &Response<T>,
        body: &[u8],
        mut writer: impl AsyncWrite + Unpin,
    ) -> io::Result<()> {
        let version = version(response.version());
        let status = response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .as_bytes();

        write_bytes!(
            writer,
            version,
            b" ",
            response.status().as_str().as_bytes(),
            b" ",
            status,
            b"\r\n"
        );

        headers(response.headers(), &mut writer).await?;

        write_bytes!(writer, b"\r\n", body);
        Ok(())
    }

    /// `writer` should be buffered.
    ///
    /// # Errors
    ///
    /// Passes any errors from writing to `writer`.
    pub async fn request<T>(
        request: &Request<T>,
        body: &[u8],
        mut writer: impl AsyncWrite + Unpin,
    ) -> io::Result<()> {
        let method = request.method().as_str().as_bytes();
        let path = request
            .uri()
            .path_and_query()
            .map_or(&b"/"[..], |p| p.as_str().as_bytes());

        let version = version(request.version());

        write_bytes!(writer, method, b" ", path, b" ", version, b"\r\n");

        headers(request.headers(), &mut writer).await?;

        write_bytes!(writer, b"\r\n", body);

        writer.flush().await?;
        Ok(())
    }
}

/// An adaptor between std's [`Read`] and tokio's [`AsyncRead`] traits.
/// This should be used when you have a foreign type which implements read
/// (on a [`Vec`], for example) that returns immediately, because you buffered the actual read with tokio.
///
/// The `reader` should return immediately, else it'll block.
pub fn read_to_async<R: Read + Unpin>(reader: R) -> ReadToAsync<R> {
    ReadToAsync(reader)
}
/// Helper struct for [`read_to_async`].
#[derive(Debug)]
pub struct ReadToAsync<R>(R);
impl<R: Read + Unpin> AsyncRead for ReadToAsync<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // buf.put_slice(buf)
        let extra_filled = unsafe {
            self.get_mut()
                .0
                .read(&mut *(buf.unfilled_mut() as *mut [_] as *mut [u8]))
        };
        Poll::Ready(match extra_filled {
            Ok(extra_filled) => {
                buf.set_filled(buf.filled().len() + extra_filled);
                Ok(())
            }
            Err(e) => Err(e),
        })
    }
}

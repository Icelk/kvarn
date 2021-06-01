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

/// Common characters expressed as a single byte each, according to UTF-8.
pub mod chars {
    /// Tab
    pub const TAB: u8 = 9;
    /// Line feed
    pub const LF: u8 = 10;
    /// Carrage return
    pub const CR: u8 = 13;
    /// ` `
    pub const SPACE: u8 = 32;
    /// `!`
    pub const BANG: u8 = 33;
    /// `&`
    pub const AMPERSAND: u8 = 38;
    /// `.`
    pub const PERIOD: u8 = 46;
    /// `/`
    pub const FORWARD_SLASH: u8 = 47;
    /// `:`
    pub const COLON: u8 = 58;
    /// `>`
    pub const PIPE: u8 = 62;
    /// `[`
    pub const L_SQ_BRACKET: u8 = 91;
    /// `\`
    pub const ESCAPE: u8 = 92;
    /// `]`
    pub const R_SQ_BRACKET: u8 = 93;
}

/// Conveniency macro to create a [`Bytes`] from multiple `&[u8]` sources.
///
/// Allocates only once; capacity is calculated before any allocation.
///
/// Works like the [`vec!`] macro, but takes byte slices and concatenates them together.
#[macro_export]
macro_rules! build_bytes {
    () => (
        $crate::prelude::Bytes::new()
    );
    ($($bytes:expr),+ $(,)?) => {{
        let mut b = $crate::prelude::BytesMut::with_capacity($($bytes.len() +)* 0);

        $(b.extend($bytes.iter());)*

        b.freeze()
    }};
}

/// A writeable `Bytes`.
///
/// Has a special allocation method for optimized usage in Kvarn.
#[derive(Debug)]
#[must_use]
pub struct WriteableBytes {
    bytes: BytesMut,
    len: usize,
}
impl WriteableBytes {
    /// Creates a new writeable buffer. Consider using
    /// [`Self::with_capacity()`] if you can estimate the capacity needed.
    #[inline]
    pub fn new() -> Self {
        Self {
            bytes: BytesMut::new(),
            len: 0,
        }
    }
    /// Crates a new writeable buffer with a specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        let mut bytes = BytesMut::with_capacity(capacity);
        // This is safe because of the guarantees of `WriteableBytes`; it stores the length internally
        // and applies it when the inner variable is exposed, through `Self::into_inner()`.
        unsafe { bytes.set_len(bytes.capacity()) };
        Self { bytes, len: 0 }
    }
    /// Turns `self` into `BytesMut` when you are done writing.
    #[inline]
    #[must_use]
    pub fn into_inner(mut self) -> BytesMut {
        unsafe { self.bytes.set_len(self.len) };
        self.bytes
    }
}
impl Default for WriteableBytes {
    fn default() -> Self {
        Self::new()
    }
}
impl From<BytesMut> for WriteableBytes {
    fn from(mut bytes: BytesMut) -> Self {
        let len = bytes.len();
        // This is safe because of the guarantees of `WriteableBytes`; it stores the length internally
        // and applies it when the inner variable is exposed, through `Self::into_inner()`.
        unsafe { bytes.set_len(bytes.capacity()) };
        Self { bytes, len }
    }
}
impl Write for WriteableBytes {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.len + buf.len() > self.bytes.capacity() {
            self.bytes.reserve(buf.len() + 512);
            // This is safe because of the guarantees of `WriteableBytes`; it stores the length internally
            // and applies it when the inner variable is exposed, through `Self::into_inner()`.
            unsafe { self.bytes.set_len(self.bytes.capacity()) };
        }
        self.bytes[self.len..self.len + buf.len()].copy_from_slice(buf);
        self.len += buf.len();
        Ok(buf.len())
    }
    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
        return Ok(())
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

/// Makes a [`PathBuf`] using one allocation.
///
/// Format is `<base_path>/<dir>/<file>(.<extension>)`
pub fn make_path(
    base_path: impl AsRef<Path>,
    dir: impl AsRef<Path>,
    file: impl AsRef<Path>,
    extension: Option<&str>,
) -> PathBuf {
    let mut path = PathBuf::with_capacity(
        base_path.as_ref().as_os_str().len()
            + dir.as_ref().as_os_str().len()
            + 2
            + file.as_ref().as_os_str().len()
            + extension.map_or(0, |e| e.len() + 1),
    );
    path.push(base_path);
    path.push(dir);
    path.push(file);
    if let Some(extension) = extension {
        path.set_extension(extension);
    }
    path
}

/// Get a hardcoded error message.
///
/// It can be useful when you don't have access to the file cache
/// or if a error html file isn't provided. Is used by the preferred
/// function [`default_error`].
#[must_use]
pub fn hardcoded_error_body(code: StatusCode, message: Option<&[u8]>) -> Bytes {
    // a 404 page is 168 bytes. Accounting for long code.canonical_reason() and future message.
    let mut body = BytesMut::with_capacity(200);
    // Get code and reason!
    let reason = code.canonical_reason();

    body.extend(b"<html><head><title>");
    // Code and reason
    body.extend(code.as_str().as_bytes());
    body.extend(b" ");
    if let Some(reason) = reason {
        body.extend(reason.as_bytes());
    }

    body.extend(b"</title></head><body><center><h1>".iter());
    // Code and reason
    body.extend(code.as_str().as_bytes());
    body.extend(b" ");
    if let Some(reason) = reason {
        body.extend(reason.as_bytes());
    }
    body.extend(b"</h1><hr>An unexpected error occurred. <a href='/'>Return home</a>?".iter());

    if let Some(message) = message {
        body.extend(b"<p>");
        body.extend(message);
        body.extend(b"</p>");
    }

    body.extend(b"</center></body></html>".iter());

    body.freeze()
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
            let path = make_path(&host.path, "errors", code.as_str(), Some("html"));

            match read_file_cached(&path, &host.file_cache).await {
                Some(file) => file,
                None => hardcoded_error_body(code, message),
            }
        }
        None => hardcoded_error_body(code, message),
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

/// Clones a [`Response`], discarding the body.
///
/// Use [`Response::map()`] to add a body.
#[inline]
pub fn empty_clone_response<T>(response: &Response<T>) -> Response<()> {
    let mut builder = Response::builder()
        .version(response.version())
        .status(response.status());

    // Unwrap is ok, the builder is guaranteed to have a [`HeaderMap`] if it's valid, which we know it is from above.
    *builder.headers_mut().unwrap() = response.headers().clone();
    builder.body(()).unwrap()
}
/// Clones a [`Request`], discarding the body.
///
/// Use [`Request::map()`] to add a body.
#[inline]
pub fn empty_clone_request<T>(request: &Request<T>) -> Request<()> {
    let mut builder = Request::builder()
        .method(request.method())
        .version(request.version())
        .uri(request.uri().clone());
    // Unwrap is ok, the builder is guaranteed to have a [`HeaderMap`] if it's valid, which we know it is from above.
    *builder.headers_mut().unwrap() = request.headers().clone();
    builder.body(()).unwrap()
}
/// Splits a [`Response`] into a empty [`Response`] and it's body.
#[inline]
pub fn split_response<T>(response: Response<T>) -> (Response<()>, T) {
    let mut body = None;
    let response = response.map(|t| body = Some(t));
    // We know it is `Some`.
    (response, body.unwrap())
}

/// Replaces the header `name` with `new` in `headers`.
///
/// Removes all other occurrences of `name`.
#[inline]
pub fn replace_header<K: header::IntoHeaderName + Copy>(
    headers: &mut HeaderMap,
    name: K,
    new: HeaderValue,
) {
    match headers.entry(name) {
        header::Entry::Vacant(slot) => {
            slot.insert(new);
        }
        header::Entry::Occupied(slot) => {
            slot.remove_entry_mult();
            headers.insert(name, new);
        }
    }
}
/// Replaces header `name` with `new` (a &'static str) in `headers`.
///
/// See [`replace_header`] for more info.
#[inline]
pub fn replace_header_static<K: header::IntoHeaderName + Copy>(
    headers: &mut HeaderMap,
    name: K,
    new: &'static str,
) {
    replace_header(headers, name, HeaderValue::from_static(new))
}
/// Removes all headers from `headers` with `name`.
#[inline]
pub fn remove_all_headers<K: header::IntoHeaderName>(headers: &mut HeaderMap, name: K) {
    if let header::Entry::Occupied(entry) = headers.entry(name) {
        entry.remove_entry_mult();
    }
}

macro_rules! starts_with_any {
    ($e:expr, $($match:expr $(,)?)*) => {
        $($e.starts_with($match) || )* false
    };
}
/// Checks the equality of value of `name` in `headers` and `value`.
/// Value **must** be all lowercase; the [`HeaderValue`] in `headers` is converted to lowercase.
pub fn header_eq(headers: &HeaderMap, name: impl header::AsHeaderName, value: &str) -> bool {
    let header_value = headers
        .get(name)
        .map(HeaderValue::to_str)
        .and_then(Result::ok);
    header_value.map_or(false, |s| s.to_ascii_lowercase() == value)
}

/// Check if `bytes` starts with a valid [`Method`].
#[must_use]
pub fn valid_method(bytes: &[u8]) -> bool {
    starts_with_any!(
        bytes, b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"TRACE", b"OPTIONS", b"CONNECT",
        b"PATCH"
    )
}
/// Checks if `bytes` starts with a valid [`Version`]
#[must_use]
pub fn valid_version(bytes: &[u8]) -> bool {
    starts_with_any!(
        bytes,
        b"HTTP/0.9",
        b"HTTP/1.0",
        b"HTTP/1.1",
        b"HTTP/2",
        b"HTTP/3"
    )
}
/// Gets the body len gth from the [`Request::headers`] of `request`.
///
/// If [`method_has_request_body`] returns `false` or the header isn't present, it defaults to `0`.
#[inline]
pub fn get_body_length_request<T>(request: &Request<T>) -> usize {
    use std::str::FromStr;
    if method_has_request_body(request.method()) {
        request
            .headers()
            .get("content-length")
            .map(HeaderValue::to_str)
            .and_then(Result::ok)
            .map(usize::from_str)
            .and_then(Result::ok)
            .unwrap_or(0)
    } else {
        0
    }
}
/// Sets the `content-length` of `headers` to `len`.
///
/// See [`replace_header`] for details.
#[inline]
pub fn set_content_length(headers: &mut HeaderMap, len: usize) {
    // unwrap is ok, we know the formatted bytes from a number are (0-9) or `.`
    utility::replace_header(
        headers,
        "content-length",
        HeaderValue::from_str(len.to_string().as_str()).unwrap(),
    )
}
/// Gets the body length of a `response`.
///
/// If `method` is [`Some`] and [`method_has_response_body`] returns true, `0` is
/// returned. Else the `content-length` header is checked. `0` is otherwise returned.
pub fn get_body_length_response<T>(response: &Response<T>, method: Option<&Method>) -> usize {
    use std::str::FromStr;
    if method.map_or(true, |m| method_has_response_body(m)) {
        response
            .headers()
            .get("content-length")
            .map(HeaderValue::to_str)
            .and_then(Result::ok)
            .map(usize::from_str)
            .and_then(Result::ok)
            .unwrap_or(0)
    } else {
        0
    }
}

/// Does a request of type `method` have a body?
#[inline]
#[must_use]
pub fn method_has_request_body(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::DELETE)
}
/// Does a response of type `method` have a body?
#[inline]
#[must_use]
pub fn method_has_response_body(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET
            | Method::POST
            | Method::DELETE
            | Method::CONNECT
            | Method::OPTIONS
            | Method::PATCH
    )
}

/// Implements [`Debug`] from the [`Display`] implementation of `value`.
///
/// Can be used to give fields a arbitrary [`mod@str`] without surrounding quotes.
pub struct CleanDebug<'a, T: ?Sized + Display>(&'a T);
impl<'a, T: ?Sized + Display> CleanDebug<'a, T> {
    /// Creates a new wrapper around `value` with [`Debug`] implemented as [`Display`].
    #[inline]
    pub fn new(value: &'a T) -> Self {
        Self(value)
    }
}
impl<'a, T: ?Sized + Display> Debug for CleanDebug<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, f)
    }
}
impl<'a, T: ?Sized + Display> Display for CleanDebug<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, f)
    }
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

// pub fn read_to_async<R: Read>(reader: R) -> ReadToAsync<R> {
//     ReadToAsync(reader)
// }
// pub struct ReadToAsync<R: Read>(R);
// impl<R> AsyncRead for ReadToAsync<R> {
//     fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
//         buf.put_slice(buf)
//         self.get_mut().read(buf)
//     }
// }

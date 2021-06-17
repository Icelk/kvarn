pub mod parse;
pub mod prelude;
use prelude::*;

pub use parse::{sanitize_request, CriticalRequestComponents, list_header, ValueQualitySet};

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
pub fn hardcoded_error_body(code: http::StatusCode, message: Option<&[u8]>) -> Bytes {
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
    replace_header(
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
/// Can be used to give fields a arbitrary [`mod@str`] without surrounding quotes,
/// for example in [`fmt::DebugStruct::field`].
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
/// Trait to enable `.as_clean` to get a [`CleanDebug`] for the variable.
pub trait AsCleanDebug {
    /// Get a [`CleanDebug`] for Self.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let s = "a\tstring";
    /// let clean_debug = s.as_clean();
    ///
    /// // A debug formatting is the same as the value itself.
    /// assert_eq!(format!("{:?}", clean_debug), s);
    ///
    /// // The debug formatting of the `&str` is messy for clean output in debug implementations.
    /// assert_eq!(format!("{:?}", s), r#""a\tstring""#)
    /// ```
    fn as_clean(&self) -> CleanDebug<Self>
    where
        Self: Display,
    {
        CleanDebug::new(self)
    }
}
impl<T: Display> AsCleanDebug for T {}

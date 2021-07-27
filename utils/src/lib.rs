//! Utility functions for web application development.
//!
//! This includes
//! - commonly used [`chars`],
//! - a [`build_bytes`] macro to create a [`Bytes`] from bytes slices with one allocation,
//! - [`WriteableBytes`] to optimize performance when creating a new [`Bytes`] of unknown length,
//! - [`hardcoded_error_body`] to get a hard-coded error response.
//! - [`CleanDebug`] and it's trait [`AsCleanDebug`] to get a [`Debug`] implementation wired to the
//!   item's [`Display`] implementation.
#![deny(
    unreachable_pub,
    missing_debug_implementations,
    missing_docs,
    clippy::pedantic
)]
#![allow(clippy::missing_panics_doc)]

pub mod extensions;
pub mod parse;
pub mod prelude;
use prelude::*;

pub use extensions::{
    PresentArguments, PresentArgumentsIter, PresentExtensions, PresentExtensionsIter,
};
pub use parse::{list_header, sanitize_request, CriticalRequestComponents, ValueQualitySet};

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

/// Convenience macro to create a [`Bytes`] from multiple `&[u8]` sources.
///
/// Allocates only once; capacity is calculated before any allocation.
///
/// Works like the [`vec!`] macro, but takes byte slices and concatenates them together.
///
/// # Examples
///
/// ```
/// # use kvarn_utils::prelude::*;
/// let built_bytes = build_bytes!(b"GET", b" ", b"/foo-", b"bar", b" HTTP/2");
/// assert_eq!(built_bytes, Bytes::from_static(b"GET /foo-bar HTTP/2"));
/// ```
#[macro_export]
macro_rules! build_bytes {
    () => (
        $crate::prelude::prelude::Bytes::new()
    );
    ($($bytes:expr),+ $(,)?) => {{
        let mut b = $crate::prelude::BytesMut::with_capacity($($bytes.len() +)* 0);

        $(b.extend($bytes.iter());)*

        b.freeze()
    }};
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
    /// # use kvarn_utils::prelude::prelude::*;
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
/// function `default_error` found in Kvarn.
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

/// Checks the equality of value of `name` in `headers` and `value`.
/// Value does not need to be all lowercase; the equality operation ignores the cases.
pub fn header_eq(headers: &HeaderMap, name: impl header::AsHeaderName, value: &str) -> bool {
    let header_value = headers
        .get(name)
        .map(HeaderValue::to_str)
        .and_then(Result::ok);
    header_value.map_or(false, |s| s.eq_ignore_ascii_case(value))
}

/// Tests if the first arguments starts with any of the following.
///
/// # Examples
///
/// ```
/// # use kvarn_utils::prelude::*;
/// let example = "POST /api/username HTTP/3";
/// assert!(
///     starts_with_any!(example, "GET" , "HEAD" , "POST")
/// );
/// ```
#[macro_export]
macro_rules! starts_with_any {
    ($e:expr, $($match:expr),*) => {
        $($e.starts_with($match) || )* false
    };
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
/// If `method` is [`Some`] and [`method_has_response_body`] returns false, `0` is
/// returned. If the [`method_has_request_body`] or `method` is [`None`],
/// the `content-length` header is checked. `0` is otherwise returned.
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

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn build_bytes() {
        struct Spaces {
            count: usize,
        }
        impl Spaces {
            fn iter(&mut self) -> &mut Self {
                self
            }
            fn len(&self) -> usize {
                self.count
            }
        }
        impl Iterator for Spaces {
            type Item = u8;
            fn next(&mut self) -> Option<Self::Item> {
                if self.count == 0 {
                    return None;
                }
                self.count -= 1;
                Some(chars::SPACE)
            }
        }
        let mut spaces = Spaces { count: 1 };
        let world = "world!".to_string().into_bytes();
        let bytes = build_bytes!(b"Hello", spaces, &world);
        assert_eq!(bytes, "Hello world!".as_bytes());
    }

    #[test]
    fn starts_with() {
        let example1 = "POST /api/username HTTP/3";
        let example2 = "S_,Qasz>8!+}24_R?Z?j";
        assert!(starts_with_any!(example1, "POST", "PUT", "DELETE", "PATCH"));
        assert!(!starts_with_any!(
            example2, "POST", "PUT", "DELETE", "PATCH", "S_,qasz"
        ));
    }

    #[test]
    fn clean_debug() {
        let message = "All\tOK.";
        assert_eq!(format!("{:?}", message.as_clean()), message);
        assert_ne!(format!("{:?}", message), message);
        assert_eq!(format!("{:?}", message), r#""All\tOK.""#);
    }

    #[test]
    fn writeable_bytes() {
        use io::Write;
        let mut bytes = WriteableBytes::new();
        bytes.write_all(b"oh hi").unwrap();
        bytes.write_all(&[chars::SPACE; 8]).unwrap();
        bytes.write_all(b"bye").unwrap();

        assert_eq!(bytes.into_inner().freeze(), "oh hi        bye".as_bytes());
    }

    #[test]
    fn body_length() {
        let request1 = Request::options("/")
            .body(Bytes::from_static(b"Hello!"))
            .unwrap();
        let request2 = Request::get("/api/update-status")
            .header("content-length", HeaderValue::from_static("42"))
            .body(Bytes::from_static(
                b"{ name: \"Icelk\", status: \"Testing Kvarn\" } spurious data...",
            ))
            .unwrap();
        let request3 = Request::put("/api/status?name=icelk")
            .header("content-length", HeaderValue::from_static("13"))
            .body(Bytes::from_static(b"Testing Kvarn"))
            .unwrap();
        assert_eq!(get_body_length_request(&request1), 0);
        assert_eq!(get_body_length_request(&request2), 0);
        assert_eq!(get_body_length_request(&request3), 13);

        let data =
            Bytes::from_static(b"I refuses to brew coffee because I am, permanently, a teapot.");
        let data_len = data.len();
        let response1 = Response::builder()
            .status(418)
            .header(
                "content-length",
                HeaderValue::from_str(data_len.to_string().as_str()).unwrap(),
            )
            .body(data.clone())
            .unwrap();
        assert_eq!(
            get_body_length_response(&response1, Some(&Method::GET)),
            data_len
        );
        assert_eq!(get_body_length_response(&response1, None), data_len);
        assert_eq!(get_body_length_response(&response1, Some(&Method::PUT)), 0);

        let mut response2 = empty_clone_response(&response1).map(|()| data);
        replace_header_static(
            response2.headers_mut(),
            "Content-Length",
            "invalid content-length",
        );
        assert_eq!(get_body_length_response(&response2, Some(&Method::GET)), 0);
    }
    #[test]
    fn header_case_insensitive_equality() {
        let mut headers = HeaderMap::default();
        headers.append("referrer-policy", HeaderValue::from_static("no-referrer"));
        headers.append("content-encoding", HeaderValue::from_static("gzip"));

        assert!(header_eq(&headers, "referrer-policy", "NO-REFERRER"));
        assert!(header_eq(&headers, "REFERRER-POLICY", "no-refeRrer"));
        assert!(!header_eq(&headers, "REFERRER-POLICY", "NO_REFERRER"));
        assert!(header_eq(&headers, "content-encoding", "gzip"));
        assert!(header_eq(&headers, "Content-Encoding", "gzip"));
        assert!(!header_eq(&headers, "Content_Encoding", "gzip"));
    }
    #[test]
    fn path1() {
        let path = make_path("public", "errors", "404", Some("html"));
        assert_eq!(path, Path::new("public/errors/404.html"));
    }
    #[test]
    fn path2() {
        let path = make_path("public", "errors/static", "404", None);
        assert_eq!(path, Path::new("public/errors/static/404"));
    }

    fn get_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.append("user-agent", HeaderValue::from_static("curl/7.64.1"));
        headers.append(
            "user-agent",
            HeaderValue::from_static("Kvarn/0.2.0 (macOS)"),
        );
        headers.append("accept", HeaderValue::from_static("text/plain"));

        headers
    }
    #[test]
    fn header_management1() {
        let mut headers = get_headers();
        remove_all_headers(&mut headers, "user-agent");
        assert_eq!(headers.get("user-agent"), None);
        assert!(headers.get("accept").is_some());
    }
    #[test]
    fn header_management2() {
        let start = std::time::Instant::now();
        let mut headers = get_headers();
        replace_header(
            &mut headers,
            "user-agent",
            HeaderValue::from_str("tinyquest").unwrap(),
        );
        let processing_time = start.elapsed().as_micros().to_string();
        replace_header(
            &mut headers,
            "x-processing-time",
            HeaderValue::from_str(&processing_time).unwrap(),
        );
        assert_eq!(
            headers.get("user-agent"),
            Some(&HeaderValue::from_static("tinyquest"))
        );
        assert_eq!(
            headers.get("x-processing-time").unwrap().to_str().unwrap(),
            &processing_time
        );
        assert!(headers.get("accept").is_some());
    }
    #[test]
    fn header_management3() {
        let mut headers = get_headers();
        replace_header_static(&mut headers, "user-agent", "tinyquest");
        assert_eq!(
            headers.get("user-agent"),
            Some(&HeaderValue::from_static("tinyquest"))
        );
        assert!(headers.get("accept").is_some());
    }
}

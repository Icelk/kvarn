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

#[doc(inline)]
pub use extensions::{
    PresentArguments, PresentArgumentsIter, PresentExtensions, PresentExtensionsIter,
};
#[doc(inline)]
pub use parse::{list_header, sanitize_request, CriticalRequestComponents, ValueQualitySet};

/// Stringify $field on $self. This only returns the field name.
/// This is constructed to make your IDE recognize the input as the actual field.
/// This means renaming is applied to the string returned from this when you rename a field in your
/// IDE.
///
/// This is useful for debug implementations.
///
/// # Examples
///
/// ```
/// use kvarn_utils::field_str;
///
/// struct Foo {
///     bar: u128,
/// }
/// impl Foo {
///     fn name(&self) -> &'static str {
///         field_str!(self.bar)
///     }
/// }
///
/// let foo = Foo { bar: 42 };
/// assert_eq!(foo.name(), "bar");
#[macro_export]
macro_rules! field_str {
    ($self:ident.$field:ident) => {{
        #[allow(unused_must_use)]
        {
            // this makes the IDE treat the input as the real deal, enabling renaming to also rename
            // the thing to be stringified.
            &$self.$field;
        }
        stringify!($field)
    }};
}
/// Adds a `$field` to the [`std::fmt::DebugStruct`], `$f` from `$self`.
///
/// # Examples
///
/// ```
/// use std::fmt::{self, Debug};
/// use kvarn_utils::{fmt_field, ident_str};
/// struct Foo {
///     bar: u128,
///     foobar: String,
/// }
/// impl Debug for Foo {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         let mut s = f.debug_struct(ident_str!(Foo));
///         fmt_field!(s, self.bar, &self.bar.to_le_bytes());
///         fmt_field!(s, self.foobar);
///         s.finish()
///     }
/// }
#[macro_export]
macro_rules! fmt_field {
    ($f: expr, $self:ident.$field:ident) => {
        $f.field($crate::field_str!($self.$field), &$self.$field);
    };
    ($f: expr, $self:ident.$field:ident, $value:expr) => {
        $f.field($crate::field_str!($self.$field), $value);
    };
}
/// [`fmt_field!`] but multiple.
///
/// # Examples
///
/// ```
/// use std::fmt::{self, Debug};
/// use kvarn_utils::{fmt_fields, ident_str};
/// struct Foo {
///     bar: u128,
///     foo: u32,
///     #[cfg(feature = "foobar")]
///     foobar: String,
/// }
/// impl Debug for Foo {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         let mut s = f.debug_struct(ident_str!(Foo));
///         fmt_fields!(
///             s,
///             (self.bar, &self.bar.to_le_bytes()),
///             (self.foo),
///             #[cfg(feature = "foobar")]
///             (self.foobar),
///         );
///         s.finish()
///     }
/// }
#[macro_export]
macro_rules! fmt_fields {
    ($f: expr, $($(#[$meta:meta])?($self:ident.$field:ident $(, $value:expr)?)),+ $(,)?) => {
        $(
            $(#[$meta])?
            $crate::fmt_field!($f, $self.$field $(, $value)?);
        )+
    };
}
/// Return stringified representation of `$item`.
/// This uses similar techniques to [`ident_str!`].
///
/// # Examples
///
/// See [`fmt_field!`].
///
/// If you have a generic struct:
/// ```
/// use kvarn_utils::ident_str;
///
/// struct Foo<T: Eq + Clone> {
///     bar: T,
/// }
/// assert_eq!(ident_str!(Foo, T, T: Eq + Clone), "Foo");
/// ```
#[macro_export]
macro_rules! ident_str {
    ($item:ident $(, $($name:ident)+, $($generics:tt)+)?) => {{
        // we use this to make rust-analyzer realize $name is
        // an item. This means IDE renaming is also applied on $var.
        #[allow(non_local_definitions)]
        impl$(<$($generics)+>)? $item$(<$($name)+>)? {}
        stringify!($item)
    }};
}

/// Common characters expressed as a single byte each, according to UTF-8.
pub mod chars {
    /// Tab
    pub const TAB: u8 = b'\t';
    /// Line feed
    pub const LF: u8 = b'\n';
    /// Carrage return
    pub const CR: u8 = b'\r';
    /// ` `
    pub const SPACE: u8 = b' ';
    /// `"`
    pub const DOUBLE_QUOTES: u8 = b'"';
    /// `'`
    pub const SINGLE_QUOTES: u8 = b'\'';
}

/// [`Bytes`] but potentially [`BytesMut`], which enables e.g. changing the data without
/// allocations when chaining `Present` extensions.
#[derive(Debug)]
pub enum BytesCow {
    /// We just have a reference. This will be reallocated if you make any changes.
    Ref(Bytes),
    /// We have mutable ownership - giving us maximal control.
    Mut(BytesMut),
}
impl BytesCow {
    /// Make this immutable.
    pub fn freeze(self) -> Bytes {
        match self {
            BytesCow::Ref(b) => b,
            BytesCow::Mut(b) => b.freeze(),
        }
    }
    /// Make this mutable.
    pub fn into_mut(mut self) -> BytesMut {
        core::mem::take(self.ref_mut())
    }
    /// Get a mutable reference to the bytes.
    /// Copies if `self` is [`BytesCow::Ref`].
    pub fn ref_mut(&mut self) -> &mut BytesMut {
        match self {
            BytesCow::Ref(b) => {
                *self = Self::Mut(BytesMut::from(b.as_ref()));
                self.ref_mut()
            }
            BytesCow::Mut(b) => b,
        }
    }
    fn take_mut(&mut self) -> BytesMut {
        core::mem::take(self.ref_mut())
    }
    /// Replace the data in `remove` with `replacement`.
    /// This function is similar to `splice` methods in other languages.
    #[inline]
    pub fn replace(&mut self, mut remove: std::ops::Range<usize>, replacement: &[u8]) {
        #[cold]
        #[inline(never)]
        fn warn_remove_range() {
            warn!("Trying to remove a range where the end is before the start");
        }
        if remove.start > remove.end {
            warn_remove_range();
            remove.start = remove.end;
        }
        let mut bytes = self.take_mut();
        let len_change = replacement
            .len()
            .saturating_sub(remove.end.saturating_sub(remove.start));
        bytes.reserve(len_change);
        let len_before = bytes.len();
        let new_len = (bytes.len() + replacement.len() + remove.start)
            .checked_sub(remove.end)
            .expect("removed more than what was available");
        unsafe {
            bytes.set_len(bytes.len() + len_change);
        };
        bytes.copy_within(remove.end..len_before, remove.start + replacement.len());
        bytes[remove.start..(remove.start + replacement.len())].copy_from_slice(replacement);
        unsafe {
            bytes.set_len(new_len);
        };
        *self = Self::Mut(bytes);
    }
}
impl AsRef<[u8]> for BytesCow {
    fn as_ref(&self) -> &[u8] {
        match self {
            BytesCow::Ref(b) => b,
            BytesCow::Mut(b) => b,
        }
    }
}
impl std::ops::Deref for BytesCow {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}
impl From<Bytes> for BytesCow {
    fn from(b: Bytes) -> Self {
        Self::Ref(b)
    }
}
impl From<BytesMut> for BytesCow {
    fn from(b: BytesMut) -> Self {
        Self::Mut(b)
    }
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
        b
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
impl<T: ?Sized + Display> Debug for CleanDebug<'_, T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, f)
    }
}
impl<T: ?Sized + Display> Display for CleanDebug<'_, T> {
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
    /// # use kvarn_utils::prelude::*;
    /// let s = "a\tstring";
    /// let clean_debug = s.as_clean();
    ///
    /// // A debug formatting is the same as the value itself.
    /// assert_eq!(format!("{:?}", clean_debug), s);
    ///
    /// // The debug formatting of the `&str` is messy for clean output in debug implementations.
    /// assert_eq!(format!("{:?}", s), r#""a\tstring""#)
    /// ```
    fn as_clean(&self) -> CleanDebug<'_, Self>
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
            self.bytes.reserve(buf.len() * 3 / 2 + 128);
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
    base_path: impl AsRef<str>,
    dir: impl AsRef<str>,
    file: impl AsRef<str>,
    extension: Option<&str>,
) -> CompactString {
    let mut path = CompactString::with_capacity(
        base_path.as_ref().len()
            + dir.as_ref().len()
            + 2
            + file.as_ref().len()
            + extension.map_or(0, |e| e.len() + 1),
    );
    path.push_str(base_path.as_ref());
    path.push('/');
    path.push_str(dir.as_ref());
    path.push('/');
    path.push_str(file.as_ref());
    if let Some(extension) = extension {
        let mut folder = false;
        if let Some(pos) = path.rfind(move |c| {
            if folder {
                return false;
            }
            if c == '/' {
                folder = true;
            }
            c == '.'
        }) {
            path.split_off(pos);
        }
        path.push('.');
        path.push_str(extension);
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
    use bytes::BufMut;

    let print_home = !matches!(
        code,
        StatusCode::CONFLICT | StatusCode::METHOD_NOT_ALLOWED | StatusCode::TOO_MANY_REQUESTS
    );

    // Get code and reason!
    let reason = code.canonical_reason();
    let len = 220 - if print_home { 0 } else { 58 }
        + message.map_or(0, <[u8]>::len)
        + (reason.map_or(0, str::len) + code.as_str().len()) * 2;
    // a 404 page is 168 bytes. Accounting for long code.canonical_reason() and future message.
    let mut body = BytesMut::with_capacity(len);

    body.extend(
        b"<!DOCTYPE html><html><head><meta name='color-scheme' content='dark light'><title>",
    );
    // Code and reason
    body.extend_from_slice(code.as_str().as_bytes());
    body.put_u8(b' ');
    if let Some(reason) = reason {
        body.extend_from_slice(reason.as_bytes());
    }

    body.extend_from_slice(b"</title></head><body><center><h1>");
    // Code and reason
    body.extend_from_slice(code.as_str().as_bytes());
    body.put_u8(b' ');
    if let Some(reason) = reason {
        body.extend_from_slice(reason.as_bytes());
    }
    body.extend_from_slice(b"</h1><hr>");
    if print_home {
        body.extend_from_slice(b"An unexpected error occurred. <a href='/'>Return home</a>?");
    }

    if let Some(message) = message {
        body.extend_from_slice(b"<p>");
        body.extend_from_slice(message);
        body.extend_from_slice(b"</p>");
    }

    body.extend_from_slice(b"</center></body></html>");

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
///     kvarn_utils::starts_with_any!(example, "GET" , "HEAD" , "POST")
/// );
/// ```
#[macro_export]
macro_rules! starts_with_any {
    ($e:expr, $($match:expr),* $(,)?) => {
        $($e.starts_with($match) || )* false
    };
}

/// Check if `bytes` starts with a valid [`Method`].
#[must_use]
pub fn valid_method(bytes: &[u8]) -> bool {
    starts_with_any!(
        bytes,
        b"GET",
        b"HEAD",
        b"POST",
        b"PUT",
        b"DELETE",
        b"TRACE",
        b"OPTIONS",
        b"CONNECT",
        b"PATCH",
        // WebDAV
        b"COPY",
        b"LOCK",
        b"MKCOL",
        b"MOVE",
        b"PROPFIND",
        b"PROPPATCH",
        b"UNLOCK",
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
/// Gets the body length from the [`Request::headers`] of `request`.
#[inline]
pub fn get_body_length_request<T>(request: &Request<T>) -> usize {
    use std::str::FromStr;
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::CONNECT | Method::TRACE
    ) {
        return 0;
    }
    request
        .headers()
        .get("content-length")
        .map(HeaderValue::to_str)
        .and_then(Result::ok)
        .map(usize::from_str)
        .and_then(Result::ok)
        .unwrap_or(0)
}
/// Sets the `content-length` of `headers` to `len`.
#[inline]
pub fn set_content_length(headers: &mut HeaderMap, len: u64) {
    headers.insert(
        "content-length",
        // unwrap is ok, we know the formatted bytes from a number are (0-9)
        HeaderValue::from_str(len.to_string().as_str()).unwrap(),
    );
}
/// Gets the body length of a `response`.
///
/// If `method` is [`Some`] and [`method_has_response_body`] returns false, `0` is
/// returned. If `method` is [`None`],
/// the `content-length` header is checked. `0` is otherwise returned.
pub fn get_body_length_response<T>(response: &Response<T>, method: Option<&Method>) -> u64 {
    use std::str::FromStr;
    if method.map_or(true, method_has_response_body) {
        response
            .headers()
            .get("content-length")
            .map(HeaderValue::to_str)
            .and_then(Result::ok)
            .map(u64::from_str)
            .and_then(Result::ok)
            .unwrap_or(0)
    } else {
        0
    }
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

/// Checks `byte` if it's a valid byte for [`HeaderValue`]s.
#[must_use]
#[inline]
pub fn is_valid_header_value_byte(byte: u8) -> bool {
    (32..127).contains(&byte) || byte == b'\t'
}

/// Decodes the URI encoding.
///
/// If any errors surface, `s` is returned.
#[must_use]
#[inline]
pub fn percent_decode(s: &str) -> Cow<'_, str> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .unwrap_or(Cow::Borrowed(s))
}

/// Joins the items in `iter` with a `separator` using 1 allocation.
///
/// `separator` can be `""` to concatenate the items of `iter`.
///
/// This will [`Clone`] `iter`, as we need to count the length of the strings in `iter` and then
/// use them. This should be cheap for most iterators.
pub fn join<S: AsRef<str>, I: Iterator<Item = S> + Clone>(
    iter: I,
    separator: impl AsRef<str>,
) -> String {
    // The adding of `separator.len()` in the map is to add the length of the `separator` after
    // each item, then removing 1 at the end.
    let length = iter
        .clone()
        .map(|s| s.as_ref().len() + separator.as_ref().len())
        .sum::<usize>()
        // Saturating if `iter.len()` is 0.
        .saturating_sub(separator.as_ref().len());

    let mut string = String::with_capacity(length);

    for (pos, s) in iter.enumerate() {
        if pos != 0 {
            string += separator.as_ref();
        }
        string += s.as_ref();
    }

    string
}

#[derive(Debug, Clone, Copy)]
enum InQuotes {
    No,
    Single,
    Double,
}
impl InQuotes {
    fn quoted(self) -> bool {
        matches!(self, Self::Single | Self::Double)
    }
}
/// Iterator for [`quoted_str_split`].
/// Returns owned strings.
#[derive(Debug, Clone)]
#[must_use = "consume the iterator"]
pub struct QuotedStrSplitIter<'a> {
    iter: std::str::Chars<'a>,
    quotes: InQuotes,
    current: String,
    escaped: usize,
}
impl Iterator for QuotedStrSplitIter<'_> {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            #[allow(clippy::single_match_else)] // clarity
            let c = match self.iter.next() {
                Some(c) => c,
                None => {
                    if !self.current.is_empty() {
                        return Some(std::mem::take(&mut self.current));
                    }
                    return None;
                }
            };
            // check this before the exceptions below
            if c == '\\' {
                self.escaped += 1;
                // skip to the next iteration.
                match self.escaped {
                    1 => continue,
                    2 => {
                        self.current.push('\\');
                        self.escaped = 0;
                        continue;
                    }
                    _ => {}
                }
            }
            if self.escaped != 1 {
                match c {
                    ' ' if !self.quotes.quoted() => {
                        if self.current.is_empty() {
                            continue;
                        }
                        return Some(std::mem::replace(
                            &mut self.current,
                            String::with_capacity(16),
                        ));
                    }
                    '"' => match self.quotes {
                        InQuotes::No => {
                            self.quotes = InQuotes::Double;
                            continue;
                        }
                        InQuotes::Double => {
                            self.quotes = InQuotes::No;
                            continue;
                        }
                        InQuotes::Single => {}
                    },
                    '\'' => match self.quotes {
                        InQuotes::No => {
                            self.quotes = InQuotes::Single;
                            continue;
                        }
                        InQuotes::Single => {
                            self.quotes = InQuotes::No;
                            continue;
                        }
                        InQuotes::Double => {}
                    },
                    _ => {}
                }
            }
            if c != '\\' {
                self.escaped = 0;
            }
            self.current.push(c);
        }
    }
}
/// Shell-like splitting of `s`.
///
/// Quotes (both single and double) and backslashes `\` disables spaces'
/// effect.
///
/// # Examples
///
/// This is quote a convoluted example which shows some of the more intrecate edge-cases.
/// Refer to the tests at the bottom of this
/// [source file](https://github.com/Icelk/kvarn/blob/main/utils/src/lib.rs) for more examples.
///
/// ```
/// # use kvarn_utils::*;
/// let s = r#"program arg1 'arg "'two\ st\"il"l goes "on. 'third-arg "#;
/// assert_eq!(quoted_str_split(s).collect::<Vec<_>>(), ["program", "arg1", "arg \"two st\"ill goes on.", "third-arg "]);
/// ```
pub fn quoted_str_split(s: &str) -> QuotedStrSplitIter<'_> {
    QuotedStrSplitIter {
        iter: s.chars(),
        quotes: InQuotes::No,
        current: String::with_capacity(16),
        escaped: 0,
    }
}
/// Encodes, to be decoded by [`quoted_str_split`], `src` by appending to `dest`.
///
/// This takes care of escapes, quotes, etc. The output of [`quoted_str_split`] when given `dest`
/// should be the same as `src`.
///
/// Capacity on `dest` is reserved using heuristics - you don't need to use `with_capacity` or
/// `reserve` on `dest`.
pub fn encode_quoted_str(src: &str, dest: &mut String) {
    dest.reserve(src.len() + 2 + 4); // 2 for quotes and 4 for good measure (e.g. capacity for \\, \")
    dest.push('"');
    for c in src.chars() {
        match c {
            '"' => dest.push_str("\\\""),
            '\\' => dest.push_str("\\\\"),
            _ => dest.push(c),
        }
    }
    dest.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let data_len = data.len() as u64;
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
        response2.headers_mut().insert(
            "Content-Length",
            HeaderValue::from_static("invalid content-length"),
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
        assert_eq!(path, "public/errors/404.html");
    }
    #[test]
    fn path2() {
        let path = make_path("public", "errors/static", "404", None);
        assert_eq!(path, "public/errors/static/404");
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
        headers.insert("user-agent", HeaderValue::from_str("tinyquest").unwrap());
        let processing_time = start.elapsed().as_micros().to_string();
        headers.insert(
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
        headers.insert("user-agent", HeaderValue::from_static("tinyquest"));
        assert_eq!(
            headers.get("user-agent"),
            Some(&HeaderValue::from_static("tinyquest"))
        );
        assert!(headers.get("accept").is_some());
    }

    #[test]
    fn quoted_str_split_1() {
        let s = r#"this" should be" quoted. Is\ it?"#;
        assert_eq!(
            quoted_str_split(s).collect::<Vec<_>>(),
            ["this should be", "quoted.", "Is it?"]
        );
    }
    #[test]
    fn quoted_str_split_2() {
        let s = r" yay! this\\ works\ ! ";
        assert_eq!(
            quoted_str_split(s).collect::<Vec<_>>(),
            ["yay!", "this\\", "works !"]
        );
    }
    #[test]
    fn quoted_str_split_3() {
        let s = r" how' bou't this?' no end to this quote ";
        assert_eq!(
            quoted_str_split(s).collect::<Vec<_>>(),
            ["how bout", "this? no end to this quote "]
        );
    }
    #[test]
    fn quoted_str_split_4() {
        let s = r#"Just normal quotes:\ \" and \'."#;
        assert_eq!(
            quoted_str_split(s).collect::<Vec<_>>(),
            ["Just", "normal", "quotes: \"", "and", "'."]
        );
    }
    #[test]
    fn quoted_str_split_5() {
        let s = r#"This 'is a quote " inside a quote. "#;
        assert_eq!(
            quoted_str_split(s).collect::<Vec<_>>(),
            ["This", "is a quote \" inside a quote. "]
        );
    }
    #[test]
    fn quoted_str_split_6() {
        let s = r#"h"i \\\\\" the"re"#;
        assert_eq!(quoted_str_split(s).collect::<Vec<_>>(), [r#"hi \\" there"#]);
    }
    #[test]
    fn quoted_str_encode_decode_1() {
        let src = r#"program arg1 'arg "'two\ st\\\"il"l goes "on. 'third-arg "#;
        let mut dest = String::new();
        encode_quoted_str(src, &mut dest);

        let mut iter = quoted_str_split(&dest);
        assert_eq!(iter.next().unwrap(), src);
        assert_eq!(iter.next(), None);
    }
}

//! General parsing complying to the HTTP standards.
//!
//! This parses small bits of a HTTP request/response to extract common information.
//! The [`sanitize_request`] exists to check if a request is valid.
//!
//! This is where part of Layer 6 resides. The [`list_header`] and [`query`]
//! are very useful.

use crate::{percent_decode, prelude::*};

/// A general error from parsing.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a [`http`] type.
    ///
    /// This is often a [`Uri`], [`Request`], [`Method`], or [`Version`].
    Http(http::Error),
    /// No path was parsed as part of a [`Request`]
    NoPath,
    /// Done reading and processing
    UnexpectedEnd,
    /// The header is too long.
    ///
    /// 'header' is the data before `\r\n\r\n`, and
    /// may be invalid data not containing a `\r\n\r\n`
    HeaderTooLong,
    /// The path ([`Uri`]) is invalid and could not be parsed
    InvalidPath,
    /// The [`Method`] is invalid
    InvalidMethod,
    /// The [`Version`] is invalid
    InvalidVersion,
    /// The [`StatusCode`] is invalid
    InvalidStatusCode,
    /// A syntax error in the data.
    ///
    /// Often means the request isn't what we expect;
    /// maybe it's transmitted over HTTPS.
    Syntax,
    /// There are illegal bytes in a [`HeaderName`]
    IllegalName,
    /// There are illegal bytes in a [`HeaderValue`]
    IllegalValue,
    /// No host was found and no default host was specified.
    NoHost,
}
impl Error {
    /// Gets a string representation of [`Error`].
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http(_) => "http library parsing error",
            Self::NoPath => "no path was supplied in the request",
            Self::UnexpectedEnd => "stream is exhausted",
            Self::HeaderTooLong => "header is too long",
            Self::InvalidPath => "path is invalid or contains illegal bytes",
            Self::InvalidMethod => "method is invalid",
            Self::InvalidVersion => "version is invalid",
            Self::InvalidStatusCode => "status code in invalid",
            Self::Syntax => {
                "invalid syntax of data. The input might unexpectedly \
                be encrypted (HTTPS) or compressed (HTTP/2)"
            }
            Self::IllegalName => "header name invalid",
            Self::IllegalValue => "header value invalid",
            Self::NoHost => "the host could not be resolved",
        }
    }
}
impl From<http::Error> for Error {
    #[inline]
    fn from(err: http::Error) -> Self {
        Self::Http(err)
    }
}
impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::Http(http) => io::Error::new(io::ErrorKind::InvalidData, http),
            Error::NoPath
            | Error::HeaderTooLong
            | Error::InvalidPath
            | Error::InvalidMethod
            | Error::InvalidVersion
            | Error::InvalidStatusCode
            | Error::Syntax
            | Error::IllegalName
            | Error::IllegalValue
            | Error::NoHost => io::Error::new(io::ErrorKind::InvalidData, err.as_str()),
            Error::UnexpectedEnd => io::Error::new(io::ErrorKind::BrokenPipe, err.as_str()),
        }
    }
}

/// An error with parsing [`CacheControl`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CacheControlError {
    /// Multiple `max-age` directives were found.
    ///
    /// There must only be one; else you can't decide which to honour.
    MultipleMaxAge,
    /// Could not parse integer in max-age or Kvarn cache control header.
    InvalidInteger,
    /// The unit in the `kvarn-cache-control` header is invalid.
    ///
    /// For now, valid units are
    /// - `s` for seconds
    /// - `m` for minutes
    /// - `h` for hours
    /// - `d` for days
    InvalidUnit,
    /// The `kvarn-cache-control` header is a keyword, but it is invalid.
    ///
    /// For now, valid keywords are
    /// - `none` for no caching
    /// - and `full` for endless caching.
    InvalidKeyword,
    /// Could not convert [`HeaderValue::to_str`].
    InvalidBytes,
}
/// Directives to limit cache lifetime, read from `cache-control` and `kvarn-cache-control` headers.
///
/// See [`Self::from_cache_control`] and [`Self::from_kvarn_cache_control`] for respective parsing.
#[derive(Debug, Clone)]
pub struct CacheControl {
    max_age: Option<u32>,
    no_store: bool,
}
impl CacheControl {
    /// Respects `max-age=` and `no-store` parts of `cache-control` header.
    ///
    /// Uses the standard syntax.
    ///
    /// # Errors
    ///
    /// Can return [`CacheControlError::MultipleMaxAge`] and [`CacheControlError::InvalidInteger`].
    pub fn from_cache_control(header: &str) -> Result<Self, CacheControlError> {
        let mut max_age = None;
        let mut no_store = false;
        for segment in header.split(',') {
            let trimmed = segment.trim();
            if trimmed.starts_with("no-store") {
                no_store = true;
            } else if let Some(age) = trimmed.strip_prefix("max-age=") {
                if max_age.is_some() {
                    return Err(CacheControlError::MultipleMaxAge);
                }
                if let Ok(age) = age.parse() {
                    max_age = Some(age);
                } else {
                    return Err(CacheControlError::InvalidInteger);
                }
            }
        }

        Ok(CacheControl { max_age, no_store })
    }
    /// Converts a `kvarn-cache-control` header to a [`CacheControl`] directive.
    ///
    /// The `kvarn-cache-control` header is used for reverse-proxy servers and other downstream sources to
    /// signal how Kvarn should cache their content. This header is prioritized over `cache-control`, but serves a
    /// similar function. This only applies to the server cache, whereas `cache-control` effects both the client
    /// and the server (if this header isn't available).
    ///
    /// See [`CacheControlError::InvalidUnit`] for available units.
    ///
    /// # Examples
    ///
    /// To limit a response to be in the cache for 10 minutes,
    /// return `kvarn-cache-control: 10m` as a header in a
    /// reverse-proxied server or in a extension.
    ///
    /// # Errors
    ///
    /// Can return [`CacheControlError::InvalidKeyword`], [`CacheControlError::InvalidUnit`],
    /// and [`CacheControlError::InvalidInteger`].
    pub fn from_kvarn_cache_control(header: &str) -> Result<Self, CacheControlError> {
        let header = header.trim();
        Ok(match header {
            "none" => Self {
                max_age: None,
                no_store: true,
            },
            "full" => Self {
                max_age: None,
                no_store: false,
            },
            _ if header.len() > 1
                && header.chars().next().map_or(false, char::is_numeric)
                && header
                    .chars()
                    .next_back()
                    .as_ref()
                    .map_or(false, char::is_ascii_alphabetic) =>
            {
                // This will not panic; the last character is ascii.
                let integer = &header[..header.len() - 1];
                let integer: u32 = integer
                    .parse()
                    .ok()
                    .ok_or(CacheControlError::InvalidInteger)?;
                let multiplier = match header.chars().next_back().unwrap_or('s') {
                    's' => 1,
                    'm' => 60,
                    'h' => 60 * 60,
                    'd' => 60 * 60 * 24,
                    _ => return Err(CacheControlError::InvalidUnit),
                };
                Self {
                    max_age: Some(integer * multiplier),
                    no_store: false,
                }
            }
            _ => return Err(CacheControlError::InvalidKeyword),
        })
    }
    /// Tries to get [`CacheControl`] from a [`HeaderMap`].
    ///
    /// See [`Self::from_kvarn_cache_control`] for more info about how the
    /// server cache directive is decided.
    ///
    /// # Errors
    ///
    /// Same as [`Self::from_kvarn_cache_control`] and [`Self::from_cache_control`] with
    /// [`CacheControlError::InvalidBytes`] if [`HeaderValue::to_str`] returns an error.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, CacheControlError> {
        headers.get("kvarn-cache-control").map_or_else(
            || {
                headers.get("cache-control").map_or(
                    Ok(Self {
                        max_age: None,
                        no_store: false,
                    }),
                    |value| {
                        if let Ok(s) = value.to_str() {
                            Self::from_cache_control(s)
                        } else {
                            Err(CacheControlError::InvalidBytes)
                        }
                    },
                )
            },
            |value| {
                if let Ok(s) = value.to_str() {
                    Self::from_kvarn_cache_control(s)
                } else {
                    Err(CacheControlError::InvalidBytes)
                }
            },
        )
    }

    /// Returns if you should cache.
    #[must_use]
    pub fn store(&self) -> bool {
        // Don't store if max_age less than 60s.
        !self.no_store || self.max_age.map_or(false, |age| age > 60)
    }
    /// Gets the freshness lifetime of this cache control directive.
    /// If the returned value is [`None`], you should let it be in the cache for as long as possible,
    /// longer than any with a defined lifetime.
    #[must_use]
    pub fn as_freshness(&self) -> Option<u32> {
        if let (true, Some(max_age)) = (self.store(), self.max_age) {
            Some(max_age)
        } else {
            None
        }
    }
}

/// A pair of a value string and a quality of said value.
///
/// Often used in the `accept-*` HTTP headers.
#[derive(Debug, PartialEq)]
pub struct ValueQualitySet<'a> {
    /// The value with a quality
    pub value: &'a str,
    /// The quality of a value
    pub quality: f32,
}
impl PartialEq<str> for ValueQualitySet<'_> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.value == other
    }
}

/// Parses a header with a value-quality list of pairs.
///
/// Very useful to parse `accept-*` HTTP headers.
#[must_use]
pub fn list_header(header: &str) -> Vec<ValueQualitySet<'_>> {
    let elements = header
        .chars()
        .fold(1, |acc, byte| if byte == ',' { acc + 1 } else { acc });
    let mut list = Vec::with_capacity(elements);

    let mut start_byte = 0;
    let mut end_byte = 0;
    let mut in_quality = false;
    let mut previous_was_q = false;
    let mut quality_start_byte = 0;
    for (position, byte) in header.char_indices() {
        if byte == ' ' {
            continue;
        }

        if in_quality && quality_start_byte == 0 {
            match byte {
                '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '.' => {
                    quality_start_byte = position;
                }
                _ => {}
            }
        }

        if byte == ';' && !in_quality {
            end_byte = position;
            in_quality = true;
        }
        if in_quality {
            if byte == '=' && previous_was_q {
                quality_start_byte = position + 1;
            }
            previous_was_q = byte == 'q';
        }

        if byte == ',' {
            let quality = header
                .get(quality_start_byte..position)
                .and_then(|quality| quality.parse().ok())
                .unwrap_or(1.0);
            if let Some(accept) =
                header.get(start_byte..if end_byte == 0 { position } else { end_byte })
            {
                list.push(ValueQualitySet {
                    value: accept,
                    quality,
                });
            }
            quality_start_byte = 0;
            end_byte = 0;
            start_byte = if header.as_bytes().get(position + 1) == Some(&chars::SPACE) {
                position + 2
            } else {
                position + 1
            };
            in_quality = false;
        }
    }
    // Last, when reaches EOF
    let quality = header
        .get(quality_start_byte..)
        .and_then(|quality| quality.parse().ok())
        .unwrap_or(1.0);
    if let Some(accept) = header.get(
        start_byte..if end_byte == 0 {
            header.len()
        } else {
            end_byte
        },
    ) {
        list.push(ValueQualitySet {
            value: accept,
            quality,
        });
    }
    list
}

/// A key-value pair in the query.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryPair<'a> {
    name: Cow<'a, str>,
    value: Cow<'a, str>,
}
impl<'a> QueryPair<'a> {
    fn new(name: Cow<'a, str>, value: Cow<'a, str>) -> Self {
        Self { name, value }
    }
    /// Gets the name of the query pair
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Gets the value of the query pair
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}
impl<'a> Display for QueryPair<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        f.write_str("=")?;
        f.write_str(self.value())
    }
}
/// A set of [`QueryPair`]s, parsed from a [`query`].
///
/// This is a multimap (one to many relation between keys and values) struct.
/// A query can have multiple values per name.
/// If we always use the first or last value of a name in a query, subtle exploits slip in.
/// You have to make a explicit choice of what to do in this implementation.
///
/// Note that the order of the names in the [`Display`] implementation may be in the right order.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct Query<'a> {
    pairs: Vec<QueryPair<'a>>,
}
impl<'a> Query<'a> {
    fn insert(&mut self, name: Cow<'a, str>, value: Cow<'a, str>) {
        match self.index_of(&name) {
            Ok(pos) | Err(pos) => {
                let pos = self.iterate_to_last(&name, pos);
                self.pairs.insert(pos, QueryPair::new(name, value));
            }
        }
    }

    /// Returns a iterator of all values with `name`.
    ///
    /// Don't use this to get the first or last item; you'll get the same drawbacks as
    /// [`Self::get_first`] and [`Self::get_last`].
    pub fn get_all(&self, name: &'a str) -> QueryPairIter {
        QueryPairIter::new(self, name)
    }
    /// Returns the value of `name`.
    /// This is the recommended method to get a [`QueryPair`].
    ///
    /// Note that this can return [`None`] even if `name` is present in the query.
    ///
    /// If there exists multiple values associated with a name, [`None`] is returned.
    #[must_use]
    pub fn get(&self, name: &'a str) -> Option<&QueryPair> {
        let mut iter = self.get_all(name).peekable();
        let first = iter.next()?;
        if iter.peek().is_some() {
            None
        } else {
            Some(first)
        }
    }
    /// Gets the first value of `name` in the query.
    /// Consider using [`Self::get`] instead, as it eliminates risks for query attacks.
    ///
    /// Watch [this Youtube video](https://youtu.be/QVZBl8yxVX0) to see how it can be exploited.
    #[must_use]
    pub fn get_first(&self, name: &'a str) -> Option<&QueryPair> {
        self.get_all(name).next()
    }
    /// Gets the last value of `name` in the query.
    /// Consider using [`Self::get`] instead, as it eliminates risks for query attacks.
    ///
    /// Watch [this Youtube video](https://youtu.be/QVZBl8yxVX0) to see how it can be exploited.
    #[must_use]
    pub fn get_last(&self, name: &'a str) -> Option<&QueryPair> {
        self.get_all(name).next_back()
    }
    /// If the value is found then [`Result::Ok`] is returned, containing the
    /// index of the matching element.
    /// If the value is not found then
    /// [`Result::Err`] is returned, containing the index where a matching
    /// element could be inserted while maintaining sorted order.
    fn index_of(&self, name: &str) -> Result<usize, usize> {
        self.pairs.binary_search_by(|probe| probe.name().cmp(name))
    }
    /// Index can be any position in the array with the [`QueryPair::name`] set to `name`.
    fn iterate_to_first(&self, name: &str, mut index: usize) -> usize {
        for pair in self.pairs[..index].iter().rev() {
            if pair.name() == name {
                index -= 1;
            } else {
                break;
            }
        }
        index
    }
    /// Index can be any position in the array with the [`QueryPair::name`] set to `name`.
    fn iterate_to_last(&self, name: &str, mut index: usize) -> usize {
        for pair in &self.pairs[index..] {
            if pair.name() == name {
                index += 1;
            } else {
                break;
            }
        }
        index
    }
    /// See [`Self::index_of`] and [`Self::iterate_to_first`].
    fn find_first(&self, name: &str) -> Result<usize, usize> {
        let index = self.index_of(name)?;
        Ok(self.iterate_to_first(name, index))
    }
}
impl<'a> Display for Query<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for (pos, pair) in self.pairs.iter().enumerate() {
            f.write_fmt(format_args!("{}", pair))?;
            if self.pairs.len() - 1 != pos {
                f.write_str("&")?;
            }
        }
        Ok(())
    }
}

/// An iterator of the values of a name in a [`Query`].
/// Created by [`Query::get_all`].
#[derive(Debug)]
#[must_use]
pub struct QueryPairIter<'a> {
    query: &'a Query<'a>,
    pos: Option<usize>,
    back_pos: Option<usize>,
    name: &'a str,
}
impl<'a> QueryPairIter<'a> {
    fn new(query: &'a Query, name: &'a str) -> Self {
        Self {
            pos: None,
            back_pos: None,
            query,
            name,
        }
    }
    fn ensure_pos(&mut self) {
        if self.pos.is_none() {
            self.pos = Some(self.back_pos.map_or_else(
                || self.query.find_first(self.name).unwrap_or(usize::MAX),
                |last| self.query.iterate_to_first(self.name, last),
            ));
        }
    }
    fn ensure_back_pos(&mut self) {
        if self.back_pos.is_none() {
            self.pos = Some(self.pos.map_or_else(
                || {
                    self.query
                        .index_of(self.name)
                        .map(|index| self.query.iterate_to_last(self.name, index))
                        .unwrap_or(usize::MAX)
                },
                |first| self.query.iterate_to_last(self.name, first),
            ));
        }
    }
}
impl<'a> Iterator for QueryPairIter<'a> {
    type Item = &'a QueryPair<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.ensure_pos();
        if Some(self.pos.unwrap()) == self.back_pos {
            return None;
        }
        self.query.pairs.get(self.pos.unwrap()).and_then(|current| {
            if current.name() == self.name {
                *self.pos.as_mut().unwrap() += 1;
                Some(current)
            } else {
                None
            }
        })
    }
}
impl<'a> DoubleEndedIterator for QueryPairIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.ensure_back_pos();
        if self.pos == Some(self.back_pos.unwrap()) {
            return None;
        }
        self.query
            .pairs
            .get(self.back_pos.unwrap())
            .and_then(|current| {
                if current.name() == self.name {
                    *self.back_pos.as_mut().unwrap() -= 1;
                    Some(current)
                } else {
                    None
                }
            })
    }
}

/// Parses a query to a map between keys and their values, as specified in the query.
///
/// `query` should not contain the `?`, but start the byte after.
///
/// Both the keys and values can be empty.
///
/// This decodes the URI's percent encoding.
pub fn query(query: &str) -> Query {
    let elements = query
        .chars()
        .fold(1, |acc, byte| acc + usize::from(byte == '&'));
    let mut map = Query {
        pairs: Vec::with_capacity(elements),
    };

    let mut pair_start = 0;
    let mut value_start = 0;
    for (position, byte) in query.char_indices() {
        match byte {
            '=' => {
                value_start = position + 1;
            }
            '&' => {
                let key = query.get(pair_start..value_start.saturating_sub(1));
                let value = query.get(value_start..position);

                if let (Some(key), Some(value)) = (key, value) {
                    if !key.is_empty() {
                        map.insert(percent_decode(key), percent_decode(value));
                    }
                }

                pair_start = position + 1;
            }
            _ => {}
        }
    }
    {
        let key = query.get(pair_start..value_start.saturating_sub(1));
        let value = query.get(value_start..);

        if let (Some(key), Some(value)) = (key, value) {
            if !key.is_empty() {
                map.insert(percent_decode(key), percent_decode(value));
            }
        }
    }
    map
}

/// Will convert an [`prim@str`] path component of a [`Uri`] to a [`Path`].
/// It asserts the first byte is a [`chars::FORWARD_SLASH`] and then chops it off.
///
/// > _Note: you **must** check that the path is safe to read from before using it. See [`sanitize_request`]._
///
/// Will return `None` if `path.is_empty()` or if the first byte isn't a `/`.
#[inline]
#[must_use]
pub fn uri(path: &str) -> Option<&str> {
    if path.as_bytes().first().copied() != Some(chars::FORWARD_SLASH) {
        return None;
    }
    // Unsafe is ok, since we remove the first byte of a string that is always `/`, occupying exactly one byte.
    let stripped_path = unsafe { str::from_utf8_unchecked(&path.as_bytes()[1..]) };

    Some(stripped_path)
}
/// Critical components from request to apply to response.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct CriticalRequestComponents {
    range: Option<(usize, usize)>,
}
impl CriticalRequestComponents {
    /// Applies the critical components' info to the `response`.
    ///
    /// For now applies range and replaces the `accept-ranges` header.
    ///
    /// # Errors
    ///
    /// Will return a [`SanitizeError::RangeNotSatisfiable`] if the start of the range is greater
    /// than the length of the body.
    pub fn apply_to_response(
        &self,
        response: &mut Response<Bytes>,
        overriden_len: Option<usize>,
    ) -> Result<(), SanitizeError> {
        if let Some((range_start, mut range_end)) = self.get_range() {
            // Clamp to length
            if range_end >= response.body().len() {
                range_end = response.body().len();
            }
            if range_start >= response.body().len() {
                return Err(SanitizeError::RangeNotSatisfiable);
            }

            let len = response.body().len().to_string();
            let start = range_start.to_string();
            let end = (range_end - 1).to_string();
            let bytes =
                crate::build_bytes!(start.as_bytes(), b"-", end.as_bytes(), b"/", len.as_bytes());

            response.headers_mut().insert(
                "content-range",
                // We know integers, b"-", and b"/" are OK!
                HeaderValue::from_maybe_shared(bytes).unwrap(),
            );

            let body = response.body().slice(range_start..range_end);
            *response.body_mut() = body;
            if response.status() == StatusCode::OK {
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            }
        } else if !response.body().is_empty() || overriden_len.map_or(false, |len| len > 0) {
            response
                .headers_mut()
                .insert("accept-ranges", HeaderValue::from_static("bytes"));
        }
        Ok(())
    }
    /// Get the range wanted by the request.
    ///
    /// The first value is the start and the second is the end.
    /// Both are relative to the start of the data.
    #[inline]
    #[must_use]
    pub fn get_range(&self) -> Option<(usize, usize)> {
        self.range
    }
}
/// An error regarding the sanitization of a request.
///
/// See the variants below and [`sanitize_request`] for when this happens.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeError {
    /// The path is unsafe. Nothing should be read from the FS.
    ///
    /// This occurs when the path is absolute or contains `./`.
    UnsafePath,
    /// The range is too large or the beginning is greater than the end.
    RangeNotSatisfiable,
}

/// Sanitizes `request` for unwanted data and returns critical components.
///
/// # Errors
///
/// Will alert you when the request's path contains a `./` or [`Path::is_absolute()`].
/// Also rejects ranges which have a start after the end.
///
/// See [`SanitizeError`] for all the variants.
pub fn sanitize_request<T>(
    request: &Request<T>,
) -> Result<CriticalRequestComponents, SanitizeError> {
    let uri_decoded_path = percent_decode(request.uri().path());
    let path_ok = if uri_decoded_path.contains("./") || !uri_decoded_path.starts_with('/') {
        false
    } else {
        parse::uri(&uri_decoded_path).map_or(false, |s| Path::new(s).is_relative())
    };
    if !path_ok {
        return Err(SanitizeError::UnsafePath);
    }
    let range = request.headers().get("range").and_then(|v| {
        let v = v.to_str().ok()?;
        if !v.starts_with("bytes=") {
            return None;
        }
        if v.contains(|c| c == ',' || c == ' ') {
            return None;
        }
        let separator = v.find('-')?;
        let first: usize = v.get(6..separator)?.parse().ok()?;
        let second: usize = v.get(separator + 1..)?.parse().ok()?;
        Some((first, second))
    });
    let mut data = CriticalRequestComponents { range: None };

    if let Some((start, end)) = range {
        if start >= end {
            return Err(SanitizeError::RangeNotSatisfiable);
        }
        data.range = Some((start, end + 1));
    }
    Ok(data)
}

/// Parses a [`Version`].
///
/// `bytes` have to be the right length,
/// 8 bytes for HTTP/0.9-1.1 and 6 bytes for HTTP/2-
#[inline]
#[must_use]
pub fn version(bytes: &[u8]) -> Option<Version> {
    Some(match bytes {
        b"HTTP/0.9" => Version::HTTP_09,
        b"HTTP/1.0" => Version::HTTP_10,
        b"HTTP/1.1" => Version::HTTP_11,
        b"HTTP/2" => Version::HTTP_2,
        b"HTTP/3" => Version::HTTP_3,
        _ => return None,
    })
}

/// Stages of parsing a HTTP [`Request`].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[must_use]
pub enum RequestParseStage {
    /// We are parsing the [`Method`].
    Method,
    /// We are parsing the [`Uri::path_and_query`] part of the [`Uri`].
    Path,
    /// We are parsing the [`Version`].
    Version,
    /// We are parsing a [`HeaderName`].
    /// The number indicates the position of this name.
    HeaderName(u32),
    /// We are parsing a [`HeaderValue`].
    /// The number indicates the position of this value.
    HeaderValue(u32),
}
impl RequestParseStage {
    /// Advances the stage of the parsing.
    #[inline]
    pub fn next(&mut self) {
        *self = match self {
            RequestParseStage::Method => RequestParseStage::Path,
            RequestParseStage::Path => RequestParseStage::Version,
            RequestParseStage::Version => RequestParseStage::HeaderName(0),
            RequestParseStage::HeaderName(n) => RequestParseStage::HeaderValue(*n),
            RequestParseStage::HeaderValue(n) => RequestParseStage::HeaderName(*n + 1),
        }
    }
}

/// Formats headers and returns the bytes from the start of `bytes`
/// where the body starts; how many bytes the header occupy.
///
/// # Errors
///
/// Returns an error if parsing a [`HeaderName`] or [`HeaderValue`] failed.
pub fn headers(bytes: &Bytes) -> Result<(HeaderMap, usize), Error> {
    let mut headers = HeaderMap::new();
    let mut parse_stage = RequestParseStage::HeaderName(0);
    let mut header_end = 0;
    let mut lf_in_row = 0;
    let mut header_name_start = 0;
    let mut name_end = 0;
    let mut value_start = 0;
    for (pos, byte) in bytes.iter().copied().enumerate() {
        header_end += 1;
        if byte == chars::CR {
            continue;
        }
        if byte == chars::LF {
            lf_in_row += 1;
            if lf_in_row == 2 {
                break;
            }
        } else {
            lf_in_row = 0;
        }
        match parse_stage {
            RequestParseStage::HeaderName(..) => {
                if byte == chars::COLON {
                    name_end = pos;
                    if bytes.get(pos + 1) != Some(&chars::SPACE) {
                        parse_stage.next();
                        let rest = &bytes[pos..];
                        value_start =
                            rest.iter().copied().position(|b| b != b' ').unwrap_or(0) + pos;
                    }
                    continue;
                }
                if byte == chars::SPACE {
                    parse_stage.next();
                    let rest = &bytes[pos..];
                    value_start = rest.iter().copied().position(|b| b != b' ').unwrap_or(0) + pos;
                    continue;
                }
            }
            RequestParseStage::HeaderValue(..) => {
                if byte == chars::LF {
                    let name = HeaderName::from_bytes(
                        bytes
                            .get(header_name_start..name_end)
                            .ok_or(Error::IllegalName)?,
                    )
                    .ok()
                    .ok_or(Error::IllegalName)?;
                    let value = HeaderValue::from_maybe_shared(bytes.slice(value_start..pos - 1))
                        .ok()
                        .ok_or(Error::IllegalValue)?;
                    headers.insert(name, value);
                    parse_stage.next();
                    header_name_start = pos + 1;
                    continue;
                }
            }
            // We know this isn't reached.
            _ => unreachable!(),
        };
    }
    Ok((headers, header_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize() {
        let request1 = Request::get("/../../etc/passwd").body(()).unwrap();
        let request2 = Request::get("//etc/passwd").body(()).unwrap();
        let request3 = Request::get("/static/movie.mkv")
            .header("range", HeaderValue::from_static("bytes=53424-98342"))
            .body(())
            .unwrap();
        let request4 = Request::get("/static/movie.mkv")
            .header("range", HeaderValue::from_static("53424-98342"))
            .body(())
            .unwrap();
        let request5 = Request::get("/static/movie.mkv")
            .header("range", HeaderValue::from_static("bytes=53424-48342"))
            .body(())
            .unwrap();
        let request6 = Request::get("/static/movie.mkv")
            .header(
                "range",
                HeaderValue::from_static("bytes=53424-98342, 98342-100000"),
            )
            .body(())
            .unwrap();

        assert_eq!(sanitize_request(&request1), Err(SanitizeError::UnsafePath));
        assert_eq!(sanitize_request(&request2), Err(SanitizeError::UnsafePath));
        assert!(sanitize_request(&request3).is_ok());
        assert_eq!(
            sanitize_request(&request4),
            Ok(CriticalRequestComponents { range: None })
        );
        assert_eq!(
            sanitize_request(&request5),
            Err(SanitizeError::RangeNotSatisfiable)
        );
        assert_eq!(
            sanitize_request(&request6),
            Ok(CriticalRequestComponents { range: None })
        );
    }

    #[test]
    fn parse_headers() {
        fn contains(headers: &HeaderMap, name: &str, value: &'static str) -> bool {
            headers.get(name).unwrap() == HeaderValue::from_static(value)
        }

        let headers1 = "\
accept-ranges: bytes\r
access-control-allow-credentials: true\r
access-control-allow-methods: GET, HEAD\r
access-control-allow-origin: https://search.brave.com\r
access-control-max-age: 31536000\r
age: 10138\r
cache-control: public; max-age=31536000; immutable\r
content-length: 7168\r
content-security-policy: sandbox\r
content-type: font/woff2\r
cross-origin-opener-policy: same-origin\r
date: Tue, 27 Jul 2021 14:08:15 GMT\r
etag: \"96c9ae84c0824fd428d14665c9d1980c\"\r
last-modified: Thu, 15 Jul 2021 08:02:39 GMT\r
server: AmazonS3\r
via: 1.1 8cd193739d511303cb3678dc24369a0c.cloudfront.net (CloudFront)\r
x-amz-cf-id: LQlkPpL1NdDw5aPwhTC2HIDjWTi6QQNqU6TsGJpyn9e2UkWFfyIPSA==\r
x-amz-cf-pop: CPH50-C1\r
x-amz-server-side-encryption: AES256\r
x-amz-version-id: gkBvWuHX41LtglHm6kRnswUH2XB9Exxi\r
x-cache: Hit from cloudfront\r
x-content-type-options: nosniff\r
x-frame-options: DENY\r";
        let headers2 = "\
accept-ranges: bytes\r
cache-control: no-store\r
content-encoding: gzip\r
content-type: text/html; charset=utf-8\r
last-modified: Tue, 27 Jul 2021 16:41:42 GMT\r
referrer-policy: no-referrer\r
server: Kvarn/0.2.0 (Linux)\r\n\r\n\
Some data!";

        let h1 = headers(&Bytes::from_static(headers1.as_bytes())).unwrap().0;
        let (h2, h2body) = headers(&Bytes::from_static(headers2.as_bytes())).unwrap();

        assert!(contains(&h1, "age", "10138"));
        assert!(contains(&h1, "content-length", "7168"));
        assert!(contains(
            &h1,
            "etag",
            "\"96c9ae84c0824fd428d14665c9d1980c\""
        ));
        assert!(contains(
            &h1,
            "x-amz-version-id",
            "gkBvWuHX41LtglHm6kRnswUH2XB9Exxi"
        ));

        assert!(contains(&h2, "referrer-policy", "no-referrer"));
        assert!(contains(&h2, "server", "Kvarn/0.2.0 (Linux)"));
        assert_eq!(&headers2[h2body..], "Some data!");
    }

    #[test]
    fn uri_sanitize() {
        let request = Request::get("//etc/passwd").body(()).unwrap();
        let u = request.uri();
        assert!(sanitize_request(&request).is_err());

        assert_eq!(uri(u.path()).unwrap(), "/etc/passwd");
        assert_eq!(uri("index.html"), None);
    }

    #[test]
    fn header_list() {
        let header = "en-GB,en-US;q=0.9,en; q=0.8, sv;q=0.7";
        let mut list = list_header(header).into_iter();
        assert_eq!(
            list.next().unwrap(),
            ValueQualitySet {
                value: "en-GB",
                quality: 1.0
            }
        );
        assert_eq!(
            list.next().unwrap(),
            ValueQualitySet {
                value: "en-US",
                quality: 0.9
            }
        );
        assert_eq!(
            list.next().unwrap(),
            ValueQualitySet {
                value: "en",
                quality: 0.8
            }
        );
        assert_eq!(
            list.next().unwrap(),
            ValueQualitySet {
                value: "sv",
                quality: 0.7
            }
        );
        assert_eq!(list.next(), None);
    }

    #[test]
    fn parse_query() {
        let uri = Uri::from_static(
            "https://banking.icelk.dev/transfer?from=icelk&to=bob&amount=500$&from=alice&to=icelk",
        );
        let query = query(uri.query().unwrap());

        let mut from = query.get_all("from");
        assert_eq!(from.next().unwrap().value(), "icelk");
        assert_eq!(from.next().unwrap().value(), "alice");
        assert_eq!(from.next(), None);

        assert_eq!(
            query.get("amount"),
            Some(&QueryPair {
                name: Cow::Borrowed("amount"),
                value: Cow::Borrowed("500$"),
            })
        );

        assert_eq!(query.get("to"), None);
        assert_eq!(
            query.get_first("to"),
            Some(&QueryPair {
                name: Cow::Borrowed("to"),
                value: Cow::Borrowed("bob")
            })
        );
    }
}

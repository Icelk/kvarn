//! General parsing complying to the HTTP standards.
//!
//! This parses small bits of a HTTP request/response to extract common information.
//! The [`sanitize_request`] exists to check if a request is valid.
//!
//! This is where part of Layer 6 resides. The [`list_header`] and [`query`]
//! are very useful.

use crate::prelude::*;

/// HTTP dates parsing and formatting in the
/// [chrono format](https://docs.rs/chrono/0.4.19/chrono/format/strftime/index.html).
pub const HTTP_DATE: &str = "%a, %d %b %Y %T GMT";

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
    Done,
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
}
impl Error {
    /// Gets a string representation of [`Error`].
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self{
            Self::Http(_) => "http library parsing error",
            Self::NoPath => "no path was supplied in the request",
            Self::Done => "stream is exhausted",
            Self::HeaderTooLong => "header is too long",
            Self::InvalidPath => "path is invalid or contains illegal bytes",
            Self::InvalidMethod => "method is invalid",
            Self::InvalidVersion => "version is invalid",
            Self::InvalidStatusCode => "status code in invalid",
            Self::Syntax => "invalid syntax of data. The input might unexpectedly be encrypted (HTTPS) or compressed (HTTP/2)",
            Self::IllegalName => "header name invalid",
            Self::IllegalValue => "header value invalid",
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
            | Error::IllegalValue => io::Error::new(io::ErrorKind::InvalidData, err.as_str()),
            Error::Done => io::Error::new(io::ErrorKind::BrokenPipe, err.as_str()),
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
/// Parses a query to a map between keys and their values, as specified in the query.
///
/// `query` should not contains the `?`, but start the byte after.
///
/// Both the keys and values can be empty.
///
/// > **Note:** if multiple of the same keys only the last will be present.
#[must_use]
pub fn query(query: &str) -> HashMap<&str, &str> {
    let elements = query
        .chars()
        .fold(1, |acc, byte| if byte == '&' { acc + 1 } else { acc });
    let mut map = HashMap::with_capacity(elements);

    let mut pair_start = 0;
    let mut value_start = 0;
    for (position, byte) in query.char_indices() {
        match byte {
            '=' => {
                value_start = position + 1;
            }
            '&' => {
                let key = query.get(pair_start..value_start);
                let value = query.get(value_start..position);

                if let (Some(key), Some(value)) = (key, value) {
                    map.insert(key, value);
                }

                pair_start = position + 1;
            }
            _ => {}
        }
    }
    {
        let key = query.get(pair_start..value_start - 1);
        let value = query.get(value_start..);

        if let (Some(key), Some(value)) = (key, value) {
            map.insert(key, value);
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
pub fn uri(path: &str) -> Option<&Path> {
    if path.as_bytes().get(0).copied() != Some(chars::FORWARD_SLASH) {
        return None;
    }
    // Unsafe is ok, since we remove the first byte of a string that is always `/`, occupying exactly one byte.
    let stripped_path = unsafe { str::from_utf8_unchecked(&path.as_bytes()[1..]) };

    Some(Path::new(stripped_path))
}
/// Critical components from request to apply to response.
#[must_use]
#[derive(Debug)]
pub struct CriticalRequestComponents {
    range: Option<(usize, usize)>,
}
impl CriticalRequestComponents {
    /// Applies the critical components' info to the `response`.
    ///
    /// For now applies range and replaces the `accept-ranges` header.
    pub async fn apply_to_response(&self, response: &mut Response<Bytes>) {
        if let Some((range_start, mut range_end)) = self.get_range() {
            // Clamp to length
            if range_end >= response.body().len() {
                range_end = response.body().len();
            }

            let len = response.body().len().to_string();
            let start = range_start.to_string();
            let end = (range_end - 1).to_string();
            let bytes = build_bytes!(start.as_bytes(), b"-", end.as_bytes(), b"/", len.as_bytes());

            crate::replace_header(
                response.headers_mut(),
                "content-range",
                // We know integers, b"-", and b"/" are OK!
                HeaderValue::from_maybe_shared(bytes).unwrap(),
            );

            let body = response.body().slice(range_start..range_end);
            *response.body_mut() = body;
            if response.status() == StatusCode::OK {
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            }
        } else if !response.body().is_empty() {
            replace_header_static(response.headers_mut(), "accept-ranges", "bytes")
        }
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
/// See the variants bellow and [`sanitize_request`] for when this happens.
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
    let path_ok = if request.uri().path().contains("./") || !request.uri().path().starts_with('/') {
        false
    } else {
        parse::uri(request.uri().path()).map_or(false, Path::is_relative)
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
        data.range = Some((start, end + 1))
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
    let mut header_name_end = 0;
    let mut header_value_start = 0;
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
                    header_name_end = pos;
                    if bytes.get(pos + 1) != Some(&chars::SPACE) {
                        parse_stage.next();
                        header_value_start = pos + 1;
                    }
                    continue;
                }
                if byte == chars::SPACE {
                    parse_stage.next();
                    header_value_start = pos + 1;
                    continue;
                }
            }
            RequestParseStage::HeaderValue(..) => {
                if byte == chars::LF {
                    let name = HeaderName::from_bytes(&bytes[header_name_start..header_name_end])
                        .ok()
                        .ok_or(Error::IllegalName)?;
                    let value =
                        HeaderValue::from_maybe_shared(bytes.slice(header_value_start..pos - 1))
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

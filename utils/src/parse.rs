use crate::prelude::*;
use chars::*;

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
            start_byte = if header.as_bytes().get(position + 1) == Some(&SPACE) {
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
/// It asserts the first byte is a [`FORWARD_SLASH`] and then chops it off.
///
/// > _Note: you **must** check that the path is safe to read from before using it. See [`sanitize_request`]._
///
/// Will return `None` if `path.is_empty()` or if the first byte isn't a `/`.
#[inline]
#[must_use]
pub fn uri(path: &str) -> Option<&Path> {
    if path.as_bytes().get(0).copied() != Some(FORWARD_SLASH) {
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

pub enum RequestParseStage {
    Method,
    Path,
    Version,
    HeaderName(i32),
    HeaderValue(i32),
}
impl RequestParseStage {
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
        if byte == CR {
            continue;
        }
        if byte == LF {
            lf_in_row += 1;
            if lf_in_row == 2 {
                break;
            }
        } else {
            lf_in_row = 0;
        }
        match parse_stage {
            RequestParseStage::HeaderName(..) => {
                if byte == COLON {
                    header_name_end = pos;
                    if bytes.get(pos + 1) != Some(&SPACE) {
                        parse_stage.next();
                        header_value_start = pos + 1;
                    }
                    continue;
                }
                if byte == SPACE {
                    parse_stage.next();
                    header_value_start = pos + 1;
                    continue;
                }
            }
            RequestParseStage::HeaderValue(..) => {
                if byte == LF {
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

//! General parsing complying to the HTTP standards.
//!
//! Mainly, it can parse [`request`]s, [`headers`], and a [`response_php`];
//! a response without the first line, giving status in the headers.
//!
//! This is also where part of Layer 6 is. The [`list_header`] and [`query`]
//! are very useful.

use crate::prelude::*;
use utils::parse::*;
use time::Duration;

/// HTTP dates parsing and formatting in the
/// [chrono format](https://docs.rs/chrono/0.4.19/chrono/format/strftime/index.html).
pub const HTTP_DATE: &str = "%a, %d %b %Y %T GMT";

/// An error with parsing [`CacheControl`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CacheControlError {
    /// Multiple `max-age` directives were found.
    ///
    /// There must only be one; else you can't decide which to honour.
    MultipleMaxAge,
    /// Could not parse integer in max-age or Kvarn cache control header.
    InvalidInteger,
    /// The unit for the Kvarn cache control header is invalid.
    ///
    /// For now, valid units are
    /// - `s` for seconds
    /// - `m` for minutes
    /// - `h` for hours
    /// - `d` for days
    InvalidUnit,
    /// The Kvarn cache control header is a keyword, but it is invalid.
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
        self.no_store || self.max_age.map_or(false, |age| age <= 60)
    }
    /// Converts [`CacheControl`] to a max lifetime [`Duration`].
    ///
    /// If the returned value is [`None`], you should let it be in the cache for as long as possible,
    /// longer than any with a defined lifetime.
    #[must_use]
    pub fn to_duration(&self) -> Option<Duration> {
        if let (true, Some(max_age)) = (self.store(), self.max_age) {
            Some(Duration::seconds(max_age.into()))
        } else {
            None
        }
    }
}

mod read_head {
    use super::{utils, utils::parse::Error, AsyncRead, AsyncReadExt, Bytes, BytesMut, CR, LF};

    pub(crate) fn contains_two_newlines(bytes: &[u8]) -> bool {
        let mut in_row = 0_u8;
        for byte in bytes.iter().copied() {
            match byte {
                LF if in_row == 0 => in_row += 1,
                LF => return true,
                CR => {}
                _ => in_row = 0,
            }
        }
        false
    }

    pub(crate) async fn read_more(
        buffer: &mut BytesMut,
        mut reader: impl AsyncRead + Unpin,
        read: &mut usize,
        max_len: usize,
    ) -> Result<usize, Error> {
        assert!(buffer.len() == *read);
        if buffer.len() == max_len {
            return Err(Error::HeaderTooLong);
        }

        if buffer.capacity() < buffer.len() + 512 {
            if buffer.len() + 512 > max_len {
                buffer.reserve((buffer.len() + 512) - max_len);
            } else {
                buffer.reserve(512);
            }
        }

        unsafe { buffer.set_len(buffer.capacity()) };
        let read_now = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reader.read(&mut buffer[*read..]),
        )
        .await
        .ok()
        .ok_or(Error::Done)?
        .ok()
        .ok_or(Error::Done)?;
        *read += read_now;
        unsafe { buffer.set_len(*read) };

        Ok(read_now)
    }

    pub(crate) async fn read_headers(
        mut reader: impl AsyncRead + Unpin,
        max_len: usize,
    ) -> Result<Bytes, Error> {
        let mut buffer = BytesMut::with_capacity(1024);
        let mut read = 0;
        let read = &mut read;

        loop {
            if read_more(&mut buffer, &mut reader, read, max_len).await? == 0 {
                break;
            };
            if !(utils::valid_method(&buffer) || utils::valid_version(&buffer)) {
                return Err(Error::Syntax);
            }

            if contains_two_newlines(&buffer) {
                break;
            }
        }
        Ok(buffer.freeze())
    }
}

/// Try to parse a request from `stream`
///
/// # Errors
///
/// Will return error if building the `http::Response` internally failed, if path is empty,
/// or any errors which occurs while reading from `stream`.
///
/// # Limitations
///
/// Request will be cut off at `max_len`.
pub async fn request<R: AsyncRead + Unpin>(
    mut stream: impl std::ops::DerefMut<Target = R>,
    max_len: usize,
    default_host: &[u8],
    scheme: &str,
) -> Result<(Request<()>, Bytes), Error> {
    let buffer = read_head::read_headers(&mut *stream, max_len).await?;

    let mut parse_stage = RequestParseStage::Method;
    // Method is max 7 bytes long
    let mut method = [0; 7];
    let mut method_len = 0;
    let mut path_start = 0;
    let mut path_end = 0;
    // Version is at most 8 bytes long
    let mut version = [0; 8];
    let mut version_index = 0;
    let mut parsed = Request::builder();
    let mut lf_in_row = 0_u8;
    let mut header_end = 0;

    for (pos, byte) in buffer.iter().copied().enumerate() {
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
            RequestParseStage::Method => {
                if byte == SPACE || method_len == method.len() {
                    if Method::from_bytes(&buffer[..method_len]).is_err() {
                        return Err(Error::InvalidMethod);
                    }
                    parse_stage.next();
                    continue;
                }
                if method_len == method.len() {
                    return Err(Error::InvalidMethod);
                }
                method[method_len] = byte;
                method_len += 1;
            }
            RequestParseStage::Path => {
                if path_start == 0 {
                    path_start = pos;
                }
                if byte == SPACE {
                    path_end = pos;
                    parse_stage.next();
                    continue;
                }
            }
            RequestParseStage::Version => {
                if byte == LF || version_index == version.len() {
                    if parse::version(&version[..version_index]).is_none() {
                        return Err(Error::InvalidVersion);
                    }
                    parse_stage.next();
                    continue;
                }
                if version_index == version.len() {
                    return Err(Error::InvalidVersion);
                }
                version[version_index] = byte;
                version_index += 1;
            }
            RequestParseStage::HeaderName(..) | RequestParseStage::HeaderValue(..) => {
                match parsed.headers_mut() {
                    Some(h) => {
                        let (headers, end) = headers(&buffer.slice(header_end - 1..))?;
                        *h = headers;
                        header_end += end;
                    }
                    None => return Err(Error::Syntax),
                }
                break;
            }
        };
    }
    if path_end
        .checked_sub(path_start)
        .map_or(true, |len| len == 0)
    {
        return Err(Error::NoPath);
    }

    let host = parsed
        .headers_ref()
        .and_then(|headers| headers.get(header::HOST).map(HeaderValue::as_bytes))
        .unwrap_or(default_host);

    let uri = {
        let mut uri =
            BytesMut::with_capacity(scheme.len() + 3 + host.len() + (path_end - path_start));

        uri.extend(scheme.as_bytes());
        uri.extend(b"://");
        uri.extend(host);
        uri.extend(&buffer[path_start..path_end]);
        uri.freeze()
    };

    match parsed
        .method(
            Method::from_bytes(&method[..method_len])
                .ok()
                .ok_or(Error::InvalidMethod)?,
        )
        .uri(Uri::from_maybe_shared(uri).ok().ok_or(Error::InvalidPath)?)
        .version(parse::version(&version[..version_index]).ok_or(Error::InvalidVersion)?)
        .body(())
    {
        Err(err) => Err(Error::Http(err)),
        Ok(request) => Ok((request, buffer.slice(header_end - 1..))),
    }
}

/// Parses a HTTP [`Response`] in plain bytes.
///
/// # Errors
///
/// Passes errors from [`headers`] and [`http::response::Builder::body`]
/// Will also return errors similar to [`request`].
pub async fn response(
    mut reader: impl AsyncRead + Unpin,
    max_len: usize,
) -> Result<Response<Bytes>, Error> {
    enum ParseStage {
        Version,
        Code,
        CanonicalReason,
    }

    let bytes = read_head::read_headers(&mut reader, max_len).await?;

    // Version is at most 8 bytes long
    let mut version_bytes = [0; 8];
    let mut version_index = 0;

    // Code is always 3 digits long.
    let mut code = [0; 3];
    let mut code_index = 0;

    let mut stage = ParseStage::Version;

    let mut header_and_body = None;

    for (pos, byte) in bytes.iter().copied().enumerate() {
        match stage {
            ParseStage::Version => {
                if byte == SPACE {
                    stage = ParseStage::Code;
                    continue;
                }
                if version_index == version_bytes.len() {
                    return Err(Error::InvalidVersion);
                }
                version_bytes[version_index] = byte;
                version_index += 1;
            }
            ParseStage::Code => {
                if byte == SPACE {
                    stage = ParseStage::CanonicalReason;
                    continue;
                }
                if code_index == code.len() {
                    return Err(Error::InvalidStatusCode);
                }
                code[code_index] = byte;
                code_index += 1;
            }
            ParseStage::CanonicalReason => {
                if byte == LF {
                    let header_bytes = bytes.slice(pos + 1..);
                    let (headers, body_start) = headers(&header_bytes)?;
                    let body = bytes.slice(pos + 1 + body_start..);
                    header_and_body = Some((headers, body));
                    break;
                }
            }
        }
    }

    match header_and_body {
        Some((headers, body)) => {
            let version = version(&version_bytes[..version_index]).ok_or(Error::InvalidVersion)?;
            let code = StatusCode::from_bytes(&code[..])
                .ok()
                .ok_or(Error::InvalidStatusCode)?;

            let mut builder = Response::builder().version(version).status(code);
            // We know it doesn't have errors.
            *builder.headers_mut().unwrap() = headers;

            builder.body(body).map_err(Error::from)
        }
        None => Err(Error::Syntax),
    }
}

/// Parses a response without the first line, status taken from the headers.
///
/// # Errors
///
/// Passes errors from [`headers`] and [`http::response::Builder::body`]
pub fn response_php(bytes: &Bytes) -> Result<Response<Bytes>, Error> {
    let header_start = 0;

    let (headers, end) = headers(&bytes.slice(header_start..))?;
    let status = headers
        .get("status")
        .and_then(|h| h.as_bytes().get(..3))
        .map(str::from_utf8)
        .and_then(Result::ok)
        .map(str::parse)
        .and_then(Result::ok)
        .unwrap_or(200_u16);
    let end = header_start + end;
    let mut builder = Response::builder().status(status);
    *builder.headers_mut().expect("wrongly built response") = headers;
    builder.body(bytes.slice(end..)).map_err(Error::from)
}

//! General parsing complying to the HTTP standards.
//!
//! Mainly, it can parse [`request`]s, [`headers`], and a [`response_php`];
//! a response without the first line, giving status in the headers.
//!
//! This is also where part of Layer 6 is. The [`list_header`] and [`query`]
//! are very useful.

use crate::prelude::*;

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
// impl PartialEq for ValueQualitySet<'_> {
//     #[inline]
//     fn eq(&self, other: &Self) -> bool {
//         self.value == other.value
//     }
// }
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
        let key = query.get(pair_start..value_start);
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
/// > _Note: you **must** check that the path is safe to read from before using it._
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

enum RequestParseStage {
    Method,
    Path,
    Version,
    HeaderName(i32),
    HeaderValue(i32),
}
impl RequestParseStage {
    #[inline]
    fn next(&mut self) {
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
pub async fn request(
    stream: &Mutex<Encryption>,
    max_len: usize,
    default_host: &[u8],
) -> Result<(Request<()>, Bytes), Error> {
    fn contains_two_newlines(bytes: &[u8]) -> bool {
        let mut in_row = 0_u8;
        for byte in bytes.iter().cloned() {
            match byte {
                LF if in_row == 0 => in_row += 1,
                LF => return true,
                CR => {}
                _ => in_row = 0,
            }
        }
        false
    }

    async fn read_more(
        buffer: &mut BytesMut,
        reader: &Mutex<Encryption>,
        read: &mut usize,
        max_len: usize,
    ) -> Result<usize, Error> {
        assert!(buffer.len() == *read);
        if buffer.len() == max_len {
            return Err(Error::HeaderTooLong);
        }

        let mut reader = reader.lock().await;

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

    let mut buffer = BytesMut::with_capacity(1024);
    let mut read = 0;
    let read = &mut read;

    loop {
        if read_more(&mut buffer, stream, read, max_len).await? == 0 {
            break;
        };
        if !utility::valid_method(&buffer) {
            return Err(Error::Syntax);
        }

        if contains_two_newlines(&buffer) {
            break;
        }
    }
    let buffer = buffer.freeze();

    let mut parse_stage = RequestParseStage::Method;
    // Method is max 7 bytes long
    let mut method = [0; 7];
    let mut method_len = 0;
    let mut path_start = 0;
    let mut path_end = 0;
    // Version is 8 bytes long
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
        let scheme = match &*stream.lock().await {
            Encryption::Tcp(_) => "http",
            #[cfg(feature = "https")]
            Encryption::TcpTls(_) => "https",
        };

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

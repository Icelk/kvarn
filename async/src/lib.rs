//! Async bits for web applications.
//!
//! This includes [reading to bytes](fn.read_to_end.html),
//! a adapter between std's [`Read`] trait and tokio's [`AsyncRead`],
//! a [`mod@write`] module for writing `HTTP/1` requests and responses,
//! and a [`read`] module for reading `HTTP/1` requests and responses.

#![deny(
    unreachable_pub,
    missing_debug_implementations,
    missing_docs,
    clippy::pedantic
)]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

pub mod prelude;

use crate::prelude::*;

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
/// Note that `max_len` is a suggestion and will probably be overran.
///
/// Note that the length of the read bytes can exceed `max_len`; it stops
/// after having read `max_len` or higher.
///
/// # Errors
///
/// Passes any errors emitted from `reader`.
pub async fn read_to_end_or_max(
    buffer: &mut BytesMut,
    mut reader: impl AsyncRead + Unpin,
    max_len: usize,
) -> io::Result<()> {
    fn reserve(read: usize, buffer: &mut BytesMut) {
        let left = buffer.capacity() - read;
        if left < 32 {
            let lower = 1024;
            let additional = buffer
                .capacity()
                .clamp(lower, (buffer.capacity() * 2 / 3).max(lower));
            buffer.reserve((buffer.capacity() - buffer.len()) + additional);
            // This is safe because of the trailing unsafe block.
            unsafe { buffer.set_len(buffer.capacity()) };
        }
    }

    let mut read = buffer.len();

    if read >= max_len {
        return Ok(());
    }

    // This is safe because of the trailing unsafe block.
    unsafe { buffer.set_len(buffer.capacity()) };
    if buffer.capacity() == buffer.len() {
        reserve(0, buffer);
    }
    loop {
        match reader.read(&mut buffer[read..]).await.map_err(|err| {
            // if err, set buffer len to safe value
            unsafe { buffer.set_len(read) };
            err
        })? {
            0 => break,
            len => {
                read += len;
                if read >= max_len {
                    unsafe { buffer.set_len(read) };
                    return Ok(());
                }
                reserve(read, buffer);
            }
        }
    }
    // I have counted the length in `read`. It will *not* include uninitiated bytes.
    unsafe { buffer.set_len(read) };
    Ok(())
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

/// Writes HTTP/1 [`Response`]s and [`Request`]s to a [`AsyncWrite`].
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
            $(
                $writer.write_all($bytes).await?;
            )*
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
/// Reads HTTP/1 [`Request`]s and [`Response`]s from a [`AsyncRead`]er.
///
/// It can also read PHP-esque responses.
pub mod read {
    // use super::{parse::Error, AsyncRead, AsyncReadExt, Bytes, BytesMut, CR, LF};
    use crate::prelude::*;
    use parse::{Error, RequestParseStage};

    pub(crate) fn contains_two_newlines(bytes: &[u8]) -> bool {
        let mut in_row = 0_u8;
        for byte in bytes.iter().copied() {
            match byte {
                chars::LF if in_row == 0 => in_row += 1,
                chars::LF => return true,
                chars::CR => {}
                _ => in_row = 0,
            }
        }
        false
    }

    /// The buffer must not be read if this returns an error.
    #[inline]
    pub(crate) async fn read_more(
        buffer: &mut BytesMut,
        mut reader: impl AsyncRead + Unpin,
        read: &mut usize,
        max_len: usize,
        timeout: std::time::Duration,
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
        let read_now = tokio::time::timeout(timeout, reader.read(&mut buffer[*read..]))
            .await
            .ok()
            .ok_or(Error::UnexpectedEnd)?
            .ok()
            .ok_or(Error::UnexpectedEnd)?;
        *read += read_now;
        unsafe { buffer.set_len(*read) };

        Ok(read_now)
    }

    #[inline]
    pub(crate) async fn read_headers(
        mut reader: impl AsyncRead + Unpin,
        max_len: usize,
        timeout: std::time::Duration,
    ) -> Result<Bytes, Error> {
        let mut buffer = BytesMut::with_capacity(512);
        let mut read = 0;
        let read = &mut read;

        loop {
            if read_more(&mut buffer, &mut reader, read, max_len, timeout).await? == 0 {
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

    /// Try to parse a request from `stream`
    ///
    /// # Errors
    ///
    /// Will return error if building the `http::Response` internally failed, if path is empty,
    /// or any errors which occurs while reading from `stream`.
    /// See [`Error`] for all vairants.
    ///
    /// # Limitations
    ///
    /// Request will be cut off at `max_len`.
    pub async fn request<R: AsyncRead + Unpin>(
        mut stream: impl std::ops::DerefMut<Target = R>,
        max_len: usize,
        default_host: Option<&[u8]>,
        scheme: &str,
        timeout: std::time::Duration,
    ) -> Result<(Request<()>, Bytes), Error> {
        let buffer = read_headers(&mut *stream, max_len, timeout).await?;

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

        *parsed
            .headers_mut()
            .expect("request headers shouldn't have an error: we just created it") =
            HeaderMap::with_capacity(
                buffer
                    .get(..1042)
                    .unwrap_or(&buffer)
                    .windows(2)
                    .filter(|s| s == b"\r\n")
                    .count()
                    .saturating_sub(2)
                    .min(20),
            );

        for (pos, byte) in buffer.iter().copied().enumerate() {
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
                RequestParseStage::Method => {
                    if byte == chars::SPACE || method_len == method.len() {
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
                    if byte == chars::SPACE {
                        path_end = pos;
                        parse_stage.next();
                        continue;
                    }
                }
                RequestParseStage::Version => {
                    if byte == chars::LF || version_index == version.len() {
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
                            let (headers, end) = parse::headers(&buffer.slice(header_end - 1..))?;
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

        let host = if let Some(host) = parsed
            .headers_ref()
            .and_then(|headers| headers.get(header::HOST).map(HeaderValue::as_bytes))
            .or(default_host)
        {
            host
        } else {
            return Err(Error::NoHost);
        };

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
    /// Passes errors from [`http::response::Builder::body`] and internal checks.
    /// See [`Error`] for variants.
    /// Will also return errors similar to [`request`].
    pub async fn response(
        mut reader: impl AsyncRead + Unpin,
        max_len: usize,
        timeout: std::time::Duration,
    ) -> Result<Response<Bytes>, Error> {
        enum ParseStage {
            Version,
            Code,
            CanonicalReason,
        }

        let bytes = read_headers(&mut reader, max_len, timeout).await?;

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
                    if byte == chars::SPACE {
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
                    if byte == chars::SPACE {
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
                    if byte == chars::LF {
                        let header_bytes = bytes.slice(pos + 1..);
                        let (headers, body_start) = parse::headers(&header_bytes)?;
                        let body = bytes.slice(pos + 1 + body_start..);
                        header_and_body = Some((headers, body));
                        break;
                    }
                }
            }
        }

        match header_and_body {
            Some((headers, body)) => {
                let version =
                    parse::version(&version_bytes[..version_index]).ok_or(Error::InvalidVersion)?;
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
    /// Returns virtually the same errors as [`response`].
    pub fn response_php(bytes: &Bytes) -> Result<Response<Bytes>, Error> {
        let header_start = 0;

        let (headers, end) = parse::headers(&bytes.slice(header_start..))?;
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
}

use crate::{encryption::Encryption, prelude::*, HostDescriptor};
use http::{header::HeaderName, HeaderValue, Method, Request, Uri, Version};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[derive(Debug)]
pub enum Error {
    Http(http::Error),
    Io(io::Error),
    H2(h2::Error),
    NoPath,
    Done,
    VersionNotSupported,
    InvalidHost,
    PushOnHttp1,
}
impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Self::Http(err)
    }
}
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<h2::Error> for Error {
    fn from(err: h2::Error) -> Self {
        Self::H2(err)
    }
}
impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Self::Io(io) => io,
            Self::Http(http) => io::Error::new(io::ErrorKind::InvalidData, http),
            Self::H2(h2) => io::Error::new(io::ErrorKind::InvalidData, h2),
            Self::Done => io::Error::new(io::ErrorKind::BrokenPipe, "stream is exhausted"),
            Self::NoPath => io::Error::new(
                io::ErrorKind::InvalidInput,
                "no path was supplied in the request",
            ),
            Self::VersionNotSupported => io::Error::new(
                io::ErrorKind::InvalidInput,
                "http version unsupported. Invalid ALPN config.",
            ),
            Self::InvalidHost => {
                io::Error::new(io::ErrorKind::InvalidData, "host contains illegal bytes")
            }
            Self::PushOnHttp1 => io::Error::new(
                io::ErrorKind::InvalidInput,
                "can not push requests on http/1",
            ),
        }
    }
}

pub enum HttpConnection {
    Http1(Arc<Mutex<Encryption<TcpStream>>>),
    Http2(h2::server::Connection<Encryption<TcpStream>, bytes::Bytes>),
}

pub fn get_host<'a>(
    request: &http::Request<Body>,
    sni_hostname: Option<&str>,
    data: &'a HostData,
) -> &'a Host {
    fn get_header(headers: &http::HeaderMap) -> Option<&str> {
        headers
            .get(http::header::HOST)
            .map(http::HeaderValue::to_str)
            .map(Result::ok)
            .flatten()
    }

    let host = sni_hostname.or_else(|| get_header(request.headers()));

    data.maybe_get_or_default(host)
}

/// ToDo: trailers
#[derive(Debug)]
pub enum Body {
    Empty,
    Http1(response::PreBufferedReader<Encryption<TcpStream>>),
    Http2(h2::RecvStream),
}

pub enum ResponsePipe {
    Http1(Arc<Mutex<Encryption<TcpStream>>>),
    Http2(h2::server::SendResponse<Bytes>),
}
pub enum ResponseBodyPipe {
    Http1(Arc<Mutex<Encryption<TcpStream>>>),
    Http2(h2::SendStream<Bytes>),
}
pub enum PushedResponsePipe {
    Http2(h2::server::SendPushedResponse<Bytes>),
}

impl HttpConnection {
    pub async fn new(stream: Encryption<TcpStream>, version: http::Version) -> Result<Self, Error> {
        match version {
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
                Ok(Self::Http1(Arc::new(Mutex::new(stream))))
            }
            Version::HTTP_2 => match h2::server::handshake(stream).await {
                Ok(connection) => Ok(HttpConnection::Http2(connection)),
                Err(err) => Err(Error::H2(err)),
            },
            Version::HTTP_3 => Err(Error::VersionNotSupported),
            _ => Err(Error::VersionNotSupported),
        }
    }

    pub async fn accept(&mut self) -> Result<(http::Request<Body>, ResponsePipe), Error> {
        match self {
            Self::Http1(stream) => {
                let response = ResponsePipe::Http1(Arc::clone(stream));
                request::parse_http_1(Arc::clone(stream))
                    .await
                    .map(|request| (request, response))
            }
            Self::Http2(connection) => match connection.accept().await {
                Some(connection) => match connection {
                    Ok((request, response)) => Ok((
                        request.map(|s| Body::Http2(s)),
                        ResponsePipe::Http2(response),
                    )),
                    Err(err) => Err(Error::H2(err)),
                },
                None => Err(Error::Done),
            },
        }
    }
}

mod request {
    use super::*;

    pub async fn parse_http_1(
        stream: Arc<Mutex<Encryption<TcpStream>>>,
    ) -> Result<http::Request<Body>, Error> {
        let (head, start, vec) = parse_request(&stream).await?;
        Ok(head.map(|()| Body::Http1(response::PreBufferedReader::new(stream, vec, start))))
    }

    enum DecodeStage {
        Method,
        Path,
        Version,
        HeaderName(i32),
        HeaderValue(i32),
    }
    impl DecodeStage {
        fn next(&mut self) {
            *self = match self {
                DecodeStage::Method => DecodeStage::Path,
                DecodeStage::Path => DecodeStage::Version,
                DecodeStage::Version => DecodeStage::HeaderName(0),
                DecodeStage::HeaderName(n) => DecodeStage::HeaderValue(*n),
                DecodeStage::HeaderValue(n) => DecodeStage::HeaderName(*n + 1),
            }
        }
    }

    /// # Errors
    /// Will return error if building the `http::Response` internally failed, or if path is empty.
    ///
    /// # Limitation
    /// request will be cut off at `crate::BUFFER_SIZE`.
    pub async fn parse_request(
        stream: &Mutex<Encryption<TcpStream>>,
    ) -> Result<(Request<()>, usize, Vec<u8>), Error> {
        let mut buffer = Vec::with_capacity(utility::BUFFER_SIZE);

        let mut parse_stage = DecodeStage::Method;
        // Method is max 7 bytes long
        let mut method = [0; 7];
        let mut method_len = 0;
        let mut path_start = 0;
        let mut path_end = 0;
        // Version is 8 bytes long
        let mut version = [0; 8];
        let mut version_index = 0;
        let mut parsed = Request::builder();
        let mut current_header_name = Vec::with_capacity(16);
        let mut current_header_value = Vec::with_capacity(32);
        let mut lf_in_row = 0_u8;
        let mut header_end = 0;
        unsafe { buffer.set_len(buffer.capacity()) };
        // ToDo: don't read only once, and only have max size with smaller start!
        let read = stream
            .lock()
            .await
            .read(&mut buffer)
            .await
            .map_err(Error::Io)?;
        unsafe { buffer.set_len(read) };

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
                DecodeStage::Method => {
                    if byte == SPACE || method_len == method.len() {
                        parse_stage.next();
                        continue;
                    }
                    method[method_len] = byte;
                    method_len += 1;
                }
                DecodeStage::Path => {
                    if path_start == 0 {
                        path_start = pos;
                    }
                    if byte == SPACE {
                        path_end = pos;
                        parse_stage.next();
                        continue;
                    }
                }
                DecodeStage::Version => {
                    if byte == LF || version_index == version.len() {
                        parse_stage.next();
                        continue;
                    }
                    version[version_index] = byte;
                    version_index += 1;
                }
                DecodeStage::HeaderName(..) => {
                    if byte == COLON {
                        continue;
                    }
                    if byte == SPACE {
                        parse_stage.next();
                        continue;
                    }
                    current_header_name.push(byte);
                }
                DecodeStage::HeaderValue(..) => {
                    if byte == LF {
                        let name = HeaderName::from_bytes(&current_header_name[..]);
                        let value = HeaderValue::from_bytes(&current_header_value[..]);
                        if name.is_ok() && value.is_ok() {
                            // Ok, because of ↑
                            parsed = parsed.header(name.unwrap(), value.unwrap());
                        }
                        current_header_name.clear();
                        current_header_value.clear();
                        parse_stage.next();
                        continue;
                    }
                    current_header_value.push(byte);
                }
            };
        }
        if path_end
            .checked_sub(path_start)
            .map(|len| len == 0)
            .unwrap_or(true)
        {
            return Err(Error::NoPath);
        }

        let host = parsed.headers_ref().and_then(|headers| {
            headers
                .get(http::header::HOST)
                .map(|header| header.as_bytes())
        });

        let uri = match host {
            None => Bytes::copy_from_slice(&buffer[path_start..path_end]),
            Some(host) => {
                let scheme = match &*stream.lock().await {
                    Encryption::None(_) => "http",
                    Encryption::Tls(_) => "https",
                };

                let mut uri = BytesMut::with_capacity(
                    scheme.len() + 3 + host.len() + (path_end - path_start),
                );

                uri.extend(scheme.as_bytes());
                uri.extend(b"://");
                uri.extend(host);
                uri.extend(&buffer[path_start..path_end]);
                uri.freeze()
            }
        };

        match parsed
            .method(Method::from_bytes(&method[..method_len]).unwrap_or(Method::GET))
            .uri(Uri::from_maybe_shared(uri).ok().ok_or(Error::InvalidHost)?)
            .version(match &version[..] {
                b"HTTP/0.9" => Version::HTTP_09,
                b"HTTP/1.0" => Version::HTTP_10,
                b"HTTP/1.1" => Version::HTTP_11,
                b"HTTP/2" => Version::HTTP_2,
                b"HTTP/2.0" => Version::HTTP_2,
                b"HTTP/3" => Version::HTTP_3,
                b"HTTP/3.0" => Version::HTTP_3,
                _ => Version::default(),
            })
            .body(())
        {
            Err(err) => Err(Error::Http(err)),
            Ok(request) => Ok((request, header_end, buffer)),
        }
    }

    impl AsyncRead for Body {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Http1(s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
                Self::Http2(tls) => {
                    let data = match tls.poll_data(cx) {
                        Poll::Ready(data) => data,
                        Poll::Pending => return Poll::Pending,
                    };
                    match data {
                        Some(d) => match d {
                            Ok(data) => buf.put_slice(&data),
                            Err(err) => {
                                let err = io::Error::new(io::ErrorKind::InvalidData, err);
                                return Poll::Ready(Err(err));
                            }
                        },
                        None => return Poll::Ready(Ok(())),
                    }
                    Poll::Ready(Ok(()))
                }
                Self::Empty => Poll::Ready(Ok(())),
            }
        }
    }
}

mod response {
    use tokio::io::AsyncWriteExt;

    use super::*;

    pub struct PreBufferedReader<R: AsyncRead + Unpin> {
        reader: Arc<Mutex<R>>,
        buffer: Vec<u8>,
        offset: usize,
    }
    impl<R: AsyncRead + Unpin + Debug> Debug for PreBufferedReader<R> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "PreBufferedReader {{ reader: {:?}, buffer: [internal buffer], offset: {:?} }}",
                self.reader, self.offset
            )
        }
    }
    impl<R: AsyncRead + Unpin> PreBufferedReader<R> {
        pub fn new(reader: Arc<Mutex<R>>, buffer: Vec<u8>, start: usize) -> Self {
            Self {
                reader,
                buffer,
                offset: start,
            }
        }
    }
    impl<R: AsyncRead + Unpin> AsyncRead for PreBufferedReader<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let me = self.get_mut();
            if me.offset < me.buffer.len() {
                buf.put_slice(&me.buffer[me.offset..]);
                me.offset = me.buffer.len();
                Poll::Ready(Ok(()))
            } else {
                let mut reader = match me.reader.try_lock() {
                    Err(_) => return Poll::Pending,
                    Ok(r) => r,
                };
                unsafe { Pin::new_unchecked(&mut *reader).poll_read(cx, buf) }
            }
        }
    }

    impl ResponsePipe {
        /// It is critical to call [`AsyncWriteExt::flush()`] on [`ResponseBodyPipe`], else the message won't be seen as fully transmitted.
        pub async fn send_response(
            &mut self,
            mut response: http::Response<()>,
            end_of_stream: bool,
        ) -> Result<ResponseBodyPipe, Error> {
            match self {
                Self::Http1(s) => {
                    let mut writer = s.lock().await;
                    match response.version() {
                        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {}
                        _ => *response.version_mut() = Version::HTTP_11,
                    }
                    utility::replace_header_static(
                        response.headers_mut(),
                        "connection",
                        "keep-alive",
                    );
                    write_http_1_response(&mut *writer, response)
                        .await
                        .map_err(Error::Io)?;
                    Ok(ResponseBodyPipe::Http1(Arc::clone(s)))
                }
                Self::Http2(s) => {
                    *response.version_mut() = Version::HTTP_2;

                    match s.send_response(response, end_of_stream) {
                        Err(err) => Err(Error::H2(err)),
                        Ok(pipe) => Ok(ResponseBodyPipe::Http2(pipe)),
                    }
                }
            }
        }
        pub fn push_request(
            &mut self,
            request: http::Request<()>,
        ) -> Result<PushedResponsePipe, Error> {
            match self {
                Self::Http1(_) => Err(Error::PushOnHttp1),
                Self::Http2(h2) => match h2.push_request(request) {
                    Ok(pipe) => Ok(PushedResponsePipe::Http2(pipe)),
                    Err(err) => Err(Error::H2(err)),
                },
            }
        }
    }
    impl PushedResponsePipe {
        pub fn send_response(
            &mut self,
            mut response: http::Response<()>,
            end_of_stream: bool,
        ) -> Result<ResponseBodyPipe, Error> {
            match self {
                Self::Http2(s) => {
                    *response.version_mut() = Version::HTTP_2;

                    match s.send_response(response, end_of_stream) {
                        Err(err) => Err(Error::H2(err)),
                        Ok(pipe) => Ok(ResponseBodyPipe::Http2(pipe)),
                    }
                }
            }
        }
    }

    /// Writer **must** be buffered!
    pub async fn write_http_1_response<W: AsyncWrite + Unpin>(
        mut writer: W,
        response: http::Response<()>,
    ) -> io::Result<()> {
        let version = match response.version() {
            Version::HTTP_09 => &b"HTTP/0.9"[..],
            Version::HTTP_10 => &b"HTTP/1.0"[..],
            Version::HTTP_2 => &b"HTTP/2"[..],
            Version::HTTP_3 => &b"HTTP/3"[..],
            _ => &b"HTTP/1.1"[..],
        };
        let status = response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .as_bytes();

        writer.write_all(version).await?;
        writer.write_all(b" ").await?;
        writer
            .write_all(response.status().as_str().as_bytes())
            .await?;
        writer.write_all(status).await?;
        writer.write_all(b"\r\n").await?;

        for (name, value) in response.headers() {
            writer.write_all(name.as_str().as_bytes()).await?;
            writer.write_all(b": ").await?;
            writer.write_all(value.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
        }
        writer.write_all(b"\r\n").await
    }
    impl ResponseBodyPipe {
        pub async fn send(&mut self, data: Bytes, end_of_stream: bool) -> Result<(), Error> {
            match self {
                Self::Http1(h1) => {
                    let mut lock = h1.lock().await;
                    lock.write_all(&data).await?;
                    if end_of_stream {
                        lock.flush().await?;
                    }
                }
                Self::Http2(h2) => h2.send_data(data, end_of_stream)?,
            }
            Ok(())
        }
        pub async fn close(&mut self) -> Result<(), Error> {
            match self {
                Self::Http1(h1) => h1.lock().await.flush().await.map_err(Error::from),
                Self::Http2(h2) => h2.send_data(Bytes::new(), true).map_err(Error::from),
            }
        }
    }
}

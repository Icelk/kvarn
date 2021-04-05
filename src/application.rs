use crate::prelude::{internals::*, *};

#[derive(Debug)]
pub enum Error {
    Http(http::Error),
    Io(io::Error),
    H2(h2::Error),
    NoPath,
    Done,
    VersionNotSupported,
    PushOnHttp1,
    InvalidHost,
    InvalidVersion,
    InvalidMethod,
    HeaderTooLong,
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
            Self::PushOnHttp1 => io::Error::new(
                io::ErrorKind::InvalidInput,
                "can not push requests on http/1",
            ),
            Self::InvalidHost => {
                io::Error::new(io::ErrorKind::InvalidData, "host contains illegal bytes")
            }
            Self::InvalidVersion => {
                io::Error::new(io::ErrorKind::InvalidData, "version is invalid")
            }
            Self::InvalidMethod => io::Error::new(io::ErrorKind::InvalidData, "method is invalid"),
            Self::HeaderTooLong => io::Error::new(io::ErrorKind::InvalidData, "header is too long"),
        }
    }
}

pub enum HttpConnection {
    Http1(Arc<Mutex<Encryption>>),
    Http2(h2::server::Connection<Encryption, bytes::Bytes>),
}

/// ToDo: trailers
#[derive(Debug)]
pub enum Body {
    Empty,
    Http1(response::PreBufferedReader<Encryption>),
    Http2(h2::RecvStream),
}

pub enum ResponsePipe {
    Http1(Arc<Mutex<Encryption>>),
    Http2(h2::server::SendResponse<Bytes>),
}
pub enum ResponseBodyPipe {
    Http1(Arc<Mutex<Encryption>>),
    Http2(h2::SendStream<Bytes>),
}
pub enum PushedResponsePipe {
    Http2(h2::server::SendPushedResponse<Bytes>),
}

impl HttpConnection {
    pub async fn new(stream: Encryption, version: Version) -> Result<Self, Error> {
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

    pub async fn accept(
        &mut self,
        default_host: &[u8],
    ) -> Result<(Request<Body>, ResponsePipe), Error> {
        match self {
            Self::Http1(stream) => {
                let response = ResponsePipe::Http1(Arc::clone(stream));
                request::parse_http_1(Arc::clone(stream), 16 * 1024, default_host)
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
        stream: Arc<Mutex<Encryption>>,
        max_len: usize,
        default_host: &[u8],
    ) -> Result<Request<Body>, Error> {
        let (head, bytes) = parse::request(&stream, max_len, default_host).await?;
        Ok(head.map(|()| Body::Http1(response::PreBufferedReader::new(stream, bytes))))
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
        bytes: Bytes,
        offset: usize,
    }
    impl<R: AsyncRead + Unpin + Debug> Debug for PreBufferedReader<R> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "PreBufferedReader {{ reader: {:?}, buffer: [internal buffer], offset: {:?} }}",
                self.reader, self.offset
            )
        }
    }
    impl<R: AsyncRead + Unpin> PreBufferedReader<R> {
        pub fn new(reader: Arc<Mutex<R>>, bytes: Bytes) -> Self {
            Self {
                reader,
                bytes,
                offset: 0,
            }
        }
    }
    impl<R: AsyncRead + Unpin> AsyncRead for PreBufferedReader<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset < self.bytes.len() {
                let remaining = buf.remaining();
                if self.bytes.len() - self.offset > remaining {
                    buf.put_slice(&self.bytes[self.offset..self.offset + remaining]);
                    self.offset += remaining;
                } else {
                    buf.put_slice(&self.bytes[self.offset..]);
                    self.offset = self.bytes.len();
                }
                Poll::Ready(Ok(()))
            } else {
                let mut reader = match self.reader.try_lock() {
                    Err(_) => return Poll::Pending,
                    Ok(r) => r,
                };
                unsafe { Pin::new_unchecked(&mut *reader).poll_read(cx, buf) }
            }
        }
    }

    impl ResponsePipe {
        /// You must ensure the [`Response::version()`] is correct before calling this function. It can be guaranteed by first calling [`Self::ensure_version()`]
        /// It is critical to call [`AsyncWriteExt::flush()`] on [`ResponseBodyPipe`], else the message won't be seen as fully transmitted.
        pub async fn send_response(
            &mut self,
            mut response: Response<()>,
            end_of_stream: bool,
        ) -> Result<ResponseBodyPipe, Error> {
            match self {
                Self::Http1(s) => {
                    let mut writer = s.lock().await;
                    utility::replace_header_static(
                        response.headers_mut(),
                        "connection",
                        "keep-alive",
                    );
                    let mut writer = tokio::io::BufWriter::with_capacity(512, &mut *writer);
                    write_http_1_response(&mut writer, response)
                        .await
                        .map_err(Error::Io)?;
                    writer.flush().await.map_err(Error::Io)?;

                    Ok(ResponseBodyPipe::Http1(Arc::clone(s)))
                }
                Self::Http2(s) => match s.send_response(response, end_of_stream) {
                    Err(err) => Err(Error::H2(err)),
                    Ok(pipe) => Ok(ResponseBodyPipe::Http2(pipe)),
                },
            }
        }
        pub fn push_request(&mut self, request: Request<()>) -> Result<PushedResponsePipe, Error> {
            match self {
                Self::Http1(_) => Err(Error::PushOnHttp1),
                Self::Http2(h2) => match h2.push_request(request) {
                    Ok(pipe) => Ok(PushedResponsePipe::Http2(pipe)),
                    Err(err) => Err(Error::H2(err)),
                },
            }
        }
        pub fn ensure_version<T>(&self, response: &mut Response<T>) {
            match self {
                Self::Http1(_) => match response.version() {
                    Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {}
                    _ => *response.version_mut() = Version::HTTP_11,
                },
                Self::Http2(_) => *response.version_mut() = Version::HTTP_2,
            }
        }
    }
    impl PushedResponsePipe {
        pub fn send_response(
            &mut self,
            mut response: Response<()>,
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
        pub fn ensure_version<T>(&self, response: &mut Response<T>) {
            match self {
                Self::Http2(_) => *response.version_mut() = Version::HTTP_2,
            }
        }
    }

    /// Writer **must** be buffered!
    pub async fn write_http_1_response<W: AsyncWrite + Unpin>(
        mut writer: W,
        response: Response<()>,
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

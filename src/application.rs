use crate::prelude::{internals::*, *};

#[derive(Debug)]
pub enum Error {
    Http(http::Error),
    Io(io::Error),
    #[cfg(feature = "h2")]
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
    #[inline]
    fn from(err: http::Error) -> Self {
        Self::Http(err)
    }
}
impl From<io::Error> for Error {
    #[inline]
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
#[cfg(feature = "h2")]
impl From<h2::Error> for Error {
    #[inline]
    fn from(err: h2::Error) -> Self {
        Self::H2(err)
    }
}
impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Self::Io(io) => io,
            Self::Http(http) => io::Error::new(io::ErrorKind::InvalidData, http),
            #[cfg(feature = "h2")]
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
    #[cfg(feature = "h2")]
    Http2(Box<h2::server::Connection<Encryption, bytes::Bytes>>),
}

/// `ToDo`: trailers
#[derive(Debug)]
pub enum Body {
    Empty,
    Http1(response::Http1Body<Encryption>),
    #[cfg(feature = "h2")]
    Http2(h2::RecvStream),
}

#[must_use]
pub enum ResponsePipe {
    Http1(Arc<Mutex<Encryption>>),
    #[cfg(feature = "h2")]
    Http2(h2::server::SendResponse<Bytes>),
}
pub enum ResponseBodyPipe {
    Http1(Arc<Mutex<Encryption>>),
    #[cfg(feature = "h2")]
    Http2(h2::SendStream<Bytes>),
}
#[must_use]
pub enum PushedResponsePipe {
    #[cfg(feature = "h2")]
    Http2(h2::server::SendPushedResponse<Bytes>),
}

impl HttpConnection {
    /// Creates a new [`HttpConnection`] from an [`Encryption`] stream.
    ///
    ///
    /// # Errors
    ///
    /// Returns [`Error::VersionNotSupported`] when a unsupported version is passed.
    ///
    /// Also passes errors from [`h2::server::handshake`].
    pub async fn new(stream: Encryption, version: Version) -> Result<Self, Error> {
        match version {
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
                Ok(Self::Http1(Arc::new(Mutex::new(stream))))
            }
            #[cfg(feature = "h2")]
            Version::HTTP_2 => match h2::server::handshake(stream).await {
                Ok(connection) => Ok(HttpConnection::Http2(Box::new(connection))),
                Err(err) => Err(Error::H2(err)),
            },
            #[cfg(not(feature = "h2"))]
            Version::HTTP_2 => Err(Error::VersionNotSupported),
            _ => Err(Error::VersionNotSupported),
        }
    }

    /// Accept a single request.
    /// `default_host` will be used if the `Host` header is not
    /// present on a HTTP/1.x request.
    ///
    ///
    /// # Errors
    ///
    /// Returns any errors emitted from [`h2::server::Connection::accept()`].
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
            #[cfg(feature = "h2")]
            Self::Http2(connection) => match connection.accept().await {
                Some(connection) => match connection {
                    Ok((request, response)) => {
                        Ok((request.map(Body::Http2), ResponsePipe::Http2(response)))
                    }
                    Err(err) => Err(Error::H2(err)),
                },
                None => Err(Error::Done),
            },
        }
    }
}

pub mod request {
    use super::{
        io, parse, response, utility, Arc, AsyncRead, Body, Bytes, Context, Encryption, Error,
        Mutex, Pin, Poll, ReadBuf, Request,
    };

    #[inline]
    pub(crate) async fn parse_http_1(
        stream: Arc<Mutex<Encryption>>,
        max_len: usize,
        default_host: &[u8],
    ) -> Result<Request<Body>, Error> {
        let (head, bytes) = parse::request(&stream, max_len, default_host).await?;
        let body = Body::Http1(response::Http1Body::new(
            stream,
            bytes,
            utility::get_content_length(&head),
        ));
        Ok(head.map(|()| body))
    }

    impl Body {
        /// Reads all bytes from [`Body`] to a [`Bytes`].
        ///
        ///
        /// # Errors
        ///
        /// Passes any errors returned from the inner reader.
        /// See [`response::Http1Body::read_to_bytes()`] and [`h2::RecvStream::poll_data()`] for more info.
        #[inline]
        pub async fn read_to_bytes(&mut self) -> io::Result<Bytes> {
            match self {
                Self::Empty => Ok(Bytes::new()),
                Self::Http1(h1) => h1.read_to_bytes().await,
                #[cfg(feature = "h2")]
                Self::Http2(h2) => futures::future::poll_fn(|cx| h2.poll_data(cx))
                    .await
                    .unwrap_or_else(|| Ok(Bytes::new()))
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
            }
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
                #[cfg(feature = "h2")]
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

pub mod response {
    use tokio::io::AsyncWriteExt;

    use super::{
        fmt, io, timeout, utility, Arc, AsyncRead, AsyncWrite, Bytes, BytesMut, Context, Debug,
        Duration, Error, Formatter, Method, Mutex, Pin, Poll, PushedResponsePipe, ReadBuf, Request,
        Response, ResponseBodyPipe, ResponsePipe, Version,
    };

    #[must_use]
    pub struct Http1Body<R: AsyncRead + Unpin> {
        reader: Arc<Mutex<R>>,
        bytes: Bytes,
        offset: usize,

        content_length: usize,
    }
    impl<R: AsyncRead + Unpin> Http1Body<R> {
        #[inline]
        pub fn new(reader: Arc<Mutex<R>>, bytes: Bytes, content_length: usize) -> Self {
            Self {
                reader,
                bytes,
                offset: 0,

                content_length,
            }
        }
        /// Reads all bytes from `self` to a [`Bytes`].
        ///
        ///
        /// # Errors
        ///
        /// Returns any errors from the underlying reader.
        #[inline]
        pub async fn read_to_bytes(&mut self) -> io::Result<Bytes> {
            let mut buffer = BytesMut::with_capacity(self.bytes.len() + 512);
            buffer.extend(&self.bytes);
            let _ = timeout(
                Duration::from_millis(250),
                utility::read_to_end(&mut buffer, &mut *self),
            )
            .await;
            Ok(buffer.freeze())
        }
    }
    impl<R: AsyncRead + Unpin + Debug> Debug for Http1Body<R> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("Http1Body")
                .field("reader", &self.reader)
                .field("buffer", &utility::CleanDebug::new("[internal buffer]"))
                .field("offset", &self.offset)
                .field("content_length", &self.content_length)
                .finish()
        }
    }
    impl<R: AsyncRead + Unpin> AsyncRead for Http1Body<R> {
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
                Poll::Pending
            } else {
                let mut reader = match self.reader.try_lock() {
                    Err(_) => return Poll::Pending,
                    Ok(r) => r,
                };
                let size = buf.filled().len();
                let result = unsafe { Pin::new_unchecked(&mut *reader).poll_read(cx, buf) };
                drop(reader);
                let difference = buf.filled().len() - size;
                self.offset += difference;
                if self.offset == self.content_length {
                    return Poll::Ready(Ok(()));
                }
                result
            }
        }
    }

    impl ResponsePipe {
        /// You must ensure the [`Response::version()`] is correct before calling this function.
        /// It can be guaranteed by first calling [`Self::ensure_version_and_length()`].
        ///
        /// It is critical to [`ResponseBodyPipe::close()`], else the message won't be seen as fully transmitted.
        ///
        ///
        /// # Errors
        ///
        /// Passes any errors from writing to the stream. see [`AsyncWriteExt::write()`] and
        /// [`h2::server::SendResponse::send_response()`] for more info.
        #[inline]
        pub async fn send_response(
            &mut self,
            mut response: Response<()>,
            #[allow(unused_variables)] end_of_stream: bool,
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
                        .map_err(Error::Io)
                        .unwrap();
                    writer.flush().await.map_err(Error::Io).unwrap();
                    writer.into_inner();

                    Ok(ResponseBodyPipe::Http1(Arc::clone(s)))
                }
                #[cfg(feature = "h2")]
                Self::Http2(s) => match s.send_response(response, end_of_stream) {
                    Err(err) => Err(Error::H2(err)),
                    Ok(pipe) => Ok(ResponseBodyPipe::Http2(pipe)),
                },
            }
        }
        /// Pushes `request` to client.
        ///
        ///
        /// # Errors
        ///
        /// If you try to push if `self` is [`ResponsePipe::Http1`], an [`Error::PushOnHttp1`] is returned.
        /// Returns errors from [`h2::server::SendResponse::push_request()`].
        #[inline]
        pub fn push_request(
            &mut self,
            #[allow(unused_variables)] request: Request<()>,
        ) -> Result<PushedResponsePipe, Error> {
            match self {
                Self::Http1(_) => Err(Error::PushOnHttp1),
                #[cfg(feature = "h2")]
                Self::Http2(h2) => match h2.push_request(request) {
                    Ok(pipe) => Ok(PushedResponsePipe::Http2(pipe)),
                    Err(err) => Err(Error::H2(err)),
                },
            }
        }
        #[inline]
        pub fn ensure_version_and_length<T>(
            &self,
            response: &mut Response<T>,
            len: usize,
            method: &Method,
        ) {
            match self {
                Self::Http1(_) => match response.version() {
                    Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
                        if utility::method_has_response_body(method) =>
                    {
                        utility::set_content_length(response.headers_mut(), len);
                    }
                    _ => *response.version_mut() = Version::HTTP_11,
                },
                #[cfg(feature = "h2")]
                Self::Http2(_) => *response.version_mut() = Version::HTTP_2,
            }
        }
    }
    #[allow(unused_variables)]
    impl PushedResponsePipe {
        /// Sends a single push response.
        ///
        ///
        /// # Errors
        ///
        /// Errors are passed from the HTTP libraries, for now only [`mod@h2`].
        /// See [`h2::server::SendPushedResponse::send_response()`] for more information.
        #[inline]
        pub fn send_response(
            &mut self,
            response: Response<()>,
            end_of_stream: bool,
        ) -> Result<ResponseBodyPipe, Error> {
            match self {
                #[cfg(feature = "h2")]
                Self::Http2(s) => {
                    let mut response = response;
                    *response.version_mut() = Version::HTTP_2;

                    match s.send_response(response, end_of_stream) {
                        Err(err) => Err(Error::H2(err)),
                        Ok(pipe) => Ok(ResponseBodyPipe::Http2(pipe)),
                    }
                }
                #[cfg(not(any(feature = "h2")))]
                _ => unreachable!(),
            }
        }
        /// Ensures the version of `response` depending on inner version if [`PushedResponsePipe`].
        #[inline]
        #[allow(unused_variables)]
        pub fn ensure_version<T>(&self, response: &mut Response<T>) {
            match self {
                #[cfg(feature = "h2")]
                Self::Http2(_) => *response.version_mut() = Version::HTTP_2,
                #[cfg(not(any(feature = "h2")))]
                _ => unreachable!(),
            }
        }
    }

    /// Writer should be buffered.
    ///
    ///
    /// # Errors
    ///
    /// Will pass any errors emitted from `writer`.
    pub(crate) async fn write_http_1_response<W: AsyncWrite + Unpin>(
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
        writer.write_all(b" ").await?;
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
        /// Sends `data` as the body.
        ///
        ///
        /// # Errors
        ///
        /// Passes any errors from writing to the stream.
        /// See [`AsyncWriteExt::write_all()`] and [`h2::SendStream::send_data()`].
        #[inline]
        pub async fn send(&mut self, data: Bytes, end_of_stream: bool) -> Result<(), Error> {
            match self {
                Self::Http1(h1) => {
                    let mut lock = h1.lock().await;
                    lock.write_all(&data).await?;
                    if end_of_stream {
                        lock.flush().await?;
                    }
                }
                #[cfg(feature = "h2")]
                Self::Http2(h2) => h2.send_data(data, end_of_stream)?,
            }
            Ok(())
        }
        /// Closes the pipe.
        ///
        ///
        /// # Errors
        ///
        /// Passes any errors emitted when closing the writer.
        /// See [`AsyncWriteExt::flush()`] and [`h2::SendStream::send_data()`].
        #[inline]
        pub async fn close(&mut self) -> Result<(), Error> {
            match self {
                Self::Http1(h1) => h1.lock().await.flush().await.map_err(Error::from),
                #[cfg(feature = "h2")]
                Self::Http2(h2) => h2.send_data(Bytes::new(), true).map_err(Error::from),
            }
        }
    }
}

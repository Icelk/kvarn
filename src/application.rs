//! Abstractions for the [application layer](https://en.wikipedia.org/wiki/Application_layer),
//! providing a common interface for all HTTP versions supported.
//!
//! > **You should not have to interface with this module. Use [`handle_connection`] instead.**
//!
//! The main types are [`HttpConnection`], representing a single encrypted generic http connection.
//!
//! When accepting on the [`HttpConnection`], you get a [`FatRequest`]; a [`http::Request`] with a [`Body`].
//! The [`Body`] is a stream providing the body of the request if you need it, to avoid unnecessary allocations.

use crate::prelude::{internals::*, *};
pub use response::Http1Body;

#[cfg(all(feature = "uring", not(feature = "async-networking")))]
compile_error!("You must enable the 'async-networking' feature to use uring.");
#[cfg(all(feature = "http3", not(feature = "async-networking")))]
compile_error!("You must enable the 'async-networking' feature to use HTTP/3.");

#[cfg(feature = "uring")]
pub use uring_tokio_compat::TcpStreamAsyncWrapper;

/// General error for application-level logic.
///
/// Mostly, the [`Error::Parse`], [`Error::Io`], and [`Error::H2`]
/// signal errors with the request emitted from respective library.
#[derive(Debug)]
pub enum Error {
    /// A parse error from the module [`parse`].
    Parse(utils::parse::Error),
    /// An input-output error was encountered while reading or writing.
    Io(io::Error),
    /// [`h2`] emitted an error
    #[cfg(feature = "http2")]
    H2(h2::Error),
    /// [`h3`] emitted an error
    #[cfg(feature = "http3")]
    H3(h3::Error),
    /// The HTTP version assumed by the client is not supported.
    /// Invalid ALPN config is a candidate.
    VersionNotSupported,
    /// You tried to push a response on a HTTP/1 (or HTTP/3, for now) connection.
    ///
    /// *Use HTTP/2 instead, or check if the [`ResponsePipe`] is HTTP/1*.
    /// Will also fail if you try to push on a pipe returned from a previous push.
    UnsupportedPush,
    /// Client closed connection before the response could be sent.
    ClientRefusedResponse,
}
impl From<utils::parse::Error> for Error {
    #[inline]
    fn from(err: utils::parse::Error) -> Self {
        Self::Parse(err)
    }
}
impl From<io::Error> for Error {
    #[inline]
    fn from(err: io::Error) -> Self {
        if let io::ErrorKind::BrokenPipe = err.kind() {
            return Self::ClientRefusedResponse;
        }
        Self::Io(err)
    }
}
#[cfg(feature = "http2")]
impl From<h2::Error> for Error {
    #[inline]
    fn from(err: h2::Error) -> Self {
        if !err.is_io() && err.reason().is_none() {
            return Self::ClientRefusedResponse;
        }
        Self::H2(err)
    }
}
#[cfg(feature = "http3")]
impl From<h3::Error> for Error {
    #[inline]
    fn from(err: h3::Error) -> Self {
        Self::H3(err)
    }
}
impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::Parse(err) => err.into(),
            Error::Io(io) => io,
            #[cfg(feature = "http2")]
            Error::H2(h2) => io::Error::new(io::ErrorKind::InvalidData, h2),
            #[cfg(feature = "http3")]
            Error::H3(h3) => io::Error::new(io::ErrorKind::InvalidData, h3),

            Error::VersionNotSupported => io::Error::new(
                io::ErrorKind::InvalidData,
                "http version unsupported. Invalid ALPN config.",
            ),
            Error::UnsupportedPush => io::Error::new(
                io::ErrorKind::InvalidInput,
                "can not push requests on http/1",
            ),
            Error::ClientRefusedResponse => {
                io::Error::new(io::ErrorKind::ConnectionReset, "client refused response")
            }
        }
    }
}

/// A single HTTP connection.
///
/// See [`HttpConnection::new`] on how to make one and
/// [`HttpConnection::accept`] on getting a [`FatRequest`].
#[must_use]
pub enum HttpConnection {
    /// An HTTP/1 connection
    Http1(Arc<Mutex<Encryption>>),
    /// An HTTP/2 connection
    ///
    /// This is boxed because a [`h2::server::Connection`] takes up
    /// over 1000 bytes of memory, and an [`Arc`] 8 bytes.
    /// It will increase performance on servers with both HTTP/1 and HTTP/2
    /// connections, but slightly hurt exclusively HTTP/2 servers.
    ///
    /// We'll see how we move forward once HTTP/3 support lands.
    #[cfg(feature = "http2")]
    Http2(Box<h2::server::Connection<Encryption, bytes::Bytes>>),
    #[cfg(feature = "http3")]
    /// An HTTP/3 conenction.
    Http3(h3::server::Connection<h3_quinn::Connection, bytes::Bytes>),
}
impl Debug for HttpConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http1(arg0) => f.debug_tuple("Http1").field(arg0).finish(),
            #[cfg(feature = "http2")]
            Self::Http2(arg0) => f.debug_tuple("Http2").field(arg0).finish(),
            #[cfg(feature = "http3")]
            Self::Http3(_) => f
                .debug_tuple("Http3")
                .field(&"[internal h3 connection]".as_clean())
                .finish(),
        }
    }
}

/// The data for [`Body::Bytes`].
#[derive(Debug)]
#[must_use]
pub struct ByteBody {
    content: Bytes,
    read: usize,
}
impl ByteBody {
    /// Read the rest of the bytes of this body
    pub fn read_rest(&mut self) -> Bytes {
        let b = self.content.slice(self.read..);
        self.read = self.content.len();
        b
    }
    /// Read `n` bytes of this body
    pub fn read_n(&mut self, n: usize) -> Bytes {
        let n = n.min(self.content.len() - self.read);
        let b = self.content.slice(self.read..(self.read + n));
        self.read += n;
        b
    }
}
impl From<Bytes> for ByteBody {
    fn from(b: Bytes) -> Self {
        Self {
            content: b,
            read: 0,
        }
    }
}

/// A body of a [`Request`].
///
/// The inner variables are streams. To get the bytes, use [`Body::read_to_bytes()`] when needed.
///
/// Also see [`FatRequest`].
pub enum Body {
    /// A body of [`Bytes`].
    ///
    /// Can be used by HTTP/2 push to simulate a GET request,
    /// or any other extensions which wants a Kvarn response.
    Bytes(ByteBody),
    /// A buffered HTTP/1 body.
    ///
    /// While the HTTP/1 headers were read, it reads too much
    /// and some of the body will be read.
    /// Therefore, the already read bytes are stored.
    /// [`Body::read_to_bytes`] leverages this and just
    /// continues writing to the buffer.
    Http1(response::Http1Body<Encryption>),
    /// An HTTP/2 body provided by [`h2`].
    #[cfg(feature = "http2")]
    Http2(h2::RecvStream),
    /// An HTTP/3 body provided by [`h3`].
    #[cfg(feature = "http3")]
    Http3(h3::server::RequestStream<h3_quinn::RecvStream, Bytes>),
}
impl Debug for Body {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(arg0) => f.debug_tuple("Bytes").field(arg0).finish(),
            Self::Http1(arg0) => f.debug_tuple("Http1").field(arg0).finish(),
            #[cfg(feature = "http2")]
            Self::Http2(arg0) => f.debug_tuple("Http2").field(arg0).finish(),
            #[cfg(feature = "http3")]
            Self::Http3(_) => f
                .debug_tuple("Http3")
                .field(&"[internal h3 connection]".as_clean())
                .finish(),
        }
    }
}

/// A pipe to send a [`Response`] through.
///
/// You may also push requests if the pipe is [`ResponsePipe::Http2`]
/// by calling [`ResponseBodyPipe::push_request`]. after you call [`ResponsePipe::send_response`].
#[must_use]
pub enum ResponsePipe {
    /// An HTTP/1 stream to send a response.
    Http1(Arc<Mutex<Encryption>>),
    /// An HTTP/2 response pipe.
    #[cfg(feature = "http2")]
    Http2(h2::server::SendResponse<Bytes>),
    /// An HTTP/3 response pipe.
    #[cfg(feature = "http3")]
    Http3(h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>),
}
impl Debug for ResponsePipe {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http1(arg0) => f.debug_tuple("Http1").field(arg0).finish(),
            #[cfg(feature = "http2")]
            Self::Http2(arg0) => f.debug_tuple("Http2").field(arg0).finish(),
            #[cfg(feature = "http3")]
            Self::Http3(_) => f
                .debug_tuple("Http3")
                .field(&"[internal h3 connection]".as_clean())
                .finish(),
        }
    }
}
/// Abstraction layer over different kinds of HTTP/2 response senders.
#[derive(Debug)]
#[cfg(feature = "http2")]
pub enum H2SendResponse {
    /// The initial response
    Initial(h2::server::SendResponse<Bytes>),
    /// Server-pushed responses
    Pushed(h2::server::SendPushedResponse<Bytes>),
}
/// A pipe to send a body after the [`Response`] is sent by
/// [`ResponsePipe::send_response`].
///
/// The [`AsyncWriteExt::shutdown`] does nothing, and will immediately return with Ok(())
pub enum ResponseBodyPipe {
    /// HTTP/1 pipe
    Http1(Arc<Mutex<Encryption>>),
    /// HTTP/2 pipe
    #[cfg(feature = "http2")]
    Http2(h2::SendStream<Bytes>, H2SendResponse),
    /// HTTP/3 pipe
    #[cfg(feature = "http3")]
    Http3(h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>),
}
impl Debug for ResponseBodyPipe {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http1(arg0) => f.debug_tuple("Http1").field(arg0).finish(),
            #[cfg(feature = "http2")]
            Self::Http2(arg0, arg1) => f.debug_tuple("Http2").field(arg0).field(arg1).finish(),
            #[cfg(feature = "http3")]
            Self::Http3(_) => f
                .debug_tuple("Http3")
                .field(&"[internal h3 connection]".as_clean())
                .finish(),
        }
    }
}
/// A [`ResponsePipe`]-like for a pushed request-response pair.
///
/// The only logic difference between this and [`ResponsePipe`] is the
/// lack of a `push_request` method. If you want to push more than one request,
/// use the same method on [`ResponsePipe`] more times.
#[derive(Debug)]
#[must_use]
pub enum PushedResponsePipe {
    /// A HTTP/2 pushed response pipe.
    ///
    /// This is the only variant for now, but as HTTP/3
    /// is implemented, a `Http3` variant will be added.
    #[cfg(feature = "http2")]
    Http2(h2::server::SendPushedResponse<Bytes>),
}

impl HttpConnection {
    /// Creates a new [`HttpConnection`] from an [`Encryption`] stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VersionNotSupported`] when a unsupported version is passed.
    ///
    /// Also passes errors from [`h2::server::handshake`].
    #[allow(clippy::unused_async)] // cfg
    pub async fn new(stream: Encryption, version: Version) -> Result<Self, Error> {
        #[allow(clippy::match_same_arms)] // When http2 isn't enabled
        match version {
            #[allow(clippy::arc_with_non_send_sync)] // only for tokio-uring, and that probably
            // won't use that much HTTP/1, so I'll ignore.
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
                Ok(Self::Http1(Arc::new(Mutex::new(stream))))
            }
            #[cfg(feature = "http2")]
            Version::HTTP_2 => {
                let result = h2::server::Builder::new()
                    .max_concurrent_streams(512)
                    // 4MiB, not the bad default 64KiB
                    .initial_window_size(4 * 1024 * 1024)
                    .handshake(stream)
                    .await;
                match result {
                    Ok(connection) => Ok(HttpConnection::Http2(Box::new(connection))),
                    Err(err) => Err(err.into()),
                }
            }
            #[cfg(not(feature = "http2"))]
            Version::HTTP_2 => Err(Error::VersionNotSupported),
            _ => Err(Error::VersionNotSupported),
        }
    }

    /// Accept a single request.
    /// `default_host` will be used if the `Host` header is not
    /// present on a HTTP/1.x request.
    ///
    /// # Errors
    ///
    /// Returns any errors emitted from [`h2::server::Connection::accept()`].
    #[inline]
    pub async fn accept(
        &mut self,
        default_host: Option<&[u8]>,
    ) -> Result<(Request<Body>, ResponsePipe), Error> {
        match self {
            Self::Http1(stream) => {
                let response = ResponsePipe::Http1(Arc::clone(stream));
                request::parse_http_1(Arc::clone(stream), 16 * 1024, default_host)
                    .await
                    .map(|request| (request, response))
            }
            #[cfg(feature = "http2")]
            Self::Http2(connection) => match connection.accept().await {
                Some(exchange) => match exchange {
                    Ok((request, response)) => {
                        Ok((request.map(Body::Http2), ResponsePipe::Http2(response)))
                    }
                    Err(err) => Err(err.into()),
                },
                None => Err(utils::parse::Error::UnexpectedEnd.into()),
            },
            #[cfg(feature = "http3")]
            Self::Http3(c) => match c.accept().await {
                Ok(opt) => match opt {
                    Some((req, stream)) => {
                        let (write, read) = stream.split();
                        Ok((req.map(|()| Body::Http3(read)), ResponsePipe::Http3(write)))
                    }
                    None => Err(utils::parse::Error::UnexpectedEnd.into()),
                },
                Err(err) => Err(err.into()),
            },
        }
    }
    /// Ask this connection to shutdown.
    pub async fn shutdown(self) {
        match self {
            Self::Http1(h) => {
                drop(h.lock().await.shutdown().await);
            }
            #[cfg(feature = "http2")]
            Self::Http2(mut h) => h.graceful_shutdown(),
            #[cfg(feature = "http3")]
            Self::Http3(mut h) => drop(h.shutdown(1024)),
        }
    }
}

mod request {
    use super::{io, response, utils, Arc, Body, Bytes, Encryption, Error, Mutex, Request};

    #[inline]
    pub(crate) async fn parse_http_1(
        stream: Arc<Mutex<Encryption>>,
        max_len: usize,
        default_host: Option<&[u8]>,
    ) -> Result<Request<Body>, Error> {
        let scheme = match &*stream.lock().await {
            Encryption::Tcp(_) => "http",
            #[cfg(feature = "https")]
            Encryption::TcpTls(_) => "https",
        };
        let lock = stream.lock().await;

        #[cfg(feature = "async-networking")]
        let (head, bytes) = kvarn_async::read::request(
            lock,
            max_len,
            default_host,
            scheme,
            std::time::Duration::from_secs(5),
        )
        .await?;

        #[cfg(not(feature = "async-networking"))]
        let (head, bytes) = async {
            use kvarn_utils::{parse::Error, parse::RequestParseStage, prelude::*};

            #[inline]
            fn contains_two_newlines(bytes: &[u8]) -> bool {
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

            let mut stream = lock;
            let buffer = {
                let mut buffer = BytesMut::with_capacity(512);
                let mut read = 0;
                let read = &mut read;

                loop {
                    if {
                        let buffer: &mut BytesMut = &mut buffer;
                        let read: &mut usize = read;
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
                        let Encryption::Tcp(tcp) = &mut *stream;
                        let read_now = tcp
                            .read(&mut buffer[*read..])
                            .ok()
                            .ok_or(Error::UnexpectedEnd)?;
                        *read += read_now;
                        unsafe { buffer.set_len(*read) };

                        read_now
                    } == 0
                    {
                        break;
                    };
                    if !(utils::valid_method(&buffer) || utils::valid_version(&buffer)) {
                        return Err(Error::Syntax);
                    }

                    if contains_two_newlines(&buffer) {
                        break;
                    }
                }
                buffer.freeze()
            };

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
                                let (headers, end) =
                                    parse::headers(&buffer.slice(header_end - 1..))?;
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
                let mut uri = BytesMut::with_capacity(
                    scheme.len() + 3 + host.len() + (path_end - path_start),
                );

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
        .await?;
        let body = Body::Http1(response::Http1Body::new(
            stream,
            bytes,
            utils::get_body_length_request(&head),
        ));
        Ok(head.map(|()| body))
    }

    impl Body {
        /// Reads all bytes from [`Body`] to a [`Bytes`].
        ///
        /// # Errors
        ///
        /// Passes any errors returned from the inner reader.
        /// See [`super::Http1Body::read_to_bytes()`] and [`h2::RecvStream::poll_data()`] for more info.
        #[inline]
        pub async fn read_to_bytes(&mut self, max_len: usize) -> io::Result<Bytes> {
            match self {
                Self::Bytes(bytes) => Ok(bytes.read_rest()),
                Self::Http1(h1) => h1.read_to_bytes(max_len).await,
                #[cfg(feature = "http2")]
                Self::Http2(h2) => {
                    let mut bytes = bytes::BytesMut::new();
                    while let Some(result) = h2.data().await {
                        // Important to allow more data to be sent!
                        h2.flow_control()
                            .release_capacity(result.as_ref().map_or(0, Bytes::len))
                            .expect("we're releasing what go received");
                        let left = max_len.saturating_sub(bytes.len());
                        if left == 0 {
                            break;
                        }

                        let data = result
                            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

                        bytes.extend_from_slice(&data[..(data.len().min(left))]);
                        let left = max_len.saturating_sub(bytes.len());
                        if left == 0 {
                            break;
                        }
                    }
                    Ok(bytes.freeze())
                }
                #[cfg(feature = "http3")]
                Self::Http3(h3) => {
                    use bytes::BufMut;
                    let mut bytes = bytes::BytesMut::new();
                    while let Some(data) = h3.recv_data().await.map_err(Error::H3)? {
                        let left = max_len.saturating_sub(bytes.len());
                        if left == 0 {
                            break;
                        }

                        bytes.put(data);
                        let left = max_len.saturating_sub(bytes.len());
                        if left == 0 {
                            break;
                        }
                    }
                    Ok(bytes.freeze())
                }
            }
        }
    }
}

mod response {
    use crate::prelude::{application::*, internals::*, *};

    /// A HTTP/1 body.
    ///
    /// The reason of this type and the inner buffer is described in [`super::Body::Http1`]
    #[must_use]
    pub struct Http1Body<R: AsyncRead + Unpin> {
        reader: Arc<Mutex<R>>,
        bytes: Bytes,
        offset: usize,

        content_length: usize,
        // also update Debug implementation when adding fields
    }
    impl<R: AsyncRead + Unpin> Http1Body<R> {
        /// Creates a new body.
        ///
        /// `content_length` should be the total length of the body, found in the [`Request::headers`].
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
        /// # Errors
        ///
        /// Returns any errors from the underlying reader.
        #[inline]
        pub async fn read_to_bytes(&mut self, max_len: usize) -> io::Result<Bytes> {
            let len = self.content_length.min(max_len);

            if len == 0 {
                return Ok(Bytes::new());
            }
            let mut buffer = BytesMut::with_capacity(len);
            if len < self.bytes.len() {
                buffer.extend_from_slice(&self.bytes[..len]);
                self.offset = len;
            } else {
                buffer.extend_from_slice(&self.bytes);
                self.offset = self.bytes.len();
            }
            if let Ok(result) = timeout(
                Duration::from_secs(30),
                async_bits::read_to_end_or_max(&mut buffer, &mut *self, len),
            )
            .await
            {
                result?;
            } else {
                self.content_length = 0;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Reading of request body timed out.",
                ));
            }

            // Don't return anything next time we are called!
            self.content_length = 0;
            Ok(buffer.freeze())
        }
    }
    impl<R: AsyncRead + Unpin + Debug> Debug for Http1Body<R> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let mut s = f.debug_struct(utils::ident_str!(
                Http1Body,
                R,
                R: AsyncRead + Unpin + Debug
            ));
            utils::fmt_fields!(
                s,
                (self.reader),
                (self.bytes, &"[internal buffer]".as_clean()),
                (self.offset),
                (self.content_length)
            );
            s.finish()
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
                cx.waker().wake_by_ref();
                Poll::Ready(Ok(()))
            } else {
                let mut lock = self.reader.lock();
                let mut reader = match unsafe { Pin::new_unchecked(&mut lock) }.poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(r) => r,
                };
                let size = buf.filled().len();
                let result = unsafe { Pin::new_unchecked(&mut *reader).poll_read(cx, buf) };
                drop(reader);
                drop(lock);
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
        /// # Errors
        ///
        /// Passes any errors from writing to the stream. see [`AsyncWriteExt::write()`] and
        /// [`h2::server::SendResponse::send_response()`] for more info.
        #[inline]
        pub async fn send_response(
            self,
            mut response: Response<()>,
            #[allow(unused_variables)] end_of_stream: bool,
        ) -> Result<ResponseBodyPipe, Error> {
            match self {
                Self::Http1(s) => {
                    {
                        let mut writer = s.lock().await;
                        match response
                            .headers()
                            .get("connection")
                            .map(HeaderValue::to_str)
                            .and_then(Result::ok)
                        {
                            Some("close") | None => {
                                response
                                    .headers_mut()
                                    .insert("connection", HeaderValue::from_static("keep-alive"));
                            }
                            _ => {}
                        }
                        let mut writer = tokio::io::BufWriter::with_capacity(512, &mut *writer);
                        async_bits::write::response(&response, b"", &mut writer).await?;
                        writer.flush().await?;
                        writer.into_inner();
                    }

                    Ok(ResponseBodyPipe::Http1(s))
                }
                #[cfg(feature = "http2")]
                Self::Http2(mut s) => match s.send_response(response, end_of_stream) {
                    Err(ref err) if err.get_io().is_none() && err.reason().is_none() => {
                        Err(Error::ClientRefusedResponse)
                    }
                    Err(err) => Err(err.into()),
                    Ok(pipe) => Ok(ResponseBodyPipe::Http2(pipe, H2SendResponse::Initial(s))),
                },
                #[cfg(feature = "http3")]
                Self::Http3(mut s) => match s.send_response(response).await {
                    Err(ref err)
                        if err.try_get_code() == Some(h3::error::Code::H3_REQUEST_CANCELLED)
                            || err.try_get_code() == Some(h3::error::Code::H3_REQUEST_REJECTED)
                            || err.try_get_code() == Some(h3::error::Code::H3_NO_ERROR) =>
                    {
                        Err(Error::ClientRefusedResponse)
                    }
                    Err(err) => Err(err.into()),
                    Ok(()) => Ok(ResponseBodyPipe::Http3(s)),
                },
            }
        }
        /// Ensures the version and length of the `response` using the variant of [`ResponsePipe`].
        #[inline]
        pub fn ensure_version_and_length<T>(&self, response: &mut Response<T>, len: usize) {
            match self {
                Self::Http1(_) => match response.version() {
                    Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
                        utils::set_content_length(response.headers_mut(), len);
                    }

                    _ => *response.version_mut() = Version::HTTP_11,
                },
                #[cfg(feature = "http2")]
                Self::Http2(_) => *response.version_mut() = Version::HTTP_2,
                #[cfg(feature = "http3")]
                Self::Http3(_) => *response.version_mut() = Version::HTTP_3,
            }
        }
    }
    #[allow(unused_variables)]
    impl PushedResponsePipe {
        /// Sends a single push response.
        ///
        /// # Errors
        ///
        /// Errors are passed from the HTTP libraries, for now only [`mod@h2`].
        /// See [`h2::server::SendPushedResponse::send_response()`] for more information.
        #[inline]
        #[allow(clippy::needless_pass_by_value)]
        pub fn send_response(
            self,
            response: Response<()>,
            end_of_stream: bool,
        ) -> Result<ResponseBodyPipe, Error> {
            match self {
                #[cfg(feature = "http2")]
                Self::Http2(mut s) => {
                    let mut response = response;
                    *response.version_mut() = Version::HTTP_2;

                    match s.send_response(response, end_of_stream) {
                        Err(err) => Err(err.into()),
                        Ok(pipe) => Ok(ResponseBodyPipe::Http2(pipe, H2SendResponse::Pushed(s))),
                    }
                }
                #[allow(unreachable_patterns)]
                #[cfg(not(feature = "http2"))]
                _ => unreachable!(),
            }
        }
        /// Ensures the version of `response` depending on inner version if [`PushedResponsePipe`].
        #[inline]
        #[allow(unused_variables)]
        pub fn ensure_version<T>(&self, response: &mut Response<T>) {
            match self {
                #[cfg(feature = "http2")]
                Self::Http2(_) => *response.version_mut() = Version::HTTP_2,
                #[cfg(not(any(feature = "http2")))]
                _ => unreachable!(),
            }
        }
    }

    impl ResponseBodyPipe {
        /// Sends `data` as the body.
        ///
        /// # Errors
        ///
        /// Passes any errors from writing to the stream.
        /// See [`AsyncWriteExt::write_all()`] and [`h2::SendStream::send_data()`].
        #[inline]
        pub async fn send(&mut self, data: Bytes) -> Result<(), Error> {
            self.send_with_maybe_close(data, false).await
        }
        /// Only does something for HTTP/1, since the other protocols are not implemented as
        /// streams.
        ///
        /// **To shut down the stream**, it is necessary to call [`ResponseBodyPipe::close`].
        ///
        /// # Errors
        ///
        /// Passes any errors from flushing the stream.
        pub async fn flush(&mut self) -> Result<(), Error> {
            if let Self::Http1(h1) = self {
                let mut lock = h1.lock().await;
                lock.flush().await?;
            }
            Ok(())
        }
        /// Same as [`ResponseBodyPipe::send`] but tries its best to wait for the data to actually
        /// be sent, freeing up previous [`Bytes`] being sent before.
        ///
        /// `chunk_size` is the expected size of `data` used to negotiate and wait for capacity
        /// changes. A value of ~10MB is often good (`chunk_size` is measured in bytes).
        ///
        /// # Errors
        ///
        /// Same as [`ResponseBodyPipe::send`].
        pub async fn send_with_wait(
            &mut self,
            data: Bytes,
            chunk_size: usize,
        ) -> Result<(), Error> {
            if let Self::Http2(stream, _) = self {
                stream.reserve_capacity(chunk_size);
                // if `chunk_size` is 10MB, this artificially limits the connection to 20MB/s for
                // connections with a ping > 500ms, which imo is fair.
                //
                // I really don't care about the result.
                let _ = tokio::time::timeout(
                    Duration::from_millis(500),
                    std::future::poll_fn(|cx| stream.poll_capacity(cx)),
                )
                .await;
            }
            self.send(data).await
        }
        /// Same as [`Self::send`] but with a `end_of_stream` variable.
        #[inline]
        pub(crate) async fn send_with_maybe_close(
            &mut self,
            data: Bytes,
            end_of_stream: bool,
        ) -> Result<(), Error> {
            match self {
                Self::Http1(h1) => {
                    let mut lock = h1.lock().await;
                    lock.write_all(&data).await?;
                    if end_of_stream {
                        lock.flush().await?;
                    }
                }
                #[cfg(feature = "http2")]
                Self::Http2(h2, _) => h2.send_data(data, end_of_stream)?,
                #[cfg(feature = "http3")]
                Self::Http3(h3) => match h3.send_data(data).await {
                    Err(ref err)
                        if err.try_get_code() == Some(h3::error::Code::H3_REQUEST_CANCELLED)
                            || err.try_get_code() == Some(h3::error::Code::H3_REQUEST_REJECTED)
                            || err.try_get_code() == Some(h3::error::Code::H3_NO_ERROR) =>
                    {
                        return Err(Error::ClientRefusedResponse);
                    }
                    err @ Err(_) => {
                        err?;
                    }
                    Ok(()) => {}
                },
            }
            Ok(())
        }
        /// Pushes `request` to client.
        ///
        /// # Errors
        ///
        /// If you try to push if `self` is [`ResponsePipe::Http1`], an [`Error::UnsupportedPush`] is returned.
        /// Returns errors from [`h2::server::SendResponse::push_request()`].
        #[inline]
        #[allow(clippy::needless_pass_by_value)]
        pub fn push_request(
            &mut self,
            #[allow(unused_variables)] request: Request<()>,
        ) -> Result<PushedResponsePipe, Error> {
            match self {
                Self::Http1(_) => Err(Error::UnsupportedPush),
                #[cfg(feature = "http2")]
                Self::Http2(_, H2SendResponse::Pushed(_)) => Err(Error::UnsupportedPush),
                #[cfg(feature = "http2")]
                Self::Http2(_, H2SendResponse::Initial(h2)) => match h2.push_request(request) {
                    Ok(pipe) => Ok(PushedResponsePipe::Http2(pipe)),
                    Err(err) => Err(err.into()),
                },
                #[cfg(feature = "http3")]
                Self::Http3(_) => Err(Error::UnsupportedPush),
            }
        }
        /// Closes the pipe.
        ///
        /// # Errors
        ///
        /// Passes any errors emitted when closing the writer.
        /// See [`AsyncWriteExt::flush()`] and [`h2::SendStream::send_data()`].
        #[inline]
        pub async fn close(&mut self) -> Result<(), Error> {
            match self {
                Self::Http1(h1) => h1.lock().await.flush().await.map_err(Into::into),
                #[cfg(feature = "http2")]
                Self::Http2(h2, _) => h2.send_data(Bytes::new(), true).map_err(Error::from),
                #[cfg(feature = "http3")]
                Self::Http3(h3) => match h3.finish().await {
                    Ok(()) => Ok(()),
                    Err(ref err)
                        if err.try_get_code() == Some(h3::error::Code::H3_REQUEST_CANCELLED)
                            || err.try_get_code() == Some(h3::error::Code::H3_REQUEST_REJECTED)
                            || err.try_get_code() == Some(h3::error::Code::H3_NO_ERROR) =>
                    {
                        Err(Error::ClientRefusedResponse)
                    }
                    r => r.map_err(Error::from),
                },
            }
        }
    }
}

#[cfg(feature = "uring")]
mod uring_tokio_compat {
    use crate::prelude::*;

    /// Wrapper for `tokio_uring`'s `TcpStream`, to implement [`AsyncRead`] and [`AsyncWrite`]
    /// by using buffers.
    #[allow(clippy::type_complexity)]
    pub struct TcpStreamAsyncWrapper {
        read_fut: Option<Pin<Box<dyn Future<Output = tokio_uring::BufResult<usize, Vec<u8>>>>>>,
        write_fut: Option<Pin<Box<dyn Future<Output = tokio_uring::BufResult<(), Vec<u8>>>>>>,
        read_buf: Option<(Vec<u8>, usize)>,
        write_buf: Option<Vec<u8>>,
        stream: tokio_uring::net::TcpStream,
    }
    impl TcpStreamAsyncWrapper {
        pub(crate) fn new(stream: tokio_uring::net::TcpStream) -> Self {
            Self {
                read_fut: None,
                write_fut: None,
                read_buf: Some((Vec::with_capacity(1024 * 64), 0)),
                write_buf: Some(Vec::with_capacity(1024 * 64)),
                stream,
            }
        }
    }
    impl Debug for TcpStreamAsyncWrapper {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let mut s = f.debug_struct(utils::ident_str!(TcpStreamAsyncWrapper));

            utils::fmt_fields!(
                s,
                (
                    self.read_fut,
                    &self
                        .read_fut
                        .as_ref()
                        .map(|_| "[internal future]".as_clean())
                ),
                (
                    self.write_fut,
                    &self
                        .write_fut
                        .as_ref()
                        .map(|_| "[internal future]".as_clean())
                ),
                (self.write_buf, &"[internal buffer]".as_clean()),
                (self.read_buf, &"[internal buffer]".as_clean()),
                (self.write_fut, &"[internal buffer]".as_clean()),
                (self.stream, &"[internal stream]".as_clean()),
            );

            s.finish()
        }
    }
    impl AsyncRead for TcpStreamAsyncWrapper {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Self {
                read_fut,
                read_buf,
                stream,
                ..
            } = &mut *self;

            // SAFETY: we store the future in the same struct, and as the stream is stored after it, it
            // gets dropped later: the future's lifetime requirement for stream is met.
            let stream: &'static tokio_uring::net::TcpStream =
                unsafe { &*(stream as *const tokio_uring::net::TcpStream) };

            loop {
                if let Some(read) = read_buf {
                    let len = (read.0.len() - read.1).min(buf.remaining());
                    if len > 0 {
                        buf.put_slice(&read.0[read.1..read.1 + len]);
                        read.1 += len;

                        // fill from buffer again
                        return Poll::Ready(Result::Ok(()));
                    }
                }
                if let Some(fut) = read_fut {
                    let (r, mut buf) = std::task::ready!(Pin::new(fut).poll(cx));
                    match r {
                        Err(err) => return Poll::Ready(Err(err)),
                        Ok(read) => unsafe { buf.set_len(read) },
                    }
                    if buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    *read_buf = Some((buf, 0));
                    *read_fut = None;
                    continue;
                }

                // read
                let mut buf = read_buf.take().unwrap().0;
                unsafe { buf.set_len(buf.capacity()) };
                let fut = stream.read(buf);
                *read_fut = Some(Box::pin(fut));
                // continue
            }
        }
    }
    impl AsyncWrite for TcpStreamAsyncWrapper {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let Self {
                write_fut,
                write_buf,
                stream,
                ..
            } = &mut *self;

            // SAFETY: we store the future in the same struct, and as the stream is stored after it, it
            // gets dropped later: the future's lifetime requirement for stream is met.
            let stream: &'static tokio_uring::net::TcpStream =
                unsafe { &*(stream as *const tokio_uring::net::TcpStream) };

            loop {
                if let Some(buf) = write_buf {
                    let available = buf.capacity() - buf.len();
                    if available == 0 {
                        let fut = stream.write_all(write_buf.take().unwrap());
                        let b = Box::pin(fut);
                        *write_fut = Some(b);
                        continue;
                    }
                    let append = available.min(bytes.len());
                    buf.extend_from_slice(&bytes[..append]);
                    return Poll::Ready(Ok(append));
                }

                let fut = write_fut.as_mut().unwrap();
                let (r, mut buf) = std::task::ready!(Pin::new(fut).poll(cx));
                unsafe { buf.set_len(0) };
                *write_buf = Some(buf);
                *write_fut = None;
                if let Err(err) = r {
                    return Poll::Ready(Err(err));
                }
                // loop to write more
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(self.stream.shutdown(net::Shutdown::Both))
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            let Self {
                write_fut,
                write_buf,
                stream,
                ..
            } = &mut *self;

            // SAFETY: we store the future in the same struct, and as the stream is stored after it, it
            // gets dropped later: the future's lifetime requirement for stream is met.
            let stream: &'static tokio_uring::net::TcpStream =
                unsafe { &*(stream as *const tokio_uring::net::TcpStream) };

            loop {
                if let Some(buf) = write_buf {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let fut = stream.write_all(write_buf.take().unwrap());
                    let b = Box::pin(fut);
                    *write_fut = Some(b);
                    continue;
                }

                let fut = write_fut.as_mut().unwrap();
                let (r, mut buf) = std::task::ready!(Pin::new(fut).poll(cx));
                unsafe { buf.set_len(0) };
                *write_buf = Some(buf);
                *write_fut = None;
                if let Err(err) = r {
                    return Poll::Ready(Err(err));
                }
                // loop to write more
            }
        }
    }
}

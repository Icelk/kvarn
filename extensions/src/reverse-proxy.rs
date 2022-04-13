use crate::connection::{Connection, EstablishedConnection};
use kvarn::prelude::{internals::*, *};
use std::net::{Ipv4Addr, SocketAddrV4};

#[path = "url-rewrite.rs"]
pub mod url_rewrite;

pub use async_bits::CopyBuffer;
#[macro_use]
pub mod async_bits {
    use kvarn::prelude::*;
    macro_rules! ready {
        ($poll: expr) => {
            match $poll {
                Poll::Ready(v) => v,
                Poll::Pending => return Poll::Pending,
            }
        };
    }
    macro_rules! ret_ready_err {
        ($poll: expr) => {
            match $poll {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(r) => Poll::Ready(r),
                _ => $poll,
            }
        };
        ($poll: expr, $map: expr) => {
            match $poll {
                Poll::Ready(Err(e)) => return Poll::Ready(Err($map(e))),
                Poll::Ready(r) => Poll::Ready(r),
                _ => Poll::Pending,
            }
        };
    }

    #[derive(Debug)]
    pub struct CopyBuffer {
        read_done: bool,
        pos: usize,
        cap: usize,
        buf: Box<[u8]>,
    }

    impl CopyBuffer {
        pub fn new() -> Self {
            Self {
                read_done: false,
                pos: 0,
                cap: 0,
                buf: std::vec::from_elem(0, 2048).into_boxed_slice(),
            }
        }
        pub fn with_capacity(initialized: usize) -> Self {
            Self {
                read_done: false,
                pos: 0,
                cap: 0,
                buf: std::vec::from_elem(0, initialized).into_boxed_slice(),
            }
        }

        /// Returns Ok(true) if it's done reading.
        pub fn poll_copy<R, W>(
            &mut self,
            cx: &mut Context<'_>,
            mut reader: Pin<&mut R>,
            mut writer: Pin<&mut W>,
        ) -> Poll<io::Result<bool>>
        where
            R: AsyncRead + ?Sized,
            W: AsyncWrite + ?Sized,
        {
            loop {
                // If our buffer is empty, then we need to read some data to
                // continue.
                if self.pos == self.cap && !self.read_done {
                    let me = &mut *self;
                    let mut buf = ReadBuf::new(&mut me.buf);
                    ready!(reader.as_mut().poll_read(cx, &mut buf))?;
                    let n = buf.filled().len();
                    if n == 0 {
                        self.read_done = true;
                    } else {
                        self.pos = 0;
                        self.cap = n;
                    }
                }

                // If our buffer has some data, let's write it out!
                while self.pos < self.cap {
                    let i = ready!(writer
                        .as_mut()
                        .poll_write(cx, &self.buf[self.pos..self.cap]))?;
                    if i == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero byte into writer",
                        )));
                    } else {
                        self.pos += i;
                    }
                    if self.pos >= self.cap {
                        return Poll::Ready(Ok(false));
                    }
                }

                // If we've written all the data and we've seen EOF, flush out the
                // data and finish the transfer.
                if self.pos == self.cap && self.read_done {
                    ready!(writer.as_mut().poll_flush(cx))?;
                    return Poll::Ready(Ok(true));
                }
            }
        }
    }
    impl Default for CopyBuffer {
        fn default() -> Self {
            Self::new()
        }
    }
}

impl EstablishedConnection {
    pub async fn request<T: Debug>(
        &mut self,
        request: &Request<T>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<Response<Bytes>, GatewayError> {
        let mut buffered = tokio::io::BufWriter::new(&mut *self);
        info!("Sending request");
        write::request(request, body, &mut buffered).await?;

        info!("Sent reverse-proxy request. Reading response.");

        let response = match tokio::time::timeout(
            timeout,
            kvarn::prelude::async_bits::read::response(&mut *self, 16 * 1024, timeout),
        )
        .await
        {
            Ok(result) => match result {
                Err(err) => return Err(err.into()),
                Ok(response) => {
                    enum MaybeChunked<R1, R2> {
                        No(R1),
                        Yes(async_chunked_transfer::Decoder<R2>),
                    }
                    impl<R1: AsyncRead + Unpin, R2: AsyncRead + Unpin> AsyncRead for MaybeChunked<R1, R2> {
                        fn poll_read(
                            mut self: Pin<&mut Self>,
                            cx: &mut Context<'_>,
                            buf: &mut ReadBuf<'_>,
                        ) -> Poll<io::Result<()>> {
                            match &mut *self {
                                Self::No(reader) => Pin::new(reader).poll_read(cx, buf),
                                Self::Yes(reader) => Pin::new(reader).poll_read(cx, buf),
                            }
                        }
                    }

                    let chunked =
                        utils::header_eq(response.headers(), "transfer-encoding", "chunked");
                    let len = if chunked {
                        usize::MAX
                    } else if body.is_empty() {
                        utils::get_body_length_response(&response, Some(request.method()))
                    } else {
                        utils::get_body_length_response(&response, None)
                    };

                    let (mut head, body) = utils::split_response(response);

                    let body = if len == 0 || len <= body.len() {
                        body
                    } else {
                        let mut buffer = BytesMut::with_capacity(body.len() + 512);

                        let reader = if chunked {
                            let reader = AsyncReadExt::chain(&*body, &mut *self);
                            let decoder = async_chunked_transfer::Decoder::new(reader);
                            MaybeChunked::Yes(decoder)
                        } else {
                            buffer.extend(&body);
                            MaybeChunked::No(&mut *self)
                        };

                        if let Ok(result) = tokio::time::timeout(
                            timeout,
                            read_to_end_or_max(&mut buffer, reader, len),
                        )
                        .await
                        {
                            result?
                        } else {
                            warn!("Remote read timed out.");
                            unsafe { buffer.set_len(if chunked { 0 } else { body.len() }) };
                        }

                        if chunked {
                            utils::remove_all_headers(head.headers_mut(), "transfer-encoding");
                            info!("Decoding chunked transfer-encoding.");
                        }
                        buffer.freeze()
                    };

                    head.map(|()| body)
                }
            },
            Err(_) => return Err(GatewayError::Timeout),
        };
        Ok(response)
    }
}

#[derive(Debug)]
pub enum GatewayError {
    Io(io::Error),
    Timeout,
    Parse(parse::Error),
}
impl From<io::Error> for GatewayError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<parse::Error> for GatewayError {
    fn from(err: parse::Error) -> Self {
        Self::Parse(err)
    }
}

#[derive(Debug)]
pub enum OpenBackError {
    Front(io::Error),
    Back(io::Error),
    Closed,
}
impl OpenBackError {
    pub fn get_io(&self) -> Option<&io::Error> {
        match self {
            Self::Front(e) | Self::Back(e) => Some(e),
            Self::Closed => None,
        }
    }
    pub fn get_io_kind(&self) -> io::ErrorKind {
        match self {
            Self::Front(e) | Self::Back(e) => e.kind(),
            Self::Closed => io::ErrorKind::BrokenPipe,
        }
    }
}
pub struct ByteProxy<'a, F: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin> {
    front: &'a mut F,
    back: &'a mut B,
    // ToDo: Optimize to one buffer!
    front_buf: CopyBuffer,
    back_buf: CopyBuffer,
}
impl<'a, F: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin> ByteProxy<'a, F, B> {
    pub fn new(front: &'a mut F, back: &'a mut B) -> Self {
        Self {
            front,
            back,
            front_buf: CopyBuffer::new(),
            back_buf: CopyBuffer::new(),
        }
    }
    pub fn poll_channel(&mut self, cx: &mut Context) -> Poll<Result<(), OpenBackError>> {
        macro_rules! copy_from_to {
            ($reader: expr, $error: expr, $buf: expr, $writer: expr) => {
                if let Poll::Ready(Ok(pipe_closed)) = ret_ready_err!(
                    $buf.poll_copy(cx, Pin::new($reader), Pin::new($writer)),
                    $error
                ) {
                    if pipe_closed {
                        return Poll::Ready(Err(OpenBackError::Closed));
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                };
            };
        }

        copy_from_to!(self.back, OpenBackError::Back, self.front_buf, self.front);
        copy_from_to!(self.front, OpenBackError::Front, self.back_buf, self.back);

        Poll::Pending
    }
    pub async fn channel(&mut self) -> Result<(), OpenBackError> {
        futures_util::future::poll_fn(|cx| self.poll_channel(cx)).await
    }
}

pub type ModifyRequestFn = Arc<dyn Fn(&mut Request<()>, &mut Bytes, SocketAddr) + Send + Sync>;
pub type GetConnectionFn = Arc<dyn (Fn(&FatRequest, &Bytes) -> Option<Connection>) + Send + Sync>;

/// Creates a new [`GetConnectionFn`] which always returns `kind`
pub fn static_connection(kind: Connection) -> GetConnectionFn {
    Arc::new(move |_, _| Some(kind))
}

#[must_use = "mount the reverse proxy manager"]
pub struct Manager {
    when: extensions::If,
    connection: GetConnectionFn,
    modify: Vec<ModifyRequestFn>,
    timeout: Duration,
    rewrite_url: bool,
    priority: i32,
}
impl Manager {
    /// Consider using [`static_connection`] if your connection type is not dependent of the request.
    pub fn new(
        when: extensions::If,
        connection: GetConnectionFn,
        modify: ModifyRequestFn,
        timeout: Duration,
    ) -> Self {
        Self {
            when,
            connection,
            modify: vec![modify],
            timeout,
            rewrite_url: true,
            priority: -128,
        }
    }
    /// Disables the built-in feature of rewriting the relative URLs so they point to the forwarded
    /// site.
    pub fn disable_url_rewrite(mut self) -> Self {
        self.rewrite_url = false;
        self
    }
    /// Set the priority of the extension. The default is `-128`.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
    /// Add a function to run before the request is sent.
    /// These are ran in the order they are added in.
    pub fn add_modify_fn(mut self, modify: ModifyRequestFn) -> Self {
        self.modify.push(modify);
        self
    }
    /// Consider using [`static_connection`] if your connection type is not dependent of the request.
    pub fn base(base_path: &str, connection: GetConnectionFn, timeout: Duration) -> Self {
        assert_eq!(base_path.chars().next(), Some('/'));
        let path = if base_path.ends_with('/') {
            base_path.to_owned()
        } else {
            let mut s = String::with_capacity(base_path.len() + 1);
            s.push_str(base_path);
            s.push('/');
            s
        };
        let path = Arc::new(path);

        let when_path = Arc::clone(&path);
        let when = Box::new(move |request: &FatRequest, _host: &Host| {
            request.uri().path().starts_with(when_path.as_str())
        });

        let modify: ModifyRequestFn = Arc::new(move |request, _, _| {
            let path = Arc::clone(&path);

            let mut parts = request.uri().clone().into_parts();

            if let Some(path_and_query) = parts.path_and_query.as_ref() {
                if let Some(s) = path_and_query.as_str().get(path.as_str().len() - 1..) {
                    // We know this is a good path and query; we've just removed the first x bytes.
                    // The -1 will always be on a char boundary; the last character is always '/'
                    let short =
                        uri::PathAndQuery::from_maybe_shared(Bytes::copy_from_slice(s.as_bytes()))
                            .unwrap();
                    parts.path_and_query = Some(short);
                    parts.scheme = Some(uri::Scheme::HTTP);
                    // For unwrap, see ↑
                    let uri = Uri::from_parts(parts).unwrap();
                    *request.uri_mut() = uri;
                } else {
                    error!("We didn't get the expected path string from Kvarn. We asked for one which started with `base_path`");
                }
            }
        });

        Self::new(when, connection, modify, timeout)
    }
    /// Attach this reverse proxy to `extensions`.
    pub fn mount(self, extensions: &mut Extensions) {
        let connection = self.connection;
        let modify = self.modify;

        macro_rules! return_status {
            ($result:expr, $status:expr, $host:expr) => {
                match $result {
                    Some(v) => v,
                    None => {
                        return default_error_response($status, $host, None).await;
                    }
                }
            };
        }

        let timeout = self.timeout;
        let rewrite_url = self.rewrite_url;

        extensions.add_prepare_fn(
            self.when,
            prepare!(
                req,
                host,
                _path,
                addr,
                move |connection: GetConnectionFn,
                      modify: Vec<ModifyRequestFn>,
                      timeout: Duration,
                      rewrite_url: bool| {
                    let mut empty_req = utils::empty_clone_request(req);
                    let mut bytes = return_status!(
                        req.body_mut().read_to_bytes().await.ok(),
                        StatusCode::BAD_GATEWAY,
                        host
                    );

                    let connection =
                        return_status!(connection(req, &bytes), StatusCode::BAD_REQUEST, host);
                    let mut connection = return_status!(
                        connection.establish().await.ok(),
                        StatusCode::GATEWAY_TIMEOUT,
                        host
                    );

                    utils::replace_header_static(
                        empty_req.headers_mut(),
                        "accept-encoding",
                        "identity",
                    );

                    if utils::header_eq(empty_req.headers(), "connection", "keep-alive") {
                        utils::replace_header_static(
                            empty_req.headers_mut(),
                            "connection",
                            "close",
                        );
                    }

                    *empty_req.version_mut() = Version::HTTP_11;

                    if let Ok(value) = host.name.parse() {
                        utils::replace_header(empty_req.headers_mut(), "host", value);
                    }

                    let wait = matches!(empty_req.method(), &Method::CONNECT)
                        || empty_req.headers().get("upgrade")
                            == Some(&HeaderValue::from_static("websocket"));

                    let path = empty_req.uri().path().to_owned();

                    for modify in &*modify {
                        modify(&mut empty_req, &mut bytes, addr);
                    }

                    let mut response = match connection.request(&empty_req, &bytes, *timeout).await
                    {
                        Ok(mut response) => {
                            // The response's body will not be compressed, as we set the
                            // `accept-encoding` to `identity` before.

                            if *rewrite_url {
                                let content_type = response
                                    .headers()
                                    .get("content-type")
                                    .and_then(|ct| ct.to_str().ok())
                                    .and_then(|ct| ct.parse::<Mime>().ok());
                                if let Some(
                                    (mime::TEXT, mime::HTML | mime::CSS)
                                    | (mime::APPLICATION, mime::JAVASCRIPT),
                                ) = content_type.as_ref().map(|ct| (ct.type_(), ct.subtype()))
                                {
                                    if let Some(prefix) = path.strip_suffix(empty_req.uri().path())
                                    {
                                        // Since we strip `.path` (which starts with `/`, Kvarn denies requests with more than one `/`),
                                        // prefix is guaranteed not to end with `/`.
                                        response = response.map(|body| {
                                            url_rewrite::absolute(&body, prefix).freeze()
                                        });
                                    }
                                }

                                let headers = response.headers_mut();
                                utils::remove_all_headers(headers, "keep-alive");
                                utils::remove_all_headers(headers, "content-length");
                                if !utils::header_eq(headers, "connection", "upgrade") {
                                    utils::remove_all_headers(headers, "connection");
                                }
                            }

                            FatResponse::cache(response)
                        }
                        Err(err) => {
                            warn!("Got error {:?}", err);
                            default_error_response(
                                match err {
                                    GatewayError::Io(_) | GatewayError::Parse(_) => {
                                        StatusCode::BAD_GATEWAY
                                    }
                                    GatewayError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                                },
                                host,
                                None,
                            )
                            .await
                        }
                    };

                    if wait {
                        info!("Keeping the pipe open!");
                        let future = response_pipe_fut!(
                            response_pipe,
                            _,
                            move |connection: EstablishedConnection| {
                                let udp_connection =
                                    matches!(connection, EstablishedConnection::Udp(_));

                                let mut open_back = ByteProxy::new(response_pipe, connection);
                                debug!("Created open back!");

                                loop {
                                    // Add 90 second timeout to UDP connections.
                                    let timeout_result = if udp_connection {
                                        tokio::time::timeout(
                                            Duration::from_secs(90),
                                            open_back.channel(),
                                        )
                                        .await
                                    } else {
                                        Ok(open_back.channel().await)
                                    };

                                    if let Ok(r) = timeout_result {
                                        debug!("Open back responded! {:?}", r);
                                        match r {
                                            Err(err) => {
                                                if !matches!(
                                                    err.get_io_kind(),
                                                    io::ErrorKind::ConnectionAborted
                                                        | io::ErrorKind::ConnectionReset
                                                        | io::ErrorKind::BrokenPipe
                                                ) {
                                                    warn!("Reverse proxy io error: {:?}", err);
                                                }
                                                break;
                                            }
                                            Ok(()) => continue,
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        );

                        response = response
                            .with_future(future)
                            .with_compress(comprash::CompressPreference::None);
                    }

                    response
                }
            ),
            extensions::Id::new(self.priority, "Reverse proxy").no_override(),
        );
    }
}

pub fn localhost(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

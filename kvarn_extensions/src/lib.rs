//! # Kvarn extensions
//! A *supporter-lib* for Kvarn to supply extensions to the web server.
//!
//! Use [`new()`] to get started quickly.
//!
//! ## An introduction to the *Kvarn extension system*
//! On of the many things Kvarn extensions can to is bind to *extension declarations* and to *file extensions*.
//! For example, if you mount the extensions [`download`], it binds the *extension declaration* `download`.
//! If you then, in a file inside your `public/` directory, add `!> download` to the top, the client visiting the url pointing to the file will download it.

use kvarn::{extensions::*, prelude::*};

#[cfg(feature = "reverse-proxy")]
pub use reverse_proxy::{localhost, Connection as ReverseProxyConnection, Manager as ReverseProxy};

/// Creates a new `Extensions` and adds all enabled `kvarn_extensions`.
///
/// See [`mount_all()`] for more information.
pub fn new() -> Extensions {
    let mut e = Extensions::new();
    mount_all(&mut e);
    e
}

/// Mounts all extensions specified in Cargo.toml dependency declaration.
///
/// The current defaults are [`download()`], [`cache()`], [`php()`], and [`templates()`]
///
/// They will *always* get included in your server after calling this function.
pub fn mount_all(extensions: &mut Extensions) {
    extensions.add_present_internal("download".to_string(), Box::new(download));
    extensions.add_present_internal("cache".to_string(), Box::new(cache));
    extensions.add_present_internal("hide".to_string(), Box::new(hide));
    extensions.add_present_file("private".to_string(), Box::new(hide));
    extensions.add_present_internal("allow-ips".to_string(), Box::new(ip_allow));
    #[cfg(feature = "php")]
    extensions.add_prepare_fn(
        Box::new(|req| req.uri().path().ends_with(".php")),
        Box::new(php),
    );
    #[cfg(feature = "templates")]
    extensions.add_present_internal("tmpl".to_string(), Box::new(templates));
    #[cfg(feature = "push")]
    extensions.add_post(Box::new(push));
}

#[cfg(feature = "push")]
fn push(
    request: RequestWrapper,
    bytes: Bytes,
    mut response_pipe: ResponsePipeWrapperMut,
    addr: SocketAddr,
    host: HostWrapper,
) -> RetFut<()> {
    use internals::*;
    Box::pin(async move {
        // If it is not HTTP/1
        #[allow(irrefutable_let_patterns)]
        if let ResponsePipe::Http1(_) = unsafe { &response_pipe.get_inner() } {
            return;
        }

        const HTML_START: &str = "<!doctype html>";

        match str::from_utf8(&bytes) {
            // If it is HTML
            Ok(string) if string.get(..HTML_START.len()).map_or(false, |s| s.eq_ignore_ascii_case(HTML_START)) => {
                let mut urls = url_crawl::get_urls(string);
                let host = unsafe { host.get_inner() };

                urls.retain(|url| {
                    let correct_host = {
                        // only push https://; it's eight bytes long
                        url.get(8..)
                            .map(|url| url.starts_with(host.name))
                            .unwrap_or(false)
                    };
                    url.starts_with('/') || correct_host
                });

                info!("Pushing urls {:?}", urls);

                for url in urls {
                    unsafe {
                        let mut uri = request.get_inner().uri().clone().into_parts();
                        if let Some(url) = uri::PathAndQuery::from_maybe_shared(url.into_bytes())
                            .ok()
                            .and_then(|path| {
                                uri.path_and_query = Some(path);
                                Uri::from_parts(uri).ok()
                            })
                        {
                            let mut request = utility::empty_clone_request(request.get_inner());
                            *request.uri_mut() = url;

                            let empty_request = utility::empty_clone_request(&request);

                            let response = response_pipe.get_inner();
                            let mut response_pipe = match response.push_request(empty_request) {
                                Ok(pipe) => pipe,
                                Err(_) => return,
                            };

                            let request = request.map(|_| kvarn::application::Body::Empty);

                            if let Err(err) = kvarn::handle_cache(
                                request,
                                addr,
                                kvarn::SendKind::Push(&mut response_pipe),
                                host,
                            )
                            .await
                            {
                                error!("Error occurred when pushing request. {:?}", err);
                            };
                        }
                    }
                }
            }
            // Else, do nothing
            _ => {}
        }
    })
}

#[cfg(feature = "templates")]
pub use templates::templates;

#[cfg(feature = "fastcgi-client")]
pub mod cgi {
    use std::borrow::Cow;

    use super::*;
    use fastcgi_client::{Client, Params};

    pub enum FastcgiError {
        FailedToConnect(io::Error),
        FailedToDoRequest(fastcgi_client::ClientError),
        NoStdout,
    }
    pub async fn connect_to_fcgi(
        _port: u16,
        method: &str,
        file_name: &str,
        file_path: &str,
        uri: &str,
        address: &SocketAddr,
        body: &[u8],
    ) -> Result<Vec<u8>, FastcgiError> {
        // Create connection to FastCGI server
        #[cfg(windows)]
        let stream = match networking::TcpStream::connect((net::Ipv4Addr::LOCALHOST, _port)).await {
            Ok(stream) => stream,
            Err(err) => return Err(FastcgiError::FailedToConnect(err)),
        };
        #[cfg(unix)]
        let stream = match tokio::net::UnixStream::connect("/run/php-fpm/php-fpm.sock").await {
            Ok(stream) => stream,
            Err(err) => return Err(FastcgiError::FailedToConnect(err)),
        };
        let mut client = Client::new(stream, false);

        let len = body.len().to_string();
        let remote_addr = match address.ip() {
            IpAddr::V4(addr) => addr.to_string(),
            IpAddr::V6(addr) => addr.to_string(),
        };
        let remote_port = address.port().to_string();

        let params = Params::default()
            .set_request_method(method)
            .set_script_name(file_name)
            .set_script_filename(file_path)
            .set_request_uri(uri)
            .set_document_uri(uri)
            .set_remote_addr(&remote_addr)
            .set_remote_port(&remote_port)
            .set_server_addr("0.0.0.0")
            .set_server_port("")
            .set_server_name(kvarn::SERVER)
            .set_content_type("")
            .set_content_length(&len);

        let request = fastcgi_client::Request::new(params, body);

        match client.execute(request).await {
            Ok(output) => match output.get_stdout() {
                Some(output) => Ok(output),
                None => Err(FastcgiError::NoStdout),
            },
            Err(err) => Err(FastcgiError::FailedToDoRequest(err)),
        }
    }
    pub async fn fcgi_from_prepare<T>(
        request: &Request<T>,
        body: &[u8],
        path: &Path,
        address: SocketAddr,
        fcgi_server_port: u16,
    ) -> Result<Vec<u8>, Cow<'static, str>> {
        let file_name = match parse::format_file_name(&path) {
            Some(name) => name,
            None => {
                return Err(Cow::Borrowed("Error formatting file name!"));
            }
        };
        let file_path = match parse::format_file_path(&path) {
            Ok(name) => name,
            Err(_) => {
                return Err(Cow::Borrowed("Getting working directory!"));
            }
        };
        let file_path = match file_path.to_str() {
            Some(path) => path,
            None => {
                return Err(Cow::Borrowed("Error formatting file path!"));
            }
        };

        // Fetch fastcgi server response.
        match connect_to_fcgi(
            fcgi_server_port,
            request.method().as_str(),
            file_name,
            file_path,
            request.uri().path_and_query().unwrap().as_str(),
            &address,
            body,
        )
        .await
        {
            Ok(vec) => Ok(vec),
            Err(err) => match err {
                FastcgiError::FailedToConnect(_err) => {
                    #[cfg(windows)]
                    {
                        Err(Cow::Owned(format!(
                            "Failed to connect to FastCGI server on port {}. IO Err: {}",
                            fcgi_server_port, _err
                        )))
                    }
                    #[cfg(unix)]
                    {
                        Err(Cow::Borrowed(
                            "Failed to connect to FastCGI on '/run/php-fmp/php-fmp.sock'",
                        ))
                    }
                }
                FastcgiError::FailedToDoRequest(err) => Err(Cow::Owned(format!(
                    "Failed to request from FastCGI server! Err: {}",
                    err
                ))),
                FastcgiError::NoStdout => Err(Cow::Borrowed("No stdout in response from FastCGI!")),
            },
        }
    }
}
// Ok, since it is used, just not by every extension, and #[CFG] would be too fragile for this.
#[allow(dead_code)]
pub mod parse {
    use super::*;

    pub fn format_file_name<P: AsRef<Path>>(path: &P) -> Option<&str> {
        path.as_ref().file_name().and_then(std::ffi::OsStr::to_str)
    }
    pub fn format_file_path<P: AsRef<Path>>(path: &P) -> Result<PathBuf, io::Error> {
        let mut file_path = std::env::current_dir()?;
        file_path.push(path);
        Ok(file_path)
    }
}

#[cfg(feature = "php")]
pub fn php(
    mut req: RequestWrapperMut,
    host: HostWrapper,
    path: PathWrapper,
    address: SocketAddr,
) -> RetFut<FatResponse> {
    box_fut!({
        let req = unsafe { req.get_inner() };
        let host = unsafe { host.get_inner() };
        let path = unsafe { path.get_inner() };

        if !path.exists() {
            return utility::default_error_response(StatusCode::NOT_FOUND, host, None).await;
        }

        let body = match req.body_mut().read_to_bytes().await {
            Ok(body) => body,
            Err(_) => {
                return FatResponse::cache(
                    utility::default_error(
                        StatusCode::BAD_REQUEST,
                        Some(host),
                        Some("failed to read body".as_bytes()),
                    )
                    .await,
                )
            }
        };
        let output = match cgi::fcgi_from_prepare(req, &body, path, address, 6633).await {
            Ok(vec) => vec,
            Err(err) => {
                error!("FastCGI failed. {}", err);
                return utility::default_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    host,
                    None,
                )
                .await;
            }
        };
        let output = Bytes::copy_from_slice(&output);
        match kvarn::parse::response_php(&output) {
            Ok(response) => FatResponse::cache(response),
            Err(err) => {
                error!("failed to parse response; {}", err.as_str());
                utility::default_error_response(StatusCode::NOT_FOUND, host, None).await
            }
        }
    })
}

#[cfg(feature = "templates")]
pub mod templates {
    use super::*;

    pub fn templates(mut data: PresentDataWrapper) -> RetFut<()> {
        box_fut!({
            let data = unsafe { data.get_inner() };
            let bytes = Bytes::copy_from_slice(
                &handle_template(data.args(), &data.response().body(), data.host()).await,
            );
            *data.response_mut().body_mut() = bytes;
        })
    }

    pub async fn handle_template(
        arguments: &PresentArguments,
        file: &[u8],
        host: &Host,
    ) -> Vec<u8> {
        // Get templates, from cache or file
        let templates = read_templates(arguments.iter().rev(), host).await;

        #[derive(Eq, PartialEq)]
        enum Stage {
            Text,
            Placeholder,
        }

        let mut response = Vec::with_capacity(file.len() * 2);

        let mut stage = Stage::Text;
        let mut placeholder_start = 0;
        let mut escaped = 0;
        for (position, byte) in file.iter().enumerate() {
            let is_escape = *byte == ESCAPE;

            match stage {
                // If in text stage, check for left bracket. Then set the variables for starting identifying the placeholder for template
                // Push the current byte to response, if not start of placeholder
                Stage::Text if (escaped == 0 && !is_escape) || escaped == 1 => {
                    if *byte == L_SQ_BRACKET && escaped != 1 {
                        placeholder_start = position;
                        stage = Stage::Placeholder;
                    } else {
                        response.push(*byte);
                    }
                }
                Stage::Placeholder if escaped != 1 => {
                    // If placeholder closed
                    if *byte == R_SQ_BRACKET {
                        // Check if name is longer than empty
                        if position.checked_sub(placeholder_start + 2).is_some() {
                            // Good; we have UTF-8
                            if let Ok(key) = str::from_utf8(&file[placeholder_start + 1..position])
                            {
                                // If it is a valid template?
                                // Frick, we have to own the value for it to be borrow for Arc<String>, no &str here :(
                                if let Some(template) = templates.get(&key.to_owned()) {
                                    // Push template byte-slice to the response
                                    for byte in &**template {
                                        response.push(*byte);
                                    }
                                }
                            }
                        }
                        // Set stage to accept new text
                        stage = Stage::Text;
                    }
                }
                // Else, it's a escaping character!
                _ => {}
            }

            // Do we escape?
            if is_escape {
                escaped += 1;
                if escaped == 2 {
                    escaped = 0;
                }
            } else {
                escaped = 0;
            }
        }
        response
    }
    async fn read_templates<'a, I: Iterator<Item = &'a str>>(
        files: I,
        host: &Host,
    ) -> HashMap<String, Vec<u8>> {
        let mut templates = HashMap::with_capacity(32);

        for template in files {
            if let Some(map) = read_templates_from_file(template, host).await {
                for (key, value) in map.into_iter() {
                    templates.insert(key, value);
                }
            }
        }

        templates
    }
    async fn read_templates_from_file(
        template_set: &str,
        host: &Host,
    ) -> Option<HashMap<String, Vec<u8>>> {
        let path = utility::make_path(&host.path, "templates", template_set, None);

        // The template file will be access several times.
        match read_file_cached(&path, &host.file_cache).await {
            Some(file) => {
                let templates = extract_templates(&file[..]);
                return Some(templates);
            }
            None => None,
        }
    }
    fn extract_templates(file: &[u8]) -> HashMap<String, Vec<u8>> {
        let mut templates = HashMap::with_capacity(16);

        let mut last_was_lf = true;
        let mut escape = false;
        let mut name_start = 0;
        let mut name_end = 0usize;
        let mut newline_size = 1;
        for (position, byte) in file.iter().enumerate() {
            // Ignore all CR characters
            if *byte == CR {
                newline_size = 2;
                continue;
            }
            // Ignore all whitespace
            if *byte == SPACE || *byte == TAB {
                continue;
            }
            // If previous char was \, escape!
            // New template, process previous!
            if !escape && last_was_lf && *byte == L_SQ_BRACKET {
                // If name is longer than empty
                if name_end.checked_sub(name_start + 2).is_some() {
                    // Check if we have a valid UTF-8 string
                    if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
                        // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
                        let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                            newline_size
                        } else if file.get(name_end) == Some(&SPACE) {
                            1
                        } else {
                            0
                        };
                        // Then insert template; name we got from previous step, then bytes from where the previous template definition ended, then our current position, just before the start of the next template
                        // Returns a byte-slice of the file
                        templates.insert(
                            name.to_owned(),
                            file[name_end + add_after_name..position - newline_size].to_vec(),
                        );
                    }
                }
                // Set start of template name to now
                name_start = position;
            }
            if *byte == R_SQ_BRACKET {
                name_end = position + 1;
            }

            last_was_lf = *byte == LF;
            escape = *byte == ESCAPE;
        }
        // Because we add the definitions in the start of the new one, check for last in the end of file
        if name_end.checked_sub(name_start + 2).is_some() {
            if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
                // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
                let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                    newline_size
                } else if file.get(name_end) == Some(&SPACE) {
                    1
                } else {
                    0
                };
                templates.insert(
                    name.to_owned(),
                    file[name_end + add_after_name..file.len() - newline_size].to_vec(),
                );
            }
        }
        templates
    }
}

#[cfg(feature = "reverse-proxy")]
pub mod reverse_proxy {
    use kvarn::prelude::{internals::*, *};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::{TcpStream, UdpSocket, UnixStream};

    pub use async_bits::{poll_fn, CopyBuffer};
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
                            return Poll::Ready(Ok(false))
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
        pub fn poll_fn<T, F>(f: F) -> PollFn<F>
        where
            F: FnMut(&mut Context<'_>) -> Poll<T>,
        {
            PollFn { f }
        }
        pub struct PollFn<F> {
            f: F,
        }
        impl<F> Unpin for PollFn<F> {}
        impl<F> fmt::Debug for PollFn<F> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("PollFn").finish()
            }
        }
        impl<T, F> Future for PollFn<F>
        where
            F: FnMut(&mut Context<'_>) -> Poll<T>,
        {
            type Output = T;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
                (&mut self.f)(cx)
            }
        }
    }

    macro_rules! socket_addr_with_port {
        ($($port:literal $(,)+)*) => {
            &[
                $(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, $port)),)*
            ]
        };
    }

    #[derive(Debug, Clone, Copy)]
    pub enum Connection {
        Tcp(SocketAddr),
        /// Keep in mind, this currently has a `60s` timeout.
        /// Please use [`Self::UnixSocket`]s instead if you are on Unix.
        Udp(SocketAddr),
        #[cfg(unix)]
        UnixSocket(&'static Path),
    }
    impl Connection {
        pub async fn establish(self) -> io::Result<EstablishedConnection> {
            match self {
                Self::Tcp(addr) => TcpStream::connect(addr)
                    .await
                    .map(EstablishedConnection::Tcp),
                Self::Udp(addr) => {
                    let candidates = &socket_addr_with_port!(
                        17448, 64567, 40022, 56654, 52027, 44328, 29973, 27919, 26513, 42327,
                        64855, 5296, 52942, 43204, 15322, 13243,
                    )[..];
                    let socket = UdpSocket::bind(candidates).await?;
                    socket.connect(addr).await?;
                    /* UdpSocket::connect(&self, UDP_CANDIDATES) */
                    Ok(EstablishedConnection::Udp(socket))
                }
                Self::UnixSocket(path) => UnixStream::connect(path)
                    .await
                    .map(EstablishedConnection::UnixSocket),
            }
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
    pub enum EstablishedConnection {
        Tcp(TcpStream),
        Udp(UdpSocket),
        #[cfg(unix)]
        UnixSocket(UnixStream),
    }
    impl AsyncWrite for EstablishedConnection {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            match self.get_mut() {
                Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
                Self::Udp(s) => Pin::new(s).poll_send(cx, buf),
                Self::UnixSocket(s) => Pin::new(s).poll_write(cx, buf),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            match self.get_mut() {
                Self::Tcp(s) => Pin::new(s).poll_flush(cx),
                Self::Udp(_) => Poll::Ready(Ok(())),
                Self::UnixSocket(s) => Pin::new(s).poll_flush(cx),
            }
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            match self.get_mut() {
                Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
                Self::Udp(_) => Poll::Ready(Ok(())),
                Self::UnixSocket(s) => Pin::new(s).poll_shutdown(cx),
            }
        }
    }
    impl AsyncRead for EstablishedConnection {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
                Self::Udp(s) => Pin::new(s).poll_recv(cx, buf),
                Self::UnixSocket(s) => Pin::new(s).poll_read(cx, buf),
            }
        }
    }
    impl EstablishedConnection {
        pub async fn request<T: Debug>(
            &mut self,
            request: &Request<T>,
            body: &[u8],
        ) -> Result<Response<Bytes>, GatewayError> {
            pub fn read_to_end(buffer: &mut BytesMut, mut reader: impl Read) -> io::Result<()> {
                let mut read = buffer.len();
                // This is safe because of the trailing unsafe block.
                unsafe { buffer.set_len(buffer.capacity()) };
                loop {
                    match reader.read(&mut buffer[read..])? {
                        0 => break,
                        len => {
                            read += len;
                            if read > buffer.len() - 512 {
                                buffer.reserve(2048);
                                // This is safe because of the trailing unsafe block.
                                unsafe { buffer.set_len(buffer.capacity()) };
                            }
                        }
                    }
                }
                // I have counted the length in `read`. It will *not* include uninitiated bytes.
                unsafe { buffer.set_len(read) };
                Ok(())
            }

            let mut buffered = tokio::io::BufWriter::new(&mut *self);
            utility::write::request(request, body, &mut buffered).await?;

            debug!("Sent reverse-proxy bytes.");

            let response = match timeout(Duration::from_millis(1000), async {
                parse::response(&mut *self, 16 * 1024).await
            })
            .await
            {
                Ok(result) => match result {
                    Err(err) => return Err(err.into()),
                    Ok(response) => {
                        let chunked =
                            utility::header_eq(response.headers(), "transfer-encoding", "chunked");
                        let len = if chunked {
                            usize::MAX
                        } else {
                            utility::get_body_length_response(&response, Some(request.method()))
                        };

                        let (mut head, body) = utility::split_response(response);

                        let body = if len == 0 {
                            body
                        } else {
                            let mut buffer = BytesMut::with_capacity(body.len() + 512);
                            buffer.extend(&body);
                            if let Ok(result) = timeout(
                                Duration::from_millis(5000),
                                utility::read_to_end_or_max(&mut buffer, &mut *self, len),
                            )
                            .await
                            {
                                result?
                            } else if !chunked {
                                unsafe { buffer.set_len(0) };
                            }

                            if chunked {
                                let mut new_buffer = BytesMut::with_capacity(buffer.len());
                                let decoder = chunked_transfer::Decoder::new(&buffer[..]);
                                read_to_end(&mut new_buffer, decoder)?;
                                buffer = new_buffer;

                                utility::remove_all_headers(
                                    head.headers_mut(),
                                    "transfer-encoding",
                                );
                            }
                            buffer.freeze()
                        };

                        info!("Response {:#?}", head);
                        head.map(|()| body)
                    }
                },
                Err(_) => return Err(GatewayError::Timeout),
            };
            Ok(response)
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
                        $buf.poll_copy(cx, Pin::new($reader), Pin::new($writer)), $error
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
            poll_fn(|cx| self.poll_channel(cx)).await
        }
    }

    pub type ModifyRequestFn = Arc<dyn Fn(&mut FatRequest, &mut Bytes) + Send + Sync>;

    pub struct Manager {
        when: extensions::If,
        kind: Connection,
        modify: ModifyRequestFn,
    }
    impl Manager {
        pub fn new(when: extensions::If, kind: Connection, modify: ModifyRequestFn) -> Self {
            Self { when, kind, modify }
        }
        pub fn base(base_path: &str, kind: Connection) -> Self {
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
            let when = Box::new(move |request: &FatRequest| {
                let path = Arc::clone(&when_path);
                request.uri().path().starts_with(path.as_str())
            });

            let modify: Arc<dyn Fn(&mut FatRequest, &mut Bytes) + Send + Sync> = Arc::new(
                move |request, _| {
                    let path = Arc::clone(&path)/* &modify_path */;

                    let mut parts = request.uri().clone().into_parts();

                    if let Some(path_and_query) = parts.path_and_query.as_ref() {
                        if let Some(s) = path_and_query.as_str().get(path.as_str().len() - 1..) {
                            // We know this is a good path and query; we've just removed the first x bytes.
                            // The -1 will always be on a char boundary; the last character is always '/'
                            let short = uri::PathAndQuery::from_maybe_shared(
                                Bytes::copy_from_slice(s.as_bytes()),
                            )
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
                },
            );

            Self { when, kind, modify }
        }
        pub fn mount(self, extensions: &mut Extensions) {
            let connection = self.kind;
            let modify = self.modify;

            macro_rules! return_status {
                ($result:expr, $status:expr, $host:expr) => {
                    match $result {
                        Ok(v) => v,
                        Err(_) => {
                            return default_error_response($status, $host, None).await;
                        }
                    }
                };
            }

            extensions.add_prepare_fn(
                self.when,
                prepare!(req, host, _path, _addr, move |modify| {
                    let mut connection = return_status!(
                        connection.establish().await,
                        StatusCode::GATEWAY_TIMEOUT,
                        host
                    );

                    let mut bytes = return_status!(
                        req.body_mut().read_to_bytes().await,
                        StatusCode::BAD_GATEWAY,
                        host
                    );

                    utility::replace_header_static(
                        req.headers_mut(),
                        "accept-encoding",
                        "identity",
                    );

                    if req.headers().get("connection")
                        == Some(&HeaderValue::from_static("keep-alive"))
                    {
                        utility::replace_header_static(req.headers_mut(), "connection", "close");
                    }

                    *req.version_mut() = Version::HTTP_11;

                    let wait = matches!(req.method(), &Method::CONNECT)
                        || req.headers().get("upgrade")
                            == Some(&HeaderValue::from_static("websocket"));

                    modify(req, &mut bytes);

                    let mut response = match connection.request(req, &bytes).await {
                        Ok(mut response) => {
                            let headers = response.headers_mut();
                            utility::remove_all_headers(headers, "keep-alive");
                            if !utility::header_eq(headers, "connection", "upgrade") {
                                utility::remove_all_headers(headers, "connection");
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
                        let future = response_pipe_fut!(response_pipe, _host {
                            let udp_connection = matches!(connection, EstablishedConnection::Udp(_));

                            let mut open_back = ByteProxy::new(response_pipe, &mut connection);
                            debug!("Created open back!");

                            loop {
                                // Add 60 second timeout to UDP connections.
                                let timeout_result = if udp_connection {
                                    timeout(Duration::from_secs(90), open_back.channel())
                                    .await
                                }else {
                                    Ok(open_back.channel().await)
                                };

                                if let Ok(r) = timeout_result
                                {
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
                                        },
                                        Ok(()) => continue,
                                    }
                                } else {
                                    break;
                                }
                            }
                        });

                        response = response.with_future(future).with_compress(CompressPreference::None);
                    }

                    response
                }),
            );
        }
    }

    pub fn localhost(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }
}

/// Makes the client download the file.
pub fn download(mut data: PresentDataWrapper) -> RetFut<()> {
    let data = unsafe { data.get_inner() };
    let headers = data.response_mut().headers_mut();
    kvarn::utility::replace_header_static(headers, "content-type", "application/octet-stream");
    ready(())
}

pub fn cache(mut data: PresentDataWrapper) -> RetFut<()> {
    fn parse<'a, I: Iterator<Item = &'a str>>(
        iter: I,
    ) -> (Option<ClientCachePreference>, Option<ServerCachePreference>) {
        let mut c = None;
        let mut s = None;
        for arg in iter {
            let mut parts = arg.split(':');
            let domain = parts.next();
            let cache = parts.next();
            if let (Some(domain), Some(cache)) = (domain, cache) {
                match domain {
                    "client" => {
                        if let Ok(preference) = cache.parse() {
                            c = Some(preference)
                        }
                    }
                    "server" => {
                        if let Ok(preference) = cache.parse() {
                            s = Some(preference)
                        }
                    }
                    _ => {}
                }
            }
        }
        (c, s)
    }
    let data = unsafe { data.get_inner() };
    let preference = parse(data.args().iter());
    if let Some(c) = preference.0 {
        *data.client_cache_preference() = c;
    }
    if let Some(s) = preference.1 {
        *data.server_cache_preference() = s;
    }
    ready(())
}

pub fn hide(mut data: PresentDataWrapper) -> RetFut<()> {
    box_fut!({
        let data = unsafe { data.get_inner() };
        let error = default_error(StatusCode::NOT_FOUND, Some(data.host()), None).await;
        *data.response_mut() = error;
    })
}

pub fn ip_allow(mut data: PresentDataWrapper) -> RetFut<()> {
    box_fut!({
        let data = unsafe { data.get_inner() };
        let mut matched = false;
        // Loop over denied ip in args
        for denied in data.args().iter() {
            // If parsed
            if let Ok(ip) = denied.parse::<IpAddr>() {
                // check it against the requests IP.
                if data.address().ip() == ip {
                    matched = true;
                    // Then break out of loop
                    break;
                }
            }
        }
        *data.server_cache_preference() = kvarn::comprash::ServerCachePreference::None;
        *data.client_cache_preference() = kvarn::comprash::ClientCachePreference::Changing;

        if !matched {
            // If it does not match, set the response to 404
            let error = default_error(StatusCode::NOT_FOUND, Some(data.host()), None).await;
            *data.response_mut() = error;
        }
    })
}

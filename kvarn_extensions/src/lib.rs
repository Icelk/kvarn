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
    box_fut!({
        // If it is not HTTP/1
        #[allow(irrefutable_let_patterns)]
        if let ResponsePipe::Http1(_) = unsafe { &response_pipe.get_inner() } {
            return;
        }

        match str::from_utf8(&bytes) {
            // If it is HTML
            Ok(string) if bytes.starts_with(b"<!doctype HTML>") => {
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
                return (
                    utility::default_error(
                        StatusCode::BAD_REQUEST,
                        Some(host),
                        Some("failed to read body".as_bytes()),
                    )
                    .await,
                    ClientCachePreference::Changing,
                    ServerCachePreference::None,
                    CompressPreference::None,
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
            Ok(response) => (
                response,
                ClientCachePreference::Undefined,
                ServerCachePreference::None,
                CompressPreference::Full,
            ),
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

pub mod reverse_proxy {
    use kvarn::prelude::{internals::*, *};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::{TcpStream, UdpSocket, UnixStream};

    // use std::net::ToSocketAddr;
    // pub struct UdpCandidatesIter {
    //     index: usize,
    // }
    // impl UdpCandidatesIter {
    //     pub fn new() -> UdpCandidatesIter {
    //         Self { index: 0 }
    //     }
    // }
    // impl Iterator for UdpCandidatesIter {
    //     type Item = SocketAddr;
    //     fn next(&mut self) -> Option<Self::Item> {
    //         const ITEMS: &[u16] = &[
    //             17448, 64567, 40022, 56654, 52027, 44328, 29973, 27919, 26513, 42327, 64855, 5296,
    //             52942, 43204, 15322, 13243,
    //         ];
    //         let item = ITEMS.get(self.index).copied();
    //         self.index += 1;
    //         item.map(|port| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
    //     }
    // }
    // pub struct UdpCandidates();
    // impl ToSocketAddrs for UdpCandidates {
    //     type Iter = UdpCandidatesIter;
    //     fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
    //         Ok(UdpCandidatesIter::new())
    //     }
    // }

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
        pub async fn request<T>(
            &mut self,
            request: &Request<T>,
            body: &[u8],
        ) -> Result<Response<Bytes>, GatewayError> {
            let buffered = tokio::io::BufWriter::new(&mut *self);
            utility::write::request(request, body, buffered).await?;

            let response = match timeout(Duration::from_millis(1000), async move {
                parse::response(self, 16 * 1024).await
            })
            .await
            {
                Ok(result) => match result {
                    Err(err) => return Err(err.into()),
                    Ok(d) => d,
                },
                Err(_) => return Err(GatewayError::Timeout),
            };
            // let bytes = {
            //     let content_length = utility::get_content_length(&request);
            //     let mut buffer = BytesMut::with_capacity(bytes.len() + 512);
            //     buffer.extend(&bytes);
            //     let _ = timeout(
            //         Duration::from_millis(250),
            //         utility::read_to_end_or_max(&mut buffer, self, content_length),
            //     )
            //     .await;
            //     buffer.freeze()
            // };
            Ok(response)
        }
    }
    pub struct Manager {
        when: kvarn::extensions::If,
        kind: Connection,
        modify: Arc<dyn Fn(&mut Request<Bytes>) + Send + Sync>,
    }
    impl Manager {
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
                prepare!(req, host, path, addr, move |modify| {
                    let mut connection = return_status!(
                        connection.establish().await,
                        StatusCode::GATEWAY_TIMEOUT,
                        host
                    );

                    let bytes = return_status!(
                        req.body_mut().read_to_bytes().await,
                        StatusCode::BAD_GATEWAY,
                        host
                    );

                    todo!("Server cache! And replace request accept-encoding header to identity.");

                    match connection.request(req, &bytes).await {
                        Ok(response) => (
                            response,
                            ClientCachePreference::Undefined,
                            ServerCachePreference::None,
                            CompressPreference::Full,
                        ),
                        Err(err) => {
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
                    }
                }),
            );
        }
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

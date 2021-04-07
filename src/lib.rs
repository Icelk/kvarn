// #![warn(missing_docs, missing_debug_implementations, unreachable_pub)]

// Module declaration
pub mod application;
pub mod comprash;
pub mod encryption;
pub mod extensions;
pub mod host;
pub mod limiting;
pub mod parse;
pub mod prelude;
pub mod utility;

use prelude::{internals::*, networking::*, *};
// When user only imports crate::* and not crate::prelude::*
pub use comprash::{
    ClientCachePreference, CompressPreference, CompressedResponse, ServerCachePreference,
};
pub use extensions::Extensions;
pub use utility::{read_file, read_file_cached};
pub type FatRequest = Request<application::Body>;
pub type FatResponse = (
    Response<Bytes>,
    ClientCachePreference,
    ServerCachePreference,
    CompressPreference,
);
pub fn ready<T: 'static + Send>(value: T) -> RetFut<T> {
    Box::pin(core::future::ready(value))
}

#[cfg(target_os = "windows")]
pub const SERVER_HEADER: &str = "Kvarn/0.1.0 (Windows)";
#[cfg(target_os = "macos")]
pub const SERVER_HEADER: &str = "Kvarn/0.1.0 (macOS)";
#[cfg(target_os = "linux")]
pub const SERVER_HEADER: &str = "Kvarn/0.1.0 (Linux)";
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub const SERVER_HEADER: &str = "Kvarn/0.1.0 (unknown OS)";
pub const SERVER_NAME: &str = "Kvarn";

pub fn alpn() -> Vec<Vec<u8>> {
    #[allow(unused_mut)]
    let mut vec = Vec::with_capacity(4);
    #[cfg(feature = "http2")]
    {
        vec.push(b"h2".to_vec());
    }
    vec
}

macro_rules! ret_log_app_error {
    ($e:expr) => {
        match $e {
            Err(err) => {
                error!("An error occurred while sending a request. {:?}", &err);
                return Err(err.into());
            }
            Ok(val) => val,
        }
    };
}

pub(crate) async fn handle_connection(
    stream: TcpStream,
    address: SocketAddr,
    host_descriptors: Arc<HostDescriptor>,
    #[allow(unused_variables)] limiter: LimitWrapper,
) -> io::Result<()> {
    #[cfg(feature = "limiting")]
    let mut limiter = limiter;

    // LAYER 2
    #[cfg(feature = "https")]
    let encrypted =
        encryption::Encryption::new_tcp(stream, host_descriptors.server_config.as_ref()).await?;
    #[cfg(not(feature = "https"))]
    let encrypted = encryption::Encryption::new_tcp(stream);

    let version = match encrypted.get_alpn_protocol() {
        Some(b"h2") => Version::HTTP_2,
        None | Some(b"http/1.1") => Version::HTTP_11,
        Some(b"http/1.0") => Version::HTTP_10,
        Some(b"http/0.9") => Version::HTTP_09,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP version not supported",
            ))
        }
    };
    let hostname = encrypted.get_sni_hostname().map(str::to_string);
    // LAYER 3
    let mut http = application::HttpConnection::new(encrypted, version)
        .await
        .map_err::<io::Error, _>(application::Error::into)?;

    while let Ok((request, mut response_pipe)) = http
        .accept(
            host_descriptors
                .host_data
                .get_default()
                .host_name
                .as_bytes(),
        )
        .await
    {
        #[cfg(feature = "limiting")]
        match limiter.register(address).await {
            LimitStrength::Drop => return Ok(()),
            LimitStrength::Send => {
                let version = match response_pipe {
                    ResponsePipe::Http1(_) => Version::HTTP_11,
                    ResponsePipe::Http2(_) => Version::HTTP_2,
                };
                let (mut response, body) = utility::extract_body(limiting::get_too_many_requests());
                *response.version_mut() = version;
                let mut body_pipe =
                    ret_log_app_error!(response_pipe.send_response(response, false).await);
                ret_log_app_error!(body_pipe.send(body, true).await);
                continue;
            }
            LimitStrength::Passed => {}
        }
        let host = host_descriptors
            .host_data
            .smart_get(&request, hostname.as_ref().map(String::as_str));
        // fn to handle getting from cache, generating response and sending it
        handle_cache(request, address, SendKind::Send(&mut response_pipe), host).await?;
    }

    Ok(())
}

pub enum SendKind<'a> {
    Send(&'a mut application::ResponsePipe),
    Push(&'a mut application::PushedResponsePipe),
}
impl<'a> SendKind<'a> {
    pub fn ensure_version_and_length<T>(&self, response: &mut Response<T>, len: usize) {
        match self {
            Self::Send(p) => p.ensure_version_and_length(response, len),
            Self::Push(p) => p.ensure_version(response),
        }
    }
}

/// LAYER 4
pub async fn handle_cache(
    mut request: Request<application::Body>,
    address: SocketAddr,
    pipe: SendKind<'_>,
    host: &Host,
) -> io::Result<()> {
    let bad_path = request.uri().path().is_empty()
        || request.uri().path().contains("./")
        || request.uri().path().starts_with("//");
    match host.extensions.resolve_prime(&request, address).await {
        Some(uri) => *request.uri_mut() = uri,
        None => {}
    }
    let path_query = comprash::UriKey::path_and_query(request.uri());

    let lock = host.response_cache.lock().await;
    let cached = path_query.call_all(|path| lock.get(path)).1;
    let future = match cached {
        Some(resp) => {
            info!("Found in cache!");
            let (mut response, body) = utility::extract_body(resp.clone_preferred());
            let identity_body = Bytes::clone(resp.get_identity().body());
            drop(lock);

            pipe.ensure_version_and_length(&mut response, body.len());
            host.extensions
                .resolve_package(&mut response, &request)
                .await;

            match pipe {
                SendKind::Send(response_pipe) => {
                    // Send response
                    let mut body_pipe =
                        ret_log_app_error!(response_pipe.send_response(response, false).await);

                    // Send body
                    ret_log_app_error!(body_pipe.send(body, false).await);

                    // Process post extensions
                    host.extensions
                        .resolve_post(&request, identity_body, response_pipe, address, host)
                        .await;

                    // Close the pipe.
                    ret_log_app_error!(body_pipe.close().await);
                }
                SendKind::Push(push_pipe) => {
                    // Send response
                    let mut body_pipe =
                        ret_log_app_error!(push_pipe.send_response(response, false));

                    // Send body
                    ret_log_app_error!(body_pipe.send(body, true).await);
                }
            }
            None
        }
        None => {
            drop(lock);
            let path_query = comprash::PathQuery::from_uri(request.uri());
            // LAYER 5.1
            let ((resp, client_cache, server_cache, compress), future) = match bad_path {
                false => match host.extensions.resolve_pre(&mut request, host).await {
                    Some((response, future)) => (response, Some(future)),
                    None => {
                        let path = parse::convert_uri(
                            request.uri().path(),
                            host.path.as_path(),
                            host.get_folder_default_or("index.html"),
                            host.get_extension_default_or("html"),
                        );
                        let (mut resp, client_cache, server_cache, compress) =
                            handle_request(&mut request, address, host, &path).await?;

                        host.extensions
                            .resolve_present(
                                &mut request,
                                &mut resp,
                                client_cache,
                                server_cache,
                                host,
                                address,
                                path.as_path(),
                            )
                            .await?;
                        ((resp, client_cache, server_cache, compress), None)
                    }
                },
                true => (
                    utility::default_error_response(StatusCode::BAD_REQUEST, host).await,
                    None,
                ),
            };

            let extension = match Path::new(request.uri().path())
                .extension()
                .and_then(|s| s.to_str())
            {
                Some(ext) => ext,
                None => match host.extension_default.as_ref() {
                    Some(ext) => ext.as_str(),
                    None => "",
                },
            };
            let compressed_response =
                comprash::CompressedResponse::new(resp, compress, client_cache, extension);

            let (mut response, body) = utility::extract_body(compressed_response.clone_preferred());

            pipe.ensure_version_and_length(&mut response, body.len());
            host.extensions
                .resolve_package(&mut response, &request)
                .await;

            let identity_body = Bytes::clone(compressed_response.get_identity().body());

            async fn maybe_cache(
                host: &Host,
                server_cache: ServerCachePreference,
                path_query: PathQuery,
                response: CompressedResponse,
                future: &Option<RetSyncFut<()>>,
            ) {
                if future.is_none() {
                    if server_cache.cache() {
                        let mut lock = host.response_cache.lock().await;
                        let key = match server_cache.query_matters() {
                            true => comprash::UriKey::PathQuery(path_query),
                            false => comprash::UriKey::Path(path_query.into_path()),
                        };
                        info!("Caching uri {:?}!", &key);
                        lock.cache(key, response);
                    }
                } else {
                    info!("Not caching; a Pre extension has captured. If we cached, it would not be called again.");
                }
            };

            match pipe {
                SendKind::Send(response_pipe) => {
                    let mut pipe =
                        ret_log_app_error!(response_pipe.send_response(response, false).await);
                    ret_log_app_error!(pipe.send(body, false).await);

                    maybe_cache(host, server_cache, path_query, compressed_response, &future).await;

                    // process response push
                    host.extensions
                        .resolve_post(&request, identity_body, response_pipe, address, host)
                        .await;
                    ret_log_app_error!(pipe.close().await);
                }
                SendKind::Push(push_pipe) => {
                    let mut pipe = ret_log_app_error!(push_pipe.send_response(response, false));
                    ret_log_app_error!(pipe.send(body, true).await);

                    maybe_cache(host, server_cache, path_query, compressed_response, &future).await;
                }
            }
            future
        }
    };
    if let Some(future) = future {
        future.await;
    }
    Ok(())
}

/// LAYER 5.1
pub(crate) async fn handle_request(
    request: &mut Request<application::Body>,
    address: net::SocketAddr,
    host: &Host,
    path: &PathBuf,
) -> io::Result<FatResponse> {
    let mut response = None;
    let mut client_cache = None;
    let mut server_cache = None;
    let mut compress = None;

    {
        if let Some(resp) = host
            .extensions
            .resolve_prepare(request, &host, path.as_path(), address)
            .await
        {
            response.replace(resp.0);
            client_cache.replace(resp.1);
            server_cache.replace(resp.2);
            compress.replace(resp.3);
        }
    }

    #[cfg(feature = "fs")]
    if response.is_none() {
        if let Some(content) = utility::read_file(&path, &host.file_cache).await {
            response = Some(Response::new(content));
        }
    }

    let response = match response {
        Some(r) => r,
        None => {
            utility::default_error_response(StatusCode::NOT_FOUND, host)
                .await
                .0
        }
    };

    Ok((
        response,
        client_cache.unwrap_or(ClientCachePreference::Full),
        server_cache.unwrap_or(ServerCachePreference::Full),
        compress.unwrap_or(CompressPreference::Full),
    ))
}

pub struct HostDescriptor {
    port: u16,
    #[cfg(feature = "https")]
    server_config: Option<Arc<rustls::ServerConfig>>,
    host_data: Arc<HostData>,
}
impl HostDescriptor {
    pub fn http(host: Arc<HostData>) -> Self {
        Self {
            port: 80,
            #[cfg(feature = "https")]
            server_config: None,
            host_data: host,
        }
    }
    #[cfg(feature = "https")]
    pub fn https(host: Arc<HostData>, server_config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            port: 443,
            server_config: Some(server_config),
            host_data: host,
        }
    }
    #[cfg(feature = "https")]
    pub fn new(
        port: u16,
        host_data: Arc<HostData>,
        server_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            port,
            server_config,
            host_data,
        }
    }
    #[cfg(not(feature = "https"))]
    pub fn new(port: u16, host_data: Arc<HostData>) -> Self {
        Self { port, host_data }
    }
}
impl Debug for HostDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("HostDescriptor");
        s.field("port", &self.port);

        #[cfg(feature = "https")]
        s.field(
            "server_config",
            &self
                .server_config
                .as_ref()
                .map(|_| utility::CleanDebug::new("certificate")),
        );

        s.field("host_data", &self.host_data).finish()
    }
}

#[derive(Debug)]
pub struct Config {
    descriptors: Vec<HostDescriptor>,
}
impl Config {
    pub fn new(descriptors: Vec<HostDescriptor>) -> Self {
        Config { descriptors }
    }

    pub async fn run(self) {
        trace!("Running from config");

        let len = self.descriptors.len();
        for (pos, descriptor) in self.descriptors.into_iter().enumerate() {
            let listener = TcpListener::bind(net::SocketAddrV4::new(
                net::Ipv4Addr::UNSPECIFIED,
                descriptor.port,
            ))
            .await
            .expect("Failed to bind to port");

            let future = async move {
                Self::accept(listener, descriptor)
                    .await
                    .expect("Failed to accept message!")
            };

            if pos + 1 == len {
                future.await;
            } else {
                tokio::spawn(future);
            }
        }
    }

    async fn accept(listener: TcpListener, host: HostDescriptor) -> Result<(), io::Error> {
        trace!("Started listening on {:?}", listener.local_addr());
        let host = Arc::new(host);

        #[allow(unused_mut)]
        let mut limiter = LimitWrapper::default();

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    #[cfg(feature = "limiting")]
                    match limiter.register(addr).await {
                        LimitStrength::Drop => {
                            drop(socket);
                            return Ok(());
                        }
                        LimitStrength::Send | LimitStrength::Passed => {}
                    }
                    let host = Arc::clone(&host);
                    let limiter = LimitWrapper::clone(&limiter);
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(socket, addr, host, limiter).await {
                            warn!(
                                "An error occurred in the main processing function {:?}",
                                err
                            );
                        }
                    });
                    continue;
                }
                Err(err) => {
                    // An error occurred
                    error!("Failed to accept() on listener");

                    return Err(err);
                }
            }
        }
    }
}

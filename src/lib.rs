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
pub type FatRequest = http::Request<application::Body>;
pub type FatResponse = (
    http::Response<Bytes>,
    ClientCachePreference,
    ServerCachePreference,
    CompressPreference,
);

#[cfg(target_os = "windows")]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (Windows)\r\n";
#[cfg(target_os = "macos")]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (macOS)\r\n";
#[cfg(target_os = "linux")]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (Linux)\r\n";
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (unknown OS)\r\n";
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

pub(crate) async fn handle_connection(
    stream: TcpStream,
    address: SocketAddr,
    host_descriptors: Arc<HostDescriptor>,
) -> io::Result<()> {
    // LAYER 2
    let encrypted = encryption::Encryption::new_tcp_from_connection_security(
        stream,
        host_descriptors.server_config.as_ref(),
    )
    .await?;

    let version = match encrypted.get_alpn_protocol() {
        Some(b"h2") => http::Version::HTTP_2,
        None | Some(b"http/1.1") => http::Version::HTTP_11,
        Some(b"http/1.0") => http::Version::HTTP_10,
        Some(b"http/0.9") => http::Version::HTTP_09,
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
        let host = application::get_host(
            &request,
            hostname.as_ref().map(String::as_str),
            &host_descriptors.host_data,
        );
        // fn to handle getting from cache, generating response and sending it
        handle_cache(request, address, SendKind::Send(&mut response_pipe), host).await?;
    }

    Ok(())
}

pub enum SendKind<'a> {
    Send(&'a mut application::ResponsePipe),
    Push(&'a mut application::PushedResponsePipe),
}

/// LAYER 4
pub async fn handle_cache(
    mut request: http::Request<application::Body>,
    address: SocketAddr,
    pipe: SendKind<'_>,
    host: &Host,
) -> io::Result<()> {
    let path_query = comprash::UriKey::path_and_query(request.uri());

    let lock = host.response_cache.lock().await;
    let cached = path_query.call_all(|path| lock.get(path)).1;
    match cached {
        Some(resp) => {
            info!("Found in cache!");
            let body_response = resp.get_preferred();
            let response = utility::empty_clone_response(body_response);
            let response_body = Bytes::clone(body_response.body());
            let identity_body = Bytes::clone(resp.get_identity().body());
            drop(lock);

            match pipe {
                SendKind::Send(response_pipe) => {
                    let mut body_pipe = response_pipe
                        .send_response(response, false)
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;
                    body_pipe
                        .send(response_body, false)
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;
                    host.extensions
                        .resolve_post(&request, identity_body, response_pipe, address, host)
                        .await;
                    body_pipe
                        .close()
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;
                }
                SendKind::Push(push_pipe) => {
                    let mut body_pipe = push_pipe
                        .send_response(response, false)
                        .map_err::<io::Error, _>(application::Error::into)?;
                    body_pipe
                        .send(response_body, true)
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;
                }
            }
        }
        None => {
            drop(lock);
            let path_query = comprash::PathQuery::from_uri(request.uri());
            // LAYER 5.1
            let (resp, client_cache, server_cache, compress) = match parse::convert_uri(
                request.uri().path(),
                host.path.as_path(),
                host.get_folder_default_or("index.html"),
                host.get_extension_default_or("html"),
            ) {
                Some(path) => {
                    let (mut resp, client_cache, server_cache, compress) =
                        handle_request(&mut request, address, host, &path)
                            .await
                            .unwrap();

                    host.extensions
                        .resolve_present(
                            &request,
                            &mut resp,
                            client_cache,
                            server_cache,
                            host,
                            address,
                            path.as_path(),
                        )
                        .await;
                    (resp, client_cache, server_cache, compress)
                }
                None => utility::default_error_response(http::StatusCode::BAD_REQUEST, host).await,
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

            let response = compressed_response.get_preferred();

            let resp_no_body = utility::empty_clone_response(response);

            let identity_body = Bytes::clone(compressed_response.get_identity().body());
            async fn maybe_cache(
                host: &Host,
                server_cache: ServerCachePreference,
                path_query: PathQuery,
                response: CompressedResponse,
            ) {
                if server_cache.cache() {
                    let mut lock = host.response_cache.lock().await;
                    let key = match server_cache.query_matters() {
                        true => comprash::UriKey::PathQuery(path_query),
                        false => comprash::UriKey::Path(path_query.into_path()),
                    };
                    info!("Caching uri {:?}!", &key);
                    lock.cache(key, response);
                }
            };

            match pipe {
                SendKind::Send(response_pipe) => {
                    let mut pipe = response_pipe
                        .send_response(resp_no_body, false)
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;
                    pipe.send(Bytes::clone(response.body()), false)
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;

                    maybe_cache(host, server_cache, path_query, compressed_response).await;

                    // process response push
                    host.extensions
                        .resolve_post(&request, identity_body, response_pipe, address, host)
                        .await;
                    pipe.close()
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;
                }
                SendKind::Push(push_pipe) => {
                    let mut pipe = push_pipe
                        .send_response(resp_no_body, false)
                        .map_err::<io::Error, _>(application::Error::into)?;
                    pipe.send(Bytes::clone(response.body()), true)
                        .await
                        .map_err::<io::Error, _>(application::Error::into)?;

                    maybe_cache(host, server_cache, path_query, compressed_response).await;
                }
            }
        }
    }
    Ok(())
}

/// LAYER 5.1
pub(crate) async fn handle_request(
    _request: &mut http::Request<application::Body>,
    _address: net::SocketAddr,
    host: &Host,
    path: &PathBuf,
) -> io::Result<FatResponse> {
    #[allow(unused_mut)]
    let mut response = None;
    #[allow(unused_mut)]
    let mut client_cache = None;
    #[allow(unused_mut)]
    let mut server_cache = None;
    #[allow(unused_mut)]
    let mut compress = None;

    #[cfg(feature = "fs")]
    {
        match utility::read_file(&path, &host.file_cache).await {
            Some(resp) => response = Some(http::Response::new(resp)),
            None => {}
        }
    }

    let response = match response {
        Some(r) => r,
        None => {
            utility::default_error_response(http::StatusCode::NOT_FOUND, host)
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
    server_config: Option<Arc<rustls::ServerConfig>>,
    host_data: Arc<HostData>,
}
impl HostDescriptor {
    pub fn http(host: Arc<HostData>) -> Self {
        Self {
            port: 80,
            server_config: None,
            host_data: host,
        }
    }
    pub fn https(host: Arc<HostData>, server_config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            port: 443,
            server_config: Some(server_config),
            host_data: host,
        }
    }
    pub fn new(
        port: u16,
        host: Arc<HostData>,
        server_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            port,
            server_config,
            host_data: host,
        }
    }
}
impl Debug for HostDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostDescriptor")
            .field("port", &self.port)
            .field(
                "server_config",
                &self
                    .server_config
                    .as_ref()
                    .map(|_| utility::CleanDebug::new("certificate")),
            )
            .field("host_data", &self.host_data)
            .finish()
    }
}

pub struct Config {
    sockets: Vec<HostDescriptor>,
}
impl Config {
    pub fn new(descriptors: Vec<HostDescriptor>) -> Self {
        Config {
            sockets: descriptors,
        }
    }

    pub async fn run(self) {
        trace!("Running from config");

        let limiter = LimitWrapper::default();

        let len = self.sockets.len();
        for (pos, descriptor) in self.sockets.into_iter().enumerate() {
            let listener = TcpListener::bind(net::SocketAddrV4::new(
                net::Ipv4Addr::UNSPECIFIED,
                descriptor.port,
            ))
            .await
            .expect("Failed to bind to port");

            let limiter = limiter.clone();
            let future = async move {
                Self::accept(listener, descriptor, limiter)
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

    async fn accept(
        listener: TcpListener,
        host: HostDescriptor,
        mut limiter: LimitWrapper,
    ) -> Result<(), io::Error> {
        trace!("Started listening on {:?}", listener.local_addr());
        let host = Arc::new(host);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    #[cfg(feature = "limiting")]
                    match limiter.register(addr).await {
                        LimitStrength::Send | LimitStrength::Drop => {
                            drop(socket);
                            return Ok(());
                        }
                        LimitStrength::Passed => {}
                    }
                    let host = Arc::clone(&host);
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(socket, addr, host).await {
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
impl Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Config {{ sockets: {:?}, extensions }}", self.sockets)
    }
}

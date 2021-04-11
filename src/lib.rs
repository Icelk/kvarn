#![warn(unreachable_pub)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::inline_always, clippy::too_many_lines)]
//! An extensible and efficient forward-thinking web server for the future.
//!
//! Kvarn is a rethought web server tailored for the current needs from web application developers.
//!
//! It handles several things for you, including
//! - Content-Type
//! - Compression of body
//! - Correct and performant HTTP/1 and HTTP/2
//! - Common API across HTTP/1 and HTTP/2
//! - Easy integration with HTTP/2 push promises
//! - Six types of extensions, all backed with intuitive macros
//! - Optional encryption with [`rustls`]
//! - Several checks for illegal requests
//!
//!
//! # Getting started
//!
//! The main function to call is [`run`]. See the example at [`run`]
//! on how to get a simple web server running.
//!
//! A battle-tested reference implementation can be found at [GitHub](https://github.com/Iselk/kvarn-reference/).
//! It powers my two websites with minimal resource requirements.
//!
//!
//! # Future plans
//!
//! See the [README @ GitHub](https://github.com/Iselk/kvarn/) and [kvarn.org](https://kvarn.org).

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
/// The `Request` used within Kvarn.
pub type FatRequest = Request<application::Body>;
/// A `Response` returned by [`handle_request()`].
///
/// Contains all preference information to the lower-level
/// functions. Most things like `content-length`, `content-encoding`,
/// `content-type`, `cache-control`, and server caching will be
/// automatically handled.
pub type FatResponse = (
    Response<Bytes>,
    ClientCachePreference,
    ServerCachePreference,
    CompressPreference,
);

/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "windows")]
pub const SERVER: &str = "Kvarn/0.2.0 (Windows)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "macos")]
pub const SERVER: &str = "Kvarn/0.2.0 (macOS)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "linux")]
pub const SERVER: &str = "Kvarn/0.2.0 (Linux)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "freebsd")]
pub const SERVER: &str = "Kvarn/0.2.0 (FreeBSD)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd"
)))]
pub const SERVER: &str = "Kvarn/0.2.0 (unknown OS)";

/// All the supported ALPN protocols.
///
/// **Note:** this is often not needed, as the ALPN protocols
/// are set in [`host::Data::make_config()`].
#[must_use]
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

/// Handles a single connection. This includes encrypting it, extracting the HTTP header information,
/// optionally (HTTP/2 & HTTP/3) decompressing them, and passing the request to [`handle_cache()`].
/// It will also recognise which host should handle the connection.
///
///
/// # Errors
///
/// Will pass any errors from reading the request, making a TLS handshake, and writing the response.
/// See [`handle_cache()`] and [`handle_request()`]; errors from them are passed up, through this fn.
pub async fn handle_connection(
    stream: TcpStream,
    address: SocketAddr,
    host_descriptors: Arc<PortDescriptor>,
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
            .smart_get(&request, hostname.as_deref());
        // fn to handle getting from cache, generating response and sending it
        handle_cache(request, address, SendKind::Send(&mut response_pipe), host).await?;
    }

    Ok(())
}

/// How to send data to the client.
///
/// Most often, this is `Send`, but when a push promise is created,
/// this will be `Push`. This can be used by [`extensions::Post`].
#[derive(Debug)]
pub enum SendKind<'a> {
    /// Send the response normally.
    Send(&'a mut application::ResponsePipe),
    /// Send the response as a HTTP/2 push.
    Push(&'a mut application::PushedResponsePipe),
}
impl<'a> SendKind<'a> {
    /// Ensures correct version and length (only applicable for HTTP/1 connections)
    /// of a response according to inner enum variants.
    #[inline(always)]
    pub fn ensure_version_and_length<T>(
        &self,
        response: &mut Response<T>,
        len: usize,
        method: &Method,
    ) {
        match self {
            Self::Send(p) => p.ensure_version_and_length(response, len, method),
            Self::Push(p) => p.ensure_version(response),
        }
    }
}

/// Will handle a single request, check the cache, process if needed, and caches it.
/// This is where the response is sent.
///
///
/// # Errors
///
/// Errors are passed from writing the response.
///
///
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
    host.extensions
        .resolve_prime(&mut request, host, address)
        .await;

    let path_query = comprash::UriKey::path_and_query(request.uri());

    let lock = host.response_cache.lock().await;
    let cached = path_query.call_all(|path| lock.get(path)).1;
    #[allow(clippy::single_match_else)]
    let future = match cached {
        Some(resp) => {
            info!("Found in cache!");
            let (mut response, body) =
                utility::extract_body(match resp.clone_preferred(&request) {
                    Err(code) => utility::default_error(code, Some(host)).await,
                    Ok(response) => response,
                });
            let identity_body = Bytes::clone(resp.get_identity().body());
            drop(lock);

            pipe.ensure_version_and_length(&mut response, body.len(), request.method());
            host.extensions
                .resolve_package(&mut response, &request)
                .await;

            match pipe {
                SendKind::Send(response_pipe) => {
                    // Send response
                    let mut body_pipe =
                        ret_log_app_error!(response_pipe.send_response(response, false).await);

                    if utility::method_has_response_body(request.method()) {
                        // Send body
                        ret_log_app_error!(body_pipe.send(body, false).await);
                    }

                    // Process post extensions
                    host.extensions
                        .resolve_post(&request, identity_body, response_pipe, address, host)
                        .await;

                    // Close the pipe.
                    ret_log_app_error!(body_pipe.close().await);
                }
                SendKind::Push(push_pipe) => {
                    let send_body = utility::method_has_response_body(request.method());
                    // Send response
                    let mut body_pipe =
                        ret_log_app_error!(push_pipe.send_response(response, !send_body));
                    if send_body {
                        // Send body
                        ret_log_app_error!(body_pipe.send(body, true).await);
                    }
                }
            }
            None
        }
        None => {
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
                        let key = if server_cache.query_matters() {
                            comprash::UriKey::PathQuery(path_query)
                        } else {
                            comprash::UriKey::Path(path_query.into_path())
                        };
                        info!("Caching uri {:?}!", &key);
                        lock.cache(key, response);
                    }
                } else {
                    info!("Not caching; a Pre extension has captured. If we cached, it would not be called again.");
                }
            };

            drop(lock);
            let path_query = comprash::PathQuery::from_uri(request.uri());
            // LAYER 5.1
            let ((resp, client_cache, server_cache, compress), future) = if bad_path {
                (
                    utility::default_error_response(StatusCode::BAD_REQUEST, host).await,
                    None,
                )
            } else if let Some((response, future)) = host
                .extensions
                .resolve_pre(&mut request, host, address)
                .await
            {
                (response, Some(future))
            } else {
                let path = parse::uri(request.uri().path(), host.path.as_path());
                let (mut resp, mut client_cache, mut server_cache, compress) =
                    handle_request(&mut request, address, host, &path).await?;

                host.extensions
                    .resolve_present(
                        &mut request,
                        &mut resp,
                        &mut client_cache,
                        &mut server_cache,
                        host,
                        address,
                        path.as_path(),
                    )
                    .await?;
                ((resp, client_cache, server_cache, compress), None)
            };

            let extension = match Path::new(request.uri().path())
                .extension()
                .and_then(std::ffi::OsStr::to_str)
            {
                Some(ext) => ext,
                None => match host.extension_default.as_ref() {
                    Some(ext) => ext.as_str(),
                    None => "",
                },
            };
            let compressed_response =
                comprash::CompressedResponse::new(resp, compress, client_cache, extension);

            let (mut response, body) =
                utility::extract_body(match compressed_response.clone_preferred(&request) {
                    Err(code) => utility::default_error(code, Some(host)).await,
                    Ok(response) => response,
                });

            pipe.ensure_version_and_length(&mut response, body.len(), request.method());
            host.extensions
                .resolve_package(&mut response, &request)
                .await;

            let identity_body = Bytes::clone(compressed_response.get_identity().body());

            match pipe {
                SendKind::Send(response_pipe) => {
                    let mut pipe =
                        ret_log_app_error!(response_pipe.send_response(response, false).await);
                    if utility::method_has_response_body(request.method()) {
                        ret_log_app_error!(pipe.send(body, false).await);
                    }

                    maybe_cache(host, server_cache, path_query, compressed_response, &future).await;

                    // process response push
                    host.extensions
                        .resolve_post(&request, identity_body, response_pipe, address, host)
                        .await;
                    ret_log_app_error!(pipe.close().await);
                }
                SendKind::Push(push_pipe) => {
                    let send_body = utility::method_has_response_body(request.method());
                    let mut pipe =
                        ret_log_app_error!(push_pipe.send_response(response, !send_body));
                    if send_body {
                        ret_log_app_error!(pipe.send(body, true).await);
                    }

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

/// Handles a single request and returns response with cache and compress preference.
///
///  
/// # Errors
///
/// ~~Will return any errors from reading from the body of `request`.~~ Currently, does not return any errors.
///
///  
/// LAYER 5.1
pub async fn handle_request(
    request: &mut Request<application::Body>,
    address: net::SocketAddr,
    host: &Host,
    path: &PathBuf,
) -> io::Result<FatResponse> {
    let mut response = None;
    let mut client_cache = None;
    let mut server_cache = None;
    let mut compress = None;

    #[allow(unused_mut)]
    let mut status = None;

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
        match request.method() {
            &Method::GET | &Method::HEAD => {
                if let Some(content) = utility::read_file(&path, &host.file_cache).await {
                    response = Some(Response::new(content));
                }
            }
            _ => status = Some(StatusCode::METHOD_NOT_ALLOWED),
        }
    }

    let response = match response {
        Some(r) => r,
        None => {
            utility::default_error_response(status.unwrap_or(StatusCode::NOT_FOUND), host)
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

/// Describes port, certificate, and host data for
/// a single port to bind.
#[derive(Clone)]
#[must_use]
pub struct PortDescriptor {
    port: u16,
    #[cfg(feature = "https")]
    server_config: Option<Arc<rustls::ServerConfig>>,
    host_data: Arc<Data>,
}
impl PortDescriptor {
    /// Uses the defaults for non-secure HTTP with `host_data`
    pub fn http(host_data: Arc<Data>) -> Self {
        Self {
            port: 80,
            #[cfg(feature = "https")]
            server_config: None,
            host_data,
        }
    }
    /// Uses the defaults for secure HTTP, HTTPS, with `host_data`.
    /// Gets a [`rustls::ServerConfig`] from [`Data::make_config()`].
    #[cfg(feature = "https")]
    pub fn https(host_data: Arc<Data>) -> Self {
        Self {
            port: 443,
            server_config: Some(Arc::new(Data::make_config(&host_data))),
            host_data,
        }
    }
    /// Creates a new descriptor for `port` with `host_data` and an optional [`rustls::ServerConfig`].
    #[cfg(feature = "https")]
    pub fn with_server_config(
        port: u16,
        host_data: Arc<Data>,
        server_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            port,
            server_config,
            host_data,
        }
    }
    /// Creates a new descriptor for `port` with `host_data`.
    /// If the feature `https` is enabled, a `rustls::ServerConfig` is created
    /// from the `host_data`.
    pub fn new(port: u16, host_data: Arc<Data>) -> Self {
        Self {
            port,
            #[cfg(feature = "https")]
            server_config: Some(Arc::new(Data::make_config(&host_data))),
            host_data,
        }
    }
    /// Creates a new non-secure descriptor for `port` with `host_data`.
    /// Does not try to assign a certificate.
    pub fn non_secure(port: u16, host_data: Arc<Data>) -> Self {
        Self {
            port,
            #[cfg(feature = "https")]
            server_config: None,
            host_data,
        }
    }
}
impl Debug for PortDescriptor {
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

/// Run the Kvarn web server on `ports`.
///
/// Will bind a [`TcpListener`] on every `port` in [`PortDescriptor`].
///
/// > This ↑ will change when HTTP/3 support arrives, then Udp will also be used.
///
/// This is the last step in getting Kvarn spinning.
/// You can interact with the caches through the [`Host`] and [`Data`] you created.
///
///
/// # Examples
///
/// Will start a bare-bones web server on port `8080`, using the dir `web` to serve files.
///
/// > **Note:** it uses `web` to serve files only if the feature `fs` is enabled. Place them in `web/public`
/// > to access them in your user-agent.
/// > It's done this way to enable you to have domain-specific files not being public to the web,
/// > and for a place to store other important files. `kvarn_extensions` template system would in this case
/// > read the template files from `web/templates`.
///
/// ```no_run
/// use kvarn::prelude::*;
///
/// # async move {
/// let host = Host::non_secure("localhost", PathBuf::from("web"), Extensions::default());
/// let data = Data::builder(host).build();
/// let port_descriptor = PortDescriptor::new(8080, data);
///
/// run(vec![port_descriptor]).await;
/// # };
/// ```
pub async fn run(ports: Vec<PortDescriptor>) {
    info!("Starting server on {} ports.", ports.len());

    let len = ports.len();
    for (pos, descriptor) in ports.into_iter().enumerate() {
        let listener = TcpListener::bind(net::SocketAddrV4::new(
            net::Ipv4Addr::UNSPECIFIED,
            descriptor.port,
        ))
        .await
        .expect("Failed to bind to port");

        let future = async move {
            accept(listener, descriptor)
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

async fn accept(listener: TcpListener, descriptor: PortDescriptor) -> Result<(), io::Error> {
    trace!("Started listening on {:?}", listener.local_addr());
    let host = Arc::new(descriptor);

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

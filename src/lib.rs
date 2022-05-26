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
//! - Five types of extensions, all backed with intuitive macros
//! - Optional encryption with [`rustls`](https://docs.rs/rustls)
//! - Several checks for illegal requests
//! - [`cache-control`](parse::CacheControl::from_cache_control) and [`kvarn-cache-control`](parse::CacheControl::from_kvarn_cache_control) header limits server cache lifetimes
//!
//! # Getting started
//!
//! To get started, configure a [`RunConfig`]. See the example at [`RunConfig::execute`]
//! on how to get a simple web server running.
//!
//! A battle-tested reference implementation can be found at [GitHub](https://github.com/Icelk/kvarn-reference/).
//! It powers my two websites with minimal resource requirements.
//!
//! # Future plans
//!
//! See the [README @ GitHub](https://github.com/Icelk/kvarn/) and [kvarn.org](https://kvarn.org).
// See https://doc.rust-lang.org/beta/unstable-book/language-features/doc-cfg.html & https://github.com/rust-lang/rust/pull/89596
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    unreachable_pub,
    missing_debug_implementations,
    missing_docs,
    clippy::pedantic
)]
#![allow(
    // I WANT A LONG fn!
    clippy::too_many_lines,
    // I know what I'm doing with unwraps. They should all be motivated.
    clippy::missing_panics_doc,
    // When a parameter of a function is prefixed due to `#[cfg]` in an fn.
    clippy::used_underscore_binding,
    // Same as ↑.
    clippy::unused_self,
    // When a enum variant has been conditionally compiled away.
    irrefutable_let_patterns,
)]
#![doc(html_favicon_url = "https://kvarn.org/favicon.svg")]
#![doc(html_logo_url = "https://kvarn.org/logo.svg")]
#![doc(html_root_url = "https://doc.kvarn.org/")]

// Module declaration
pub mod application;
pub mod comprash;
pub mod cors;
pub mod csp;
pub mod ctl;
pub mod encryption;
pub mod error;
pub mod extensions;
pub mod host;
pub mod limiting;
pub mod prelude;
pub mod read;
pub mod shutdown;
pub mod vary;

use prelude::{chrono::*, internals::*, networking::*, *};
// When user only imports kvarn::* and not kvarn::prelude::*
pub use error::{default as default_error, default_response as default_error_response};
pub use extensions::{Extensions, Id};
pub use read::{file as read_file, file_cached as read_file_cached};

/// Configuration for [`Self::execute`].
/// This mainly consists of an array of [`PortDescriptor`]s.
///
/// It also allows control of [handover](https://kvarn.org/shutdown-handover.).
///
/// Will bind a [`TcpListener`] on every `port` added using [`Self::bind`]
///
/// > This ↑ will change when HTTP/3 support arrives, then Udp will also be used.
///
/// # Examples
///
/// See [`Self::execute`] as it uses this, created by a macro invocation.
///
/// ```
/// # use kvarn::prelude::*;
/// # async {
/// let host = Host::unsecure("localhost", PathBuf::from("web"), Extensions::default(), host::Options::default());
/// let data = HostCollection::builder().insert(host).build();
/// let port_descriptor = PortDescriptor::new(8080, data);
///
/// let config = RunConfig::new()
///     .bind(port_descriptor)
///     .set_ctl_path("/run/kvarn-instance-1.sock");
/// config.execute().await.shutdown();
/// # };
/// ```
#[derive(Debug)]
#[must_use = "must start a server if creating a config"]
pub struct RunConfig {
    ports: Vec<PortDescriptor>,
    ctl: bool,
    ctl_path: Option<PathBuf>,

    plugins: ctl::Plugins,
}
impl RunConfig {
    /// Creates an empty [`RunConfig`].
    pub fn new() -> Self {
        RunConfig {
            ports: vec![],
            ctl: true,
            ctl_path: None,

            plugins: ctl::Plugins::default(),
        }
    }

    /// Adds a [`PortDescriptor`] to the Kvarn server.
    pub fn bind(mut self, port: PortDescriptor) -> Self {
        self.ports.push(port);
        self
    }
    /// Disables [handover](https://kvarn.org/shutdown-handover.)
    /// and [ctl](https://kvarn.org/ctl/)
    /// for the instance of Kvarn.
    ///
    /// This can enable multiple Kvarn servers to run on the same machine.
    pub fn disable_ctl(mut self) -> Self {
        self.ctl = false;
        self
    }
    /// Sets the path of the socket where the [handover](https://kvarn.org/shutdown-handover.)
    /// and [ctl](https://kvarn.org/ctl/) is managed.
    ///
    /// By default, this is `/run/user/<uid>/kvarn.sock` for users and `/run/kvarn.sock` for root
    /// users.
    ///
    /// This can enable multiple Kvarn servers to run on the same machine.
    /// If each application (as in an use for Kvarn) has it's own path, multiple can coexist.
    pub fn set_ctl_path(mut self, path: impl AsRef<Path>) -> Self {
        self.ctl_path = Some(path.as_ref().to_path_buf());
        self
    }
    /// Add `plugin` to be executed when a command with `name` is received from `kvarnctl`.
    ///
    /// Adding multiple with the same name overrides the old one.
    ///
    /// See [`ctl::Plugins`] for the default [`ctl::Plugin`]s that are added.
    pub fn add_plugin(mut self, name: impl AsRef<str>, plugin: ctl::Plugin) -> Self {
        self.plugins.add_plugin(name, plugin);
        self
    }

    /// Run the Kvarn web server on `ports`.
    ///
    /// This is the last step in getting Kvarn spinning.
    /// You can interact with the caches through the [`Host`] and [`HostCollection`] you created, and
    /// the returned [`shutdown::Manager`], if you have the `graceful-shutdown` feature enabled.
    ///
    /// # Examples
    ///
    /// Will start a bare-bones web server on port `8080`, using the dir `web` to serve files.
    ///
    /// > **Note:** it uses `web` to serve files only if the feature `fs` is enabled. Place them in `web/public`
    /// > to access them in your user-agent.
    /// > It's done this way to enable you to have domain-specific files not being public to the web,
    /// > and for a place to store other important files. Kvarn extensions' template system will in this case
    /// > read template files from `web/templates`.
    ///
    /// ```no_run
    /// use kvarn::prelude::*;
    ///
    /// # async {
    /// // Create a host with hostname "localhost", serving files from directory "./web/public/", with the default extensions and the default options.
    /// let host = Host::unsecure("localhost", PathBuf::from("web"), Extensions::default(), host::Options::default());
    /// // Create a set of virtual hosts (`HostCollection`) with `host` as the default.
    /// let data = HostCollection::builder().insert(host).build();
    /// // Bind port 8080 with `data`.
    /// let port_descriptor = PortDescriptor::new(8080, data);
    ///
    /// // Run with the configured ports.
    /// let shutdown_manager = run_config![port_descriptor].execute().await;
    /// // Waits for shutdown.
    /// shutdown_manager.wait().await;
    /// # };
    /// ```
    pub async fn execute(self) -> Arc<shutdown::Manager> {
        let RunConfig {
            ports,
            ctl,
            ctl_path,
            plugins,
        } = self;
        info!("Starting server on {} ports.", ports.len());

        let len = ports.len();
        let mut shutdown_manager = shutdown::Manager::new(len);

        let ports_clone = Arc::new(ports.clone());

        let mut listeners = Vec::with_capacity(len * 2);
        for descriptor in ports {
            fn create_listener(
                create_socket: impl Fn() -> TcpSocket,
                address: SocketAddr,
                shutdown_manager: &mut shutdown::Manager,
            ) -> AcceptManager {
                let socket = create_socket();
                #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
                {
                    if socket.set_reuseaddr(true).is_err() || socket.set_reuseport(true).is_err() {
                        error!("Failed to set reuse address/port. This is needed for graceful shutdown handover.");
                    }
                }
                socket.bind(address).expect("Failed to bind address");

                let listener = socket
                    .listen(1024)
                    .expect("Failed to listen on bound address.");

                shutdown_manager.add_listener(listener)
            }

            // we later need this in an Arc
            let descriptor = Arc::new(descriptor);

            if matches!(descriptor.version, BindIpVersion::V4 | BindIpVersion::Both) {
                let listener = create_listener(
                    || {
                        TcpSocket::new_v4()
                            .expect("Failed to create a new IPv4 socket configuration")
                    },
                    SocketAddr::new(IpAddr::V4(net::Ipv4Addr::UNSPECIFIED), descriptor.port),
                    &mut shutdown_manager,
                );
                listeners.push((listener, Arc::clone(&descriptor)));
            }
            if matches!(descriptor.version, BindIpVersion::V6 | BindIpVersion::Both) {
                let listener = create_listener(
                    || {
                        TcpSocket::new_v6()
                            .expect("Failed to create a new IPv6 socket configuration")
                    },
                    SocketAddr::new(IpAddr::V6(net::Ipv6Addr::UNSPECIFIED), descriptor.port),
                    &mut shutdown_manager,
                );
                listeners.push((listener, descriptor));
            }
        }

        let shutdown_manager = shutdown_manager.build();

        if ctl {
            // make sure we shut down before listening
            #[cfg(any(
                not(feature = "graceful-shutdown"),
                target_os = "illumos",
                target_os = "solaris"
            ))]
            ctl::listen(
                plugins,
                ports_clone,
                Arc::clone(&shutdown_manager),
                ctl_path,
            )
            .await;
        }

        for (listener, descriptor) in listeners {
            let shutdown_manager = Arc::clone(&shutdown_manager);
            let future = async move {
                accept(listener, descriptor, &shutdown_manager)
                    .await
                    .expect("Failed to accept message!");
            };

            tokio::spawn(future);
        }
        if ctl {
            #[cfg(all(
                feature = "graceful-shutdown",
                not(target_os = "illumos"),
                not(target_os = "solaris")
            ))]
            ctl::listen(
                plugins,
                ports_clone,
                Arc::clone(&shutdown_manager),
                ctl_path,
            )
            .await;
        }

        shutdown_manager
    }
}
impl Default for RunConfig {
    fn default() -> Self {
        Self::new()
    }
}
/// Creates a [`RunConfig`] from [`PortDescriptor`]s.
/// This allows you to configure the [`RunConfig`] and then [`RunConfig::execute`] the server.
///
/// # Examples
///
/// ```
/// # use kvarn::prelude::*;
/// # let host = Host::unsecure("localhost", PathBuf::from("web"), Extensions::default(), host::Options::default());
/// # let data = HostCollection::builder().insert(host).build();
/// # let port1 = PortDescriptor::new(8080, Arc::clone(&data));
/// # let port2 = PortDescriptor::new(8081, data);
/// let server = run_config!(port1, port2);
#[macro_export]
macro_rules! run_config {
    ($($port_descriptor:expr),+ $(,)?) => {
        $crate::RunConfig::new()$(.bind($port_descriptor))+
    };
}

macro_rules! ret_log_app_error {
    ($e:expr) => {
        match $e {
            Err(err) => {
                if let application::Error::ClientRefusedResponse = &err {
                    return Ok(());
                }
                error!("An error occurred while sending a response. {:?}", &err);
                return Err(err.into());
            }
            Ok(val) => val,
        }
    };
}

async fn accept(
    mut listener: AcceptManager,
    descriptor: Arc<PortDescriptor>,
    shutdown_manager: &Arc<shutdown::Manager>,
) -> Result<(), io::Error> {
    trace!(
        "Started listening on {:?}",
        listener.get_inner().local_addr()
    );

    loop {
        match listener.accept(shutdown_manager).await {
            AcceptAction::Shutdown => {
                debug!("Closing listener.");
                return Ok(());
            }
            AcceptAction::Accept(result) => match result {
                Ok((socket, addr)) => {
                    match descriptor.data.limiter().register(addr.ip()) {
                        LimitAction::Drop => {
                            drop(socket);
                            return Ok(());
                        }
                        LimitAction::Send | LimitAction::Passed => {}
                    }

                    let descriptor = Arc::clone(&descriptor);

                    #[cfg(feature = "graceful-shutdown")]
                    let shutdown_manager = Arc::clone(shutdown_manager);
                    tokio::spawn(async move {
                        #[cfg(feature = "graceful-shutdown")]
                        shutdown_manager.add_connection();
                        let _result = handle_connection(socket, addr, descriptor, || {
                            #[cfg(feature = "graceful-shutdown")]
                            {
                                !shutdown_manager.get_shutdown(threading::Ordering::Relaxed)
                            }
                            #[cfg(not(feature = "graceful-shutdown"))]
                            {
                                true
                            }
                        })
                        .await;
                        #[cfg(feature = "graceful-shutdown")]
                        shutdown_manager.remove_connection();
                    });
                    continue;
                }
                Err(err) => {
                    // An error occurred
                    error!("Failed to accept() on listener");

                    return Err(err);
                }
            },
        }
    }
}

/// Handles a single connection. This includes encrypting it, extracting the HTTP header information,
/// optionally (HTTP/2 & HTTP/3) decompressing them, and passing the request to [`handle_cache()`].
/// It will also recognize which host should handle the connection.
///
/// Here, both [layer 2](https://kvarn.org/pipeline.#layer-2--encryption)
/// and [layer 3](https://kvarn.org/pipeline.#layer-3--http)
/// are handled.
///
/// # Errors
///
/// Will pass any errors from reading the request, making a TLS handshake, and writing the response.
/// See [`handle_cache()`] and [`handle_request()`]; errors from them are passed up, through this fn.
pub async fn handle_connection(
    stream: TcpStream,
    address: SocketAddr,
    descriptor: Arc<PortDescriptor>,
    mut continue_accepting: impl FnMut() -> bool,
) -> io::Result<()> {
    // LAYER 2
    #[cfg(feature = "https")]
    let encrypted = {
        encryption::Encryption::new_tcp(stream, descriptor.server_config.clone())
            .await
            .map_err(|err| match err {
                encryption::Error::Io(io) => io,
                encryption::Error::Tls(tls) => io::Error::new(io::ErrorKind::InvalidData, tls),
            })
    }?;
    #[cfg(not(feature = "https"))]
    let encrypted = encryption::Encryption::new_tcp(stream);

    let version =
        match encrypted.alpn_protocol() {
            Some(b"h2") => Version::HTTP_2,
            None | Some(b"http/1.1") => Version::HTTP_11,
            Some(b"http/1.0") => Version::HTTP_10,
            Some(b"http/0.9") => Version::HTTP_09,
            _ => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP version not supported. Something is probably wrong with your alpn config.",
            )),
        };
    let hostname = encrypted.sni_hostname().map(str::to_string);
    debug!("New connection requesting hostname '{:?}'", hostname);

    // LAYER 3
    let mut http = application::HttpConnection::new(encrypted, version)
        .await
        .map_err::<io::Error, _>(application::Error::into)?;

    info!("Accepting requests from {}", address);

    while let Ok((mut request, mut response_pipe)) = http
        .accept(
            descriptor
                .data
                .get_default()
                .map(|host| host.name.as_bytes()),
        )
        .await
    {
        debug!("We got a new request on connection.");
        trace!("Got request {:#?}", request);
        let host = if let Some(host) = descriptor
            .data
            .get_from_request(&request, hostname.as_deref())
        {
            host
        } else {
            info!(
                "Failed to get host: {}",
                utils::parse::Error::NoHost.as_str()
            );
            return Ok(());
        };

        match host.limiter.register(address.ip()) {
            LimitAction::Drop => return Ok(()),
            LimitAction::Send => {
                let (mut response, body) = utils::split_response(limiting::get_too_many_requests());
                response_pipe.ensure_version_and_length(&mut response, body.len());

                let mut body_pipe =
                    ret_log_app_error!(response_pipe.send_response(response, false).await);

                ret_log_app_error!(body_pipe.send_with_maybe_close(body, true).await);

                continue;
            }
            LimitAction::Passed => {}
        }
        debug!("Accepting new connection from {} on {}", address, host.name);

        // fn to handle getting from cache, generating response and sending it
        debug_assert!(descriptor.data.get_host(&host.name).is_some());
        // SAFETY: We know this host is part of the Collection, since we got the Host from the
        // Collection.
        // We also assure it's not dropped by cloning the arc below.
        let hostname = unsafe { utils::SuperUnsafePointer::new(&host.name) };
        let moved_host_collection = Arc::clone(&descriptor.data);
        let future = async move {
            // SAFETY: See above.
            let hostname = unsafe { hostname.get() };
            // UNWRAP: This host must be part of the Collection, as we got it from there.
            let host = moved_host_collection.get_host(hostname).unwrap();
            let response = handle_cache(&mut request, address, host).await;

            if let Err(err) = SendKind::Send(&mut response_pipe)
                .send(response, &request, host, address)
                .await
            {
                error!("Got error from writing response: {:?}", err);
            }
        };

        // When version is HTTP/1, we block the socket if we begin listening to it again.
        match version {
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => future.await,
            _ => {
                tokio::spawn(future);
            }
        }

        if !continue_accepting() {
            break;
        }
    }
    debug!("Connection finished.");

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
    #[inline]
    pub fn ensure_version_and_length<T>(&self, response: &mut Response<T>, len: usize) {
        match self {
            Self::Send(p) => p.ensure_version_and_length(response, len),
            Self::Push(p) => p.ensure_version(response),
        }
    }
    /// Sends the `response` to this pipe.
    ///
    /// # Errors
    ///
    /// returns any errors with sending the data.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &mut self,
        response: CacheReply,
        request: &FatRequest,
        host: &Host,
        address: SocketAddr,
    ) -> io::Result<()> {
        let CacheReply {
            mut response,
            identity_body,
            sanitize_data: data,
            future,
        } = response;

        if let Ok(data) = &data {
            match data.apply_to_response(&mut response).await {
                Err(SanitizeError::RangeNotSatisfiable) => {
                    response = default_error(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        Some(host),
                        Some(b"Range start after end of body"),
                    )
                    .await;
                }
                Err(SanitizeError::UnsafePath) => {
                    response = default_error(StatusCode::BAD_REQUEST, Some(host), None).await;
                }
                Ok(()) => {}
            }
        }

        let len = response.body().len();
        self.ensure_version_and_length(&mut response, len);

        let (mut response, body) = utils::split_response(response);

        host.extensions
            .resolve_package(&mut response, request, host)
            .await;

        match self {
            SendKind::Send(response_pipe) => {
                // Send response
                let mut body_pipe =
                    ret_log_app_error!(response_pipe.send_response(response, false).await);

                if utils::method_has_response_body(request.method()) || !body.is_empty() {
                    // Send body
                    ret_log_app_error!(body_pipe.send_with_maybe_close(body, false).await);
                }

                if let Some(mut future) = future {
                    future.call(&mut body_pipe, host).await;
                }

                // Process post extensions
                host.extensions
                    .resolve_post(request, identity_body, response_pipe, address, host)
                    .await;

                // Close the pipe.
                ret_log_app_error!(body_pipe.close().await);
            }
            SendKind::Push(push_pipe) => {
                let send_body =
                    utils::method_has_response_body(request.method()) || !body.is_empty();

                // Send response
                let mut body_pipe = ret_log_app_error!(
                    push_pipe.send_response(response, !send_body && future.is_none())
                );
                if send_body {
                    // Send body
                    ret_log_app_error!(
                        body_pipe
                            .send_with_maybe_close(body, future.is_none())
                            .await
                    );
                }
                if let Some(mut future) = future {
                    future.call(&mut body_pipe, host).await;
                }

                if !send_body {
                    ret_log_app_error!(body_pipe.close().await);
                }
            }
        }
        Ok(())
    }
}

/// The returned data from [`handle_cache`].
///
/// Can be used to get responses from Kvarn without sending a request over HTTP.
pub struct CacheReply {
    /// The response.
    /// Duh.
    pub response: Response<Bytes>,
    /// The response body without compression.
    pub identity_body: Bytes,
    /// The returned value from [`utils::sanitize_request()`].
    ///
    /// Internally used in [`SendKind`] to apply [`utils::CriticalRequestComponents`] to the response.
    pub sanitize_data: Result<utils::CriticalRequestComponents, SanitizeError>,
    /// Must be awaited.
    ///
    /// Can be used for WebSocket connections.
    pub future: Option<ResponsePipeFuture>,
    // also update Debug implementation when adding fields
}
impl Debug for CacheReply {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct(utils::ident_str!(CacheReply));

        utils::fmt_fields!(
            s,
            (self.response),
            (self.identity_body),
            (self.sanitize_data),
            (self.future, &"[internal future]".as_clean())
        );

        s.finish()
    }
}

mod handle_cache_helpers {
    use crate::prelude::*;

    /// Get a [`comprash::CompressedResponse`].
    ///
    /// Handles `sanitize_data` and present extensions.
    pub(super) async fn get_response(
        request: &mut FatRequest,
        host: &Host,
        sanitize_data: &Result<utils::CriticalRequestComponents, SanitizeError>,
        address: SocketAddr,
        overide_uri: Option<&Uri>,
    ) -> (
        comprash::CompressedResponse,
        comprash::ClientCachePreference,
        comprash::ServerCachePreference,
        Option<ResponsePipeFuture>,
        comprash::PathQuery,
    ) {
        let path_query = comprash::PathQuery::from(request.uri());
        let (mut resp, mut client_cache, mut server_cache, compress, future) =
            match sanitize_data {
                Ok(_) => {
                    let path = if host.options.disable_fs {
                        None
                    } else if let Ok(decoded) =
                        percent_encoding::percent_decode_str(request.uri().path()).decode_utf8()
                    {
                        Some(utils::make_path(
                            &host.path,
                            host.options
                                .public_data_dir
                                .as_deref()
                                .unwrap_or_else(|| Path::new("public")),
                            // Ok, since Uri's have to start with a `/` (https://github.com/hyperium/http/issues/465).
                            // We also are OK with all Uris, since we did a check on the
                            // incoming and presume all internal extension changes are good.
                            utils::parse::uri(&decoded).unwrap(),
                            None,
                        ))
                    } else {
                        warn!("Invalid percent encoding in path.");
                        None
                    };

                    handle_request(request, overide_uri, address, host, &path).await
                }
                Err(err) => error::sanitize_error_into_response(*err, host).await,
            }
            .into_parts();

        host.extensions
            .resolve_present(
                request,
                &mut resp,
                &mut client_cache,
                &mut server_cache,
                host,
                address,
            )
            .await;

        let extension = match Path::new(request.uri().path())
            .extension()
            .and_then(std::ffi::OsStr::to_str)
        {
            Some(ext) => ext,
            None => match host.options.extension_default.as_ref() {
                Some(ext) => ext.as_str(),
                None => "",
            },
        };
        (
            comprash::CompressedResponse::new(
                resp,
                compress,
                client_cache,
                extension,
                host.options.disable_client_cache,
            ),
            client_cache,
            server_cache,
            future,
            path_query,
        )
    }
    /// Cache `response` if allowed by the other arguments.
    ///
    /// Returns the `response` if it wasn't cached.
    pub(super) async fn maybe_cache<T>(
        host: &Host,
        server_cache: comprash::ServerCachePreference,
        path_query: PathQuery,
        response: VariedResponse,
        method: &Method,
        future: &Option<T>,
    ) -> Option<VariedResponse> {
        if future.is_none() {
            if let Some(response_cache) = &host.response_cache {
                // Call `host::Options::status_code_cache_filter`
                let cache_action = (host.options.status_code_cache_filter)(
                    response.first().0.get_identity().status(),
                );

                if server_cache.cache(cache_action, method) {
                    let mut lock = response_cache.write().await;
                    let key = if server_cache.query_matters() {
                        comprash::UriKey::PathQuery(path_query)
                    } else {
                        comprash::UriKey::Path(path_query.into_path())
                    };
                    info!("Caching uri {:?}!", &key);
                    lock.cache(key, response);
                    return None;
                }
            }
        } else {
            info!("Not caching; a Prepare extension has captured. If we cached, it would not be called again.");
        }
        Some(response)
    }
    pub(super) async fn handle_vary_missing(
        request: &mut FatRequest,
        host: &Host,
        sanitize_data: &Result<utils::CriticalRequestComponents, SanitizeError>,
        address: SocketAddr,
        overide_uri: Option<&Uri>,
        uri_key: UriKey,
        params: vary::CacheParams,
    ) -> (
        Arc<(comprash::CompressedResponse, vary::HeaderCollection)>,
        Option<extensions::ResponsePipeFuture>,
    ) {
        let (compressed_response, _, server_cache, future, path_query) =
            get_response(request, host, sanitize_data, address, overide_uri).await;

        let mut lock = if let Some(response_cache) = &host.response_cache {
            Some(response_cache.write().await)
        } else {
            None
        };
        // Try to get back varied response. If not there, recreate it, as the
        // match-arm below does.
        let cached = if let Some(lock) = &mut lock {
            {
                // inline `UriKey::call_all` because of annoying Rust semantics
                // regarding calling impl Fns. We also had to deal with this in
                // `kvarn::extensions`.
                match lock.get_mut_with_lifetime(&uri_key).into_option() {
                    Some(t) => (uri_key, Some(t)),
                    None => match uri_key {
                        UriKey::Path(_) => (uri_key, None),
                        UriKey::PathQuery(path_query) => {
                            let uri_key = UriKey::Path(path_query.into_path());
                            let result = lock.get_mut_with_lifetime(&uri_key).into_option();
                            (uri_key, result)
                        }
                    },
                }
            }
        } else {
            (uri_key, None)
        };
        let arc = match cached {
            (_, Some((resp, _))) => Arc::clone(resp.push_response(compressed_response, params)),
            (_, None) => {
                let vary_rules = host.vary.rules_from_request(request);

                // SAFETY: The requirements are met; the cache we're storing this is is part of the
                // `host`; the `host` will outlive this struct.
                let varied_response = unsafe {
                    VariedResponse::new(compressed_response, request, vary_rules.as_ref())
                };

                let arc = Arc::clone(varied_response.first());

                handle_cache_helpers::maybe_cache(
                    host,
                    server_cache,
                    path_query,
                    varied_response,
                    request.method(),
                    &future,
                )
                .await;

                arc
            }
        };
        (arc, future)
    }
}
/// Will handle a single request, check the cache, process if needed, and caches it.
/// This is where the response is sent.
///
/// This is [layer 4](https://kvarn.org/pipeline.#layer-4--caching-and-compression)
pub async fn handle_cache(
    request: &mut FatRequest,
    address: SocketAddr,
    host: &Host,
) -> CacheReply {
    let sanitize_data = utils::sanitize_request(request);

    let overide_uri = host.extensions.resolve_prime(request, host, address).await;

    let uri_key =
        comprash::UriKey::path_and_query(overide_uri.as_ref().unwrap_or_else(|| request.uri()));

    let mut lock = if let Some(response_cache) = &host.response_cache {
        Some(response_cache.read().await)
    } else {
        None
    };

    let cached = if let Some(lock) = &mut lock {
        uri_key.call_all(|key| lock.get_with_lifetime(key).into_option())
    } else {
        (uri_key, None)
    };
    #[allow(clippy::single_match_else, clippy::unnested_or_patterns)]
    let (response, identity, future) = match cached {
        (uri_key, Some((resp, (creation, _))))
            if sanitize_data.is_ok()
                && matches!(request.method(), &Method::GET | &Method::HEAD) =>
        {
            debug!("Found in cache!");

            let creation = *creation;

            // Handle `if-modified-since` header.
            let if_modified_since: Option<OffsetDateTime> =
                if host.options.disable_if_modified_since {
                    None
                } else {
                    request
                        .headers()
                        .get("if-modified-since")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| {
                            time::PrimitiveDateTime::parse(s, &comprash::HTTP_DATE)
                                .ok()
                                .map(time::PrimitiveDateTime::assume_utc)
                        })
                };

            let client_request_is_fresh = if_modified_since.map_or(false, |timestamp| {
                // - 1s because the sent datetime floors the seconds, so the `creation`
                // datetime is 0-1s ahead.
                timestamp >= creation - 1.seconds()
            });

            // We don't need to check for `host.options.disable_if_modified_since`
            // but `if_modified_since` is `None` and therefore `client_request` is false
            // if the option is enabled, as defined in the if in the `if_modified_since`
            // definition.
            let mut response_data = if client_request_is_fresh {
                drop(lock);
                let mut response = Response::new(Bytes::new());
                *response.status_mut() = StatusCode::NOT_MODIFIED;
                (response, Bytes::new(), None)
            } else {
                // get the cached response
                let (resp_vary, future) = match resp.get_by_request(request) {
                    Ok(arc) => {
                        let arc = Arc::clone(arc);
                        drop(lock);
                        (arc, None)
                    }
                    // the varied response didn't have any version which matches the request.
                    Err(params) => {
                        // Drop lock during response creation
                        drop(lock);
                        // in a sepparate function as this is a cold path and to reduce the length
                        // of this fn
                        handle_cache_helpers::handle_vary_missing(
                            request,
                            host,
                            &sanitize_data,
                            address,
                            overide_uri.as_ref(),
                            uri_key,
                            params,
                        )
                        .await
                    }
                };
                let (resp, vary) = &*resp_vary;
                // Here, the lock is always (irrelevant of which arm the code runs) dropped, which
                // enables us to do computationally heavy things, such as compression.
                let mut response = match resp.clone_preferred(request, &host.compression_options) {
                    Err(message) => {
                        error::default(
                            StatusCode::NOT_ACCEPTABLE,
                            Some(host),
                            Some(message.as_bytes()),
                        )
                        .await
                    }
                    Ok(response) => response,
                };

                vary::apply_header(&mut response, vary);

                let identity_body = Bytes::clone(resp.get_identity().body());

                (response, identity_body, future)
            };
            if !host.options.disable_if_modified_since {
                let last_modified = HeaderValue::from_str(
                    &creation
                        .format(&comprash::HTTP_DATE)
                        .expect("failed to format datetime"),
                )
                .expect("We know these bytes are valid.");
                utils::replace_header(
                    response_data.0.headers_mut(),
                    "last-modified",
                    last_modified,
                );
            }
            response_data
        }
        _ => {
            drop(lock);

            let sanitize_data = &sanitize_data;
            let overide_uri = overide_uri.as_ref();
            let (compressed_response, _, server_cache, future, path_query) =
                handle_cache_helpers::get_response(
                    request,
                    host,
                    sanitize_data,
                    address,
                    overide_uri,
                )
                .await;

            let vary_rules = host.vary.rules_from_request(request);

            // SAFETY: The requirements are met; the cache we're storing this is is part of the
            // `host`; the `host` will outlive this struct.
            let varied_response =
                unsafe { VariedResponse::new(compressed_response, request, vary_rules.as_ref()) };

            let compressed_response = &varied_response.first().0;

            let mut response =
                match compressed_response.clone_preferred(request, &host.compression_options) {
                    Err(message) => {
                        error::default(
                            StatusCode::NOT_ACCEPTABLE,
                            Some(host),
                            Some(message.as_bytes()),
                        )
                        .await
                    }
                    Ok(response) => response,
                };

            let identity_body = Bytes::clone(compressed_response.get_identity().body());

            let vary = &varied_response.first().1;
            vary::apply_header(&mut response, vary);

            let cache_rejected = handle_cache_helpers::maybe_cache(
                host,
                server_cache,
                path_query,
                varied_response,
                request.method(),
                &future,
            )
            .await;

            if !host.options.disable_if_modified_since && cache_rejected.is_none() {
                let last_modified = HeaderValue::from_str(
                    &OffsetDateTime::now_utc()
                        .format(&comprash::HTTP_DATE)
                        .expect("failed to format datetime"),
                )
                .expect("We know these bytes are valid.");
                utils::replace_header(response.headers_mut(), "last-modified", last_modified);
            }

            (response, identity_body, future)
        }
    };

    CacheReply {
        response,
        identity_body: identity,
        sanitize_data,
        future,
    }
}

/// Handles a single request and returns response with cache and compress preference.
///
/// This is [layer 5](https://kvarn.org/pipeline.#layer-5--pathing)
pub async fn handle_request(
    request: &mut FatRequest,
    overide_uri: Option<&Uri>,
    address: SocketAddr,
    host: &Host,
    path: &Option<PathBuf>,
) -> FatResponse {
    let mut response = None;
    let mut client_cache = None;
    let mut server_cache = None;
    let mut compress = None;
    let mut future = None;

    #[allow(unused_mut)]
    let mut status = None;

    {
        if let Some(resp) = host
            .extensions
            .resolve_prepare(request, overide_uri, host, path, address)
            .await
        {
            let resp = resp.into_parts();
            response.replace(resp.0);
            client_cache.replace(resp.1);
            server_cache.replace(resp.2);
            compress.replace(resp.3);
            if let Some(f) = resp.4 {
                future.replace(f);
            }
        }
    }

    if response.is_none() {
        if let Some(path) = path {
            match *request.method() {
                Method::GET | Method::HEAD => {
                    if let Some(content) = read_file(&path, host.file_cache.as_ref()).await {
                        response = Some(Response::new(content));
                    }
                }
                _ => status = Some(StatusCode::METHOD_NOT_ALLOWED),
            }
        }
    }

    let response = match response {
        Some(r) => r,
        None => {
            error::default_response(status.unwrap_or(StatusCode::NOT_FOUND), host, None)
                .await
                .response
        }
    };

    macro_rules! maybe_with {
        ($response: expr, $option: expr, $method: tt) => {
            if let Some(t) = $option {
                $response = $response.$method(t);
            }
        };
    }
    let mut response = FatResponse::cache(response);
    maybe_with!(response, client_cache, with_client_cache);
    maybe_with!(response, server_cache, with_server_cache);
    maybe_with!(response, compress, with_compress);
    maybe_with!(response, future, with_future);

    response
}

/// Which version of the [Internet Protocol](https://en.wikipedia.org/wiki/Internet_Protocol)
/// to bind to.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[must_use]
pub enum BindIpVersion {
    /// Bind to IPv4
    V4,
    /// Bind to IPv6
    V6,
    /// Bind to IPv4 and IPv6
    Both,
}

/// Describes port, certificate, and host data for
/// a single port to bind.
///
/// See the note at the bottom of [`Host`] for an explanation
/// about the relationship between [`Self::new`] and [`Self::unsecure`].
#[derive(Clone)]
#[must_use]
pub struct PortDescriptor {
    port: u16,
    #[cfg(feature = "https")]
    server_config: Option<Arc<rustls::ServerConfig>>,
    data: Arc<HostCollection>,
    version: BindIpVersion,
    // also update Debug implementation when adding fields
}
/// Creation and configuration.
///
/// Used when creating a server.
impl PortDescriptor {
    /// Uses the defaults for non-secure HTTP with `host_data`
    pub fn http(host_data: Arc<HostCollection>) -> Self {
        Self {
            port: 80,
            #[cfg(feature = "https")]
            server_config: None,
            data: host_data,
            version: BindIpVersion::Both,
        }
    }
    /// Uses the defaults for secure HTTP, HTTPS, with `host_data`.
    /// Gets a [`rustls::ServerConfig`] from [`HostCollection::make_config()`].
    #[cfg(feature = "https")]
    pub fn https(host_data: Arc<HostCollection>) -> Self {
        Self {
            port: 443,
            server_config: Some(Arc::new(host_data.make_config())),
            data: host_data,
            version: BindIpVersion::Both,
        }
    }
    /// Creates a new descriptor for `port` with `host_data` and an optional [`rustls::ServerConfig`].
    #[cfg(feature = "https")]
    pub fn with_server_config(
        port: u16,
        host_data: Arc<HostCollection>,
        server_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            port,
            server_config,
            data: host_data,
            version: BindIpVersion::Both,
        }
    }
    /// Creates a new descriptor for `port` with `host_data`.
    /// If the feature `https` is enabled, a `rustls::ServerConfig` is created
    /// from the `host_data`.
    pub fn new(port: u16, host_data: Arc<HostCollection>) -> Self {
        Self {
            port,
            #[cfg(feature = "https")]
            server_config: Some(Arc::new(host_data.make_config())),
            data: host_data,
            version: BindIpVersion::Both,
        }
    }
    /// Creates a new non-secure descriptor for `port` with `host_data`.
    /// Does not try to assign a certificate.
    pub fn unsecure(port: u16, host_data: Arc<HostCollection>) -> Self {
        Self {
            port,
            #[cfg(feature = "https")]
            server_config: None,
            data: host_data,
            version: BindIpVersion::Both,
        }
    }
    /// Binds to IPv4 only.
    /// The default is to bind both.
    ///
    /// This disables IPv6 for this port.
    pub fn ipv4_only(mut self) -> Self {
        self.version = BindIpVersion::V4;
        self
    }
    /// Binds to IPv6 only.
    /// The default is to bind both.
    ///
    /// This disables IPv4 for this port.
    pub fn ipv6_only(mut self) -> Self {
        self.version = BindIpVersion::V6;
        self
    }
}
/// Inspection.
///
/// Used in [`ctl::Plugin`]s.
// these return references of the Arc values so they can't escape the Plugins.
// This is just restrictive in case we change the API later.
impl PortDescriptor {
    /// Get the port this description is associated with.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
    /// Get a reference to this port's optional TLS config.
    #[cfg(feature = "https")]
    #[must_use]
    pub fn tls_config(&self) -> Option<&rustls::ServerConfig> {
        self.server_config.as_deref()
    }
    /// Get the associated hosts.
    ///
    /// This can be used to remove entries from the response & file cache.
    ///
    /// Remember, this collection can be the same as for any other port descriptor.
    pub fn hosts(&self) -> &HostCollection {
        &self.data
    }
    /// Get the version of the internet protocol (IP) we are listening on
    /// through [`Self::port`].
    pub fn internet_protocol(&self) -> BindIpVersion {
        self.version
    }
}
impl Debug for PortDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct(utils::ident_str!(PortDescriptor));

        utils::fmt_fields!(
            s,
            (self.port),
            #[cfg(feature = "https")]
            (
                self.server_config,
                &self
                    .server_config
                    .as_ref()
                    .map(|_| "[opaque certificate]".as_clean())
            ),
            (self.data),
            (self.version),
        );

        s.finish()
    }
}

/// The `Request` used within Kvarn.
pub type FatRequest = Request<application::Body>;
/// A `Response` returned by [`handle_request()`].
///
/// Contains all preference information to the lower-level
/// functions. Most things like `content-length`, `content-encoding`,
/// `content-type`, `cache-control`, and server caching will be
/// automatically handled.
#[must_use = "send the response"]
pub struct FatResponse {
    response: Response<Bytes>,
    client: comprash::ClientCachePreference,
    server: comprash::ServerCachePreference,
    compress: comprash::CompressPreference,

    future: Option<ResponsePipeFuture>,
    // also update Debug implementation when adding fields
}
impl FatResponse {
    /// Create a new [`FatResponse`] with `server_cache_preference` advising Kvarn of how to cache the content.
    /// All other preferences are set to `Full` with a `future` of [`None`].
    ///
    /// Choose
    /// - [`comprash::ServerCachePreference::Full`] if the page is one regularly accessed,
    /// - [`comprash::ServerCachePreference::None`] if the page is rarely accessed or if the runtime cost of
    ///   getting the page is minimal.
    /// - [`comprash::ServerCachePreference::QueryMatters`] should be avoided. It should be used when
    ///   you have a page dictated by the query. Consider using a [`Prime`] extension
    ///   to make all requests act as only one of a few queries to increase performance
    ///   by reducing cache size.
    pub fn new(
        response: Response<Bytes>,
        server_cache_preference: comprash::ServerCachePreference,
    ) -> Self {
        Self {
            response,
            client: comprash::ClientCachePreference::Full,
            server: server_cache_preference,
            compress: comprash::CompressPreference::Full,

            future: None,
        }
    }
    /// Create a new [`FatResponse`] with all preferences set to `Full` and no `Future`.
    ///
    /// Use the `with_*` methods to change the defaults.
    pub fn cache(response: Response<Bytes>) -> Self {
        Self::new(response, comprash::ServerCachePreference::Full)
    }
    /// Create a new [`FatResponse`] with all cache preferences set to `None`,
    /// compress preference set to `Full`, and no `Future`.
    ///
    /// Use the `with_*` methods to change the defaults.
    pub fn no_cache(response: Response<Bytes>) -> Self {
        Self {
            response,
            client: comprash::ClientCachePreference::None,
            server: comprash::ServerCachePreference::None,
            compress: comprash::CompressPreference::Full,
            future: None,
        }
    }
    /// Set the inner [`comprash::ClientCachePreference`].
    pub fn with_client_cache(mut self, preference: comprash::ClientCachePreference) -> Self {
        self.client = preference;
        self
    }
    /// Set the inner [`comprash::ServerCachePreference`].
    pub fn with_server_cache(mut self, preference: comprash::ServerCachePreference) -> Self {
        self.server = preference;
        self
    }
    /// Set the inner [`comprash::CompressPreference`].
    pub fn with_compress(mut self, preference: comprash::CompressPreference) -> Self {
        self.compress = preference;
        self
    }
    /// Set the inner `future`.
    pub fn with_future(mut self, future: ResponsePipeFuture) -> Self {
        self.future = Some(future);
        self
    }

    /// Set the `content-type` header of the inner response to `content_type`.
    ///
    /// # Panics
    ///
    /// Panics if the display implementation of `content_type` produces illegal bytes for
    /// [`HeaderValue`].
    ///
    /// It's unknown if this can even happen at all.
    /// If it does happen, it's in the [`Mime::params`].
    pub fn with_content_type(mut self, content_type: &Mime) -> Self {
        utils::replace_header(
            self.response.headers_mut(),
            "content-type",
            // UNWRAP: We know the mime type is valid.
            HeaderValue::from_maybe_shared::<Bytes>(content_type.to_string().into_bytes().into())
                .unwrap(),
        );
        self
    }

    /// Turn `self` into a tuple of all it's parts.
    pub fn into_parts(
        self,
    ) -> (
        Response<Bytes>,
        comprash::ClientCachePreference,
        comprash::ServerCachePreference,
        comprash::CompressPreference,
        Option<ResponsePipeFuture>,
    ) {
        (
            self.response,
            self.client,
            self.server,
            self.compress,
            self.future,
        )
    }
}
impl Debug for FatResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        enum BytesOrStr<'a> {
            Str(&'a str),
            Bytes(&'a [u8]),
        }
        impl<'a> Debug for BytesOrStr<'a> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                match self {
                    Self::Str(s) => f.write_str(s),
                    Self::Bytes(_) => f.write_str("[binary data]"),
                }
            }
        }
        let response = utils::empty_clone_response(&self.response);
        let body = if let Ok(s) = str::from_utf8(self.response.body()) {
            BytesOrStr::Str(s)
        } else {
            BytesOrStr::Bytes(self.response.body())
        };
        let response = response.map(|()| body);
        let mut s = f.debug_struct(utils::ident_str!(FatResponse));

        utils::fmt_fields!(
            s,
            (self.response, &response),
            (self.client),
            (self.server),
            (self.compress),
            (self.future, &"[opaque Future]".as_clean()),
        );

        s.finish()
    }
}

/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "windows")]
pub const SERVER: &str = "Kvarn/0.4.1 (Windows)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "macos")]
pub const SERVER: &str = "Kvarn/0.4.1 (macOS)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "linux")]
// See https://doc.rust-lang.org/beta/unstable-book/language-features/doc-cfg.html & https://github.com/rust-lang/rust/pull/89596
#[cfg_attr(docsrs, doc(cfg(all())))]
pub const SERVER: &str = "Kvarn/0.4.1 (Linux)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "freebsd")]
pub const SERVER: &str = "Kvarn/0.4.1 (FreeBSD)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd"
)))]
pub const SERVER: &str = "Kvarn/0.4.1 (unknown OS)";

//! Helpers for integration-testing Kvarn.
//!
//! Here, you can easily spin up a new server on a random non-used port
//! and send a request to it in under 5 lines.

#![deny(clippy::all)]

use kvarn::prelude::*;

type CertifiedKey = (rustls::Certificate, Arc<Box<dyn rustls::sign::SigningKey>>);

macro_rules! impl_methods {
    ($($method: ident $name: ident),*) => {
        $(
            /// Make a request to `path` with the selected method.
            pub fn $method(&self, path: impl AsRef<str>) -> reqwest::RequestBuilder {
                let client = self.client().build().unwrap();
                client.request(reqwest::Method::$name, self.url(path))
            }
        )*
    };
}

/// A port returned by [`ServerBuilder::run`] to connect to.
pub struct Server {
    server: Arc<shutdown::Manager>,
    certificate: Option<CertifiedKey>,
    port: u16,
    handover: Option<PathBuf>,
}
impl Server {
    impl_methods!(get GET, post POST, put PUT, delete DELETE, head HEAD, options OPTIONS, connect CONNECT, patch PATCH, trace TRACE);

    /// Get a [`reqwest::ClientBuilder`] with the [`Self::cert`] accepted.
    pub fn client(&self) -> reqwest::ClientBuilder {
        let mut client = reqwest::Client::builder();
        if let Some(cert) = self.cert() {
            let cert = reqwest::Certificate::from_der(&cert.0).unwrap();
            client = client.add_root_certificate(cert);
        };
        client
    }
    /// Builds a URL to the server with `path`.
    pub fn url(&self, path: impl AsRef<str>) -> reqwest::Url {
        let added_root = if path.as_ref().starts_with('/') {
            ""
        } else {
            "/"
        };
        let string = format!(
            "http{}://localhost:{}{}{}",
            self.cert().map_or("", |_| "s"),
            self.port(),
            added_root,
            path.as_ref()
        );
        reqwest::Url::parse(&string).unwrap()
    }
    /// Gets the port of the TCP server.
    pub fn port(&self) -> u16 {
        self.port
    }
    /// Gets the certificate, if any.
    /// This dictates whether or not HTTPS should be on.
    pub fn cert(&self) -> Option<&rustls::Certificate> {
        self.certificate.as_ref().map(|(cert, _)| cert)
    }

    /// Gets a [`shutdown::Manager`] which is [`Send`].
    ///
    /// You can shut down Kvarn from another thread using this.
    pub fn get_shutdown_manager(&self) -> Arc<shutdown::Manager> {
        Arc::clone(&self.server)
    }
}
impl Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Server")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("handover", &self.handover)
            .finish()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.server.shutdown();
    }
}

/// A builder struct for starting a test [`Server`].
pub struct ServerBuilder {
    https: bool,
    extensions: Extensions,
    options: host::Options,
    path: Option<PathBuf>,
    handover: Option<(PathBuf, Option<u16>)>,
    cert: Option<CertifiedKey>,
}
impl ServerBuilder {
    /// Creates a new builder with `extensions` and `options`,
    /// with HTTPS enabled. To disable this, call [`Self::http`].
    /// Use `Self::default()` for a default configuration.
    ///
    /// Also see the [`From`] implementations for this struct.
    ///
    /// The inner [`Extensions`] can be modified with [`Self::with_extensions`]
    /// and the [`host::Options`] with [`Self::with_options`]
    pub fn new(extensions: Extensions, options: host::Options) -> Self {
        Self {
            https: true,
            extensions,
            options,
            path: None,
            handover: None,
            cert: None,
        }
    }
    /// Disables HTTPS.
    pub fn http(mut self) -> Self {
        self.https = false;
        self
    }
    /// Modifies the internal [`Extensions`] with `mutation`.
    /// If you already have a [`Extensions`], use [`From`].
    pub fn with_extensions(mut self, mutation: impl Fn(&mut Extensions)) -> Self {
        mutation(&mut self.extensions);
        self
    }
    /// Modifies the internal [`host::Options`] with `mutation`.
    /// If you already have a [`host::Options`], use [`From`].
    pub fn with_options(mut self, mutation: impl Fn(&mut host::Options)) -> Self {
        mutation(&mut self.options);
        self
    }
    /// Sets the [`Host::path`] of this server.
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Enables [handover](https://kvarn.org/shutdown-handover.) for this server.
    /// If you are starting the server which will take over the requests, use [`Self::handover_from`] instead.
    /// The communication socket is at `path`.
    pub fn enable_handover(mut self, path: impl AsRef<Path>) -> Self {
        self.handover = Some((path.as_ref().to_path_buf(), None));
        self
    }
    /// "Steals" the requests from `previous`.
    ///
    /// # Panics
    ///
    /// Will panic if [`Self::enable_handover`] wasn't called on `previous`'s [`ServerBuilder`].
    pub fn handover_from(mut self, previous: &Server) -> Self {
        self.handover = Some((
            previous
                .handover
                .to_owned()
                .expect("Previous server didn't have handover configured!"),
            Some(previous.port()),
        ));
        println!("Previous port {}", previous.port());
        self.cert = previous.certificate.to_owned();
        self
    }

    async fn test_port_availability(port: u16) -> io::Result<()> {
        match tokio::net::TcpStream::connect(SocketAddr::new(
            IpAddr::V4(net::Ipv4Addr::LOCALHOST),
            port,
        ))
        .await
        {
            Err(e) => match e.kind() {
                io::ErrorKind::ConnectionRefused => Ok(()),
                _ => panic!(
                    "Spurious IO error while checking port availability: {:?}",
                    e
                ),
            },
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Something is listening on the port!",
            )),
        }
    }
    async fn get_port() -> u16 {
        use rand::prelude::*;
        let mut rng = rand::thread_rng();
        let port_range = rand::distributions::Uniform::new(4096, 61440);

        loop {
            let port = port_range.sample(&mut rng);

            if Self::test_port_availability(port).await.is_err() {
                continue;
            }
            return port;
        }
    }

    /// Starts a Kvarn server with the current configuraion.
    ///
    /// The returned [`Server`] can make requests to the server, streamlining
    /// the process of testing Kvarn.
    pub async fn run(self) -> Server {
        let Self {
            https,
            extensions,
            options,
            path,
            handover,
            cert,
        } = self;

        let path = path.as_deref().unwrap_or(Path::new("tests"));

        let (host, certified_key) = if https {
            let (cert, pk) = cert.unwrap_or_else(|| {
                let self_signed_cert =
                    rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
                let cert = rustls::Certificate(self_signed_cert.serialize_der().unwrap());

                let pk = rustls::PrivateKey(self_signed_cert.serialize_private_key_der());
                let pk = Arc::new(rustls::sign::any_supported_type(&pk).unwrap());
                (cert, pk)
            });

            (
                Host::from_cert_and_pk(
                    "localhost",
                    vec![cert.clone()],
                    pk.clone(),
                    path,
                    extensions,
                    options,
                ),
                Some((cert, pk)),
            )
        } else {
            (
                Host::non_secure("localhost", path, extensions, options),
                None,
            )
        };

        let data = Data::builder(host).build();

        loop {
            let mut custom_port = false;
            let port = if let Some((_, Some(port))) = &handover {
                custom_port = true;
                println!("Custom port!");
                *port
            } else {
                Self::get_port().await
            };
            println!("Running on {}", port);
            let port_descriptor = if https {
                PortDescriptor::new(port, data.clone())
            } else {
                PortDescriptor::non_secure(port, data.clone())
            };
            let mut config = RunConfig::new().add(port_descriptor);
            if let Some((handover_path, _)) = &handover {
                config = config.set_handover_socket_path(handover_path);
            } else {
                config = config.disable_handover();
            }

            // Last check for collisions
            if !custom_port && Self::test_port_availability(port).await.is_err() {
                continue;
            }
            let shutdown = run(config).await;
            return Server {
                port,
                certificate: certified_key,
                server: shutdown,
                handover: handover.map(|(path, _)| path),
            };
        }
    }
}
impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new(Extensions::default(), host::Options::default())
    }
}
impl From<Extensions> for ServerBuilder {
    fn from(extensions: Extensions) -> Self {
        Self::new(extensions, host::Options::default())
    }
}
impl From<host::Options> for ServerBuilder {
    fn from(options: host::Options) -> Self {
        Self::new(Extensions::default(), options)
    }
}
impl From<(Extensions, host::Options)> for ServerBuilder {
    fn from(data: (Extensions, host::Options)) -> Self {
        Self::new(data.0, data.1)
    }
}

#[cfg(test)]
mod tests {
    use super::ServerBuilder;

    fn simple_request(server: &super::Server) {
        let response = server
            .get("")
            .timeout(time::Duration::from_millis(100))
            .send()
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "Got response {:#?}",
            response
        );
        assert!(response.text().await.unwrap().contains("404 Not Found"));
    }

    #[tokio::test]
    async fn https() {
        let server = ServerBuilder::default().run().await;
        simple_request(&server);
    }
    #[tokio::test]
    async fn http() {
        let server = ServerBuilder::default().http().run().await;
        simple_request(&server);
    }
}

/// The testing prelude.
/// Also imports `kvarn::prelude::*`.
pub mod prelude {
    pub use super::{Server, ServerBuilder};
    #[doc(hidden)]
    pub use kvarn::prelude::*;
    pub use reqwest;
}
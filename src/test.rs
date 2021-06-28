//! Helpers for integration-testing Kvarn.
//!
//! Here, you can easily spin up a new server on a random non-used port
//! and send a request to it in under 5 lines.
//! See [`run_server`] on getting started.

use crate::prelude::*;

macro_rules! impl_methods {
    ($($method: ident),*) => {
        $(
            /// Make a request to `path` with the selected method.
            pub fn $method(&self, path: impl AsRef<str>) -> reqwest::RequestBuilder {
                let client = self.client().build().unwrap();
                client.$method(self.url(path))
            }
        )*
    };
}

/// A port returned by [`run_server`] to connect to.
#[derive(Debug)]
pub struct Server {
    server: Arc<shutdown::Manager>,
    certificate: Option<rustls::Certificate>,
    port: u16,
}
impl Server {
    impl_methods!(get, post, put, patch, delete, head);

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
        let string = format!(
            "http{}://localhost:{}/{}",
            self.cert().map_or("", |_| "s"),
            self.port(),
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
        self.certificate.as_ref()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.server.shutdown();
    }
}

/// Starts a Kvarn server with the `extensions`.
///
/// The returned [`Server`] can make requests to the server, streamlining
/// the process of testing Kvarn.
pub async fn run_server(extensions: Extensions, https: bool) -> Server {
    use rand::prelude::*;
    use std::net::Ipv4Addr;

    fn lh(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    let host = if https {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = vec![rustls::Certificate(certificate.serialize_der().unwrap())];
        let pk = rustls::PrivateKey(certificate.serialize_private_key_der());
        let pk = Arc::new(rustls::sign::any_supported_type(&pk).unwrap());

        Host::from_cert_and_pk(
            "localhost",
            cert,
            pk,
            PathBuf::from("tests"),
            extensions,
            host::Options::default(),
        )
    } else {
        Host::non_secure(
            "localhost",
            PathBuf::from("tests"),
            extensions,
            host::Options::default(),
        )
    };

    let mut rng = rand::thread_rng();
    let port_range = rand::distributions::Uniform::new(4096, 61440);
    loop {
        let port = port_range.sample(&mut rng);
        match TcpStream::connect(lh(port)).await {
            Err(e) => match e.kind() {
                io::ErrorKind::ConnectionRefused => {},
                _ => panic!("Spurious IO error while checking port availability: {:?}", e),
            },
            Ok(_) => continue,
        }
        let certificate = host.certificate.as_ref().map(|cert_key| cert_key.cert[0].clone());
        let data = Data::builder(host).build();
        let port_descriptor = PortDescriptor::new(port, data);
        let shutdown = run(vec![port_descriptor]).await;
        return Server {
            port,
            certificate,
            server: shutdown,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::run_server;
    use crate::prelude::*;

    #[tokio::test]
    async fn index() {
        let server = run_server(Extensions::new(), true).await;
        let response = server
            .get("")
            .timeout(std::time::Duration::from_millis(100))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND, "Got response {:#?}", response);
        assert!(response.text().await.unwrap().contains("404 Not Found"));
    }
}

//! Handling of multiple [`Host`]s on one instance of Kvarn.
//!
//! A single [`Host`] contains the certificate, caches, and preferences
//! which are needed to run a domain.
//!
//! This also implements the logic needed for [`rustls`] to resolve which [`Host`]
//! to use for a connection. This is done by having a default and
//! other defined by their SNI (or `host` header in HTTP/1).
//!
//! This tactic might change in the future; if you have two domains pointing
//! to a single Kvarn server, say `icelk.dev` and `kvarn.org`, but only `kvarn.org`
//! is set up, the client will get a certificate error when going to `icelk.dev`.
//! Therefore, I think the user of this library should have a choice to reject connections
//! to a [`Host`] which isn't explicitly associated with said domain.

use crate::prelude::{internals::*, *};
#[cfg(feature = "https")]
use rustls::{
    internal::pemfile, sign, ClientHello, NoClientAuth, ResolvesServerCert, ServerConfig,
};

/// A set of settings for a [virtual host](https://en.wikipedia.org/wiki/Virtual_hosting),
/// allowing multiple DNS entries (domain names) to share a single IP address.
///
/// This is an integral part of Kvarn; the ability to host multiple
/// webpages on a single instance without crosstalk and with high performance
/// makes it a viable option.
///
/// # Examples
///
/// See [`run()`].
#[must_use]
pub struct Host {
    /// The name of the host, will be used in matching the requests [SNI hostname](rustls::ClientHello::server_name())
    /// and `host` header to get the requested host to handle the request.
    pub name: &'static str,
    /// The certificate of this host, if any.
    #[cfg(feature = "https")]
    pub certificate: Option<sign::CertifiedKey>,
    /// Base path of all data for this host.
    ///
    /// If you enabled the `fs` feature (enabled by default),
    /// the public files are in the directory `<path>/public`.
    ///
    /// Also, all extensions should use this to access data on disk.
    pub path: PathBuf,
    /// The extensions of this host.
    pub extensions: Extensions,
    /// The file cache of this host.
    ///
    /// The caches are separated to limit the performance fluctuations of
    /// multiple hosts on the same instance.
    ///
    /// Can be used to clear the cache and to pass to the read functions in [`utility`].
    pub file_cache: FileCache,
    /// The response cache of this host.
    /// See [`comprash`] and [`Host::file_cache`] for more info.
    pub response_cache: ResponseCache,

    /// Will be the default for folders; `/js/` will resolve to `/js/<folder_default>`.
    /// E.g. `/posts/` -> `/posts/index.html`
    ///
    /// If no value is passed, `index.html` is assumed.
    pub folder_default: Option<String>,
    /// Will be the default for unspecified file extensions; `/foobar.` will resolve to `/foobar.<extension_default>`.
    /// E.g. `/index.` -> `/index.html`
    ///
    /// If no value is passed, `html` is assumed.
    pub extension_default: Option<String>,
}
impl Host {
    /// Creates a new [`Host`].
    /// Will read certificates in the specified locations
    /// and return an non-secure host if parsing fails.
    ///
    /// To achieve greater safety, use [`Host::with_https_redirect`] and call [`Host::enable_hsts`].
    ///
    /// See [`Host::non_secure`] for a non-failing function,
    /// available regardless of features.
    ///
    /// # Errors
    ///
    /// Will return any error from [`get_certified_key()`] with a [`Host`] containing no certificates.
    #[cfg(feature = "https")]
    pub fn new(
        host_name: &'static str,
        cert_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        path: PathBuf,
        extensions: Extensions,
    ) -> Result<Self, (CertificateError, Self)> {
        let cert = get_certified_key(cert_path, private_key_path);
        match cert {
            Ok(cert) => Ok(Self {
                name: host_name,
                certificate: Some(cert),
                path,
                extensions,
                folder_default: None,
                extension_default: None,
                file_cache: Mutex::new(Cache::default()),
                response_cache: Mutex::new(Cache::default()),
            }),
            Err(err) => Err((
                err,
                Self {
                    name: host_name,
                    certificate: None,
                    path,
                    extensions,
                    folder_default: None,
                    extension_default: None,
                    file_cache: Mutex::new(Cache::default()),
                    response_cache: Mutex::new(Cache::default()),
                },
            )),
        }
    }
    /// Creates a new [`Host`] without a certificate.
    ///
    /// This host will only support non-encrypted HTTP/1 connections.
    /// Consider enabling the `https` flag and use a self-signed certificate or one from [Let's Encrypt](https://letsencrypt.org/).
    pub fn non_secure(host_name: &'static str, path: PathBuf, extensions: Extensions) -> Self {
        Self {
            name: host_name,
            #[cfg(feature = "https")]
            certificate: None,
            path,
            extensions,
            folder_default: None,
            extension_default: None,
            file_cache: Mutex::new(Cache::default()),
            response_cache: Mutex::new(Cache::default()),
        }
    }

    /// Same as [`Host::new`] with [`Host::set_http_redirect_to_https`].
    ///
    /// If [`Host::new`] returns an error, we log it as an [`Level::Error`]
    /// and continue without encryption.
    ///
    /// Consider [`Host::enable_hsts`] to harden the system.
    #[cfg(feature = "https")]
    pub fn with_http_redirect(
        host_name: &'static str,
        cert_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        path: PathBuf,
        extensions: Extensions,
    ) -> Self {
        match Host::new(host_name, cert_path, private_key_path, path, extensions) {
            Ok(mut host) => {
                host.set_http_redirect_to_https();
                host
            }
            Err((err, host_without_cert)) => {
                error!(
                    "Failed to get certificate! Not running host on HTTPS. {:?}",
                    err
                );
                host_without_cert
            }
        }
    }

    /// Adds a [`Prepare`] and a [`Prime`] extension which redirects requests using HTTP to HTTPS
    /// with a [`StatusCode::TEMPORARY_REDIRECT`].
    ///
    /// For more info about how it works, see the source of this function.
    #[cfg(feature = "https")]
    pub fn set_http_redirect_to_https(&mut self) {
        const SPECIAL_PATH: &str = "/./to_https";
        self.extensions.add_prepare_single(
            SPECIAL_PATH.to_string(),
            Box::new(|mut request, _, _, _| {
                // "/./ path" is special; it will not be accepted from outside; any path containing './' gets rejected.
                // Therefore, we can unwrap on values, making the assumption I implemented them correctly below.
                let request: &FatRequest = unsafe { request.get_inner() };
                let uri = request.uri();
                let uri = {
                    let authority = uri.authority().map_or("", uri::Authority::as_str);
                    let path = uri.query().unwrap_or("");
                    let mut bytes = BytesMut::with_capacity(8 + authority.len() + path.len());
                    bytes.extend(b"https://");
                    bytes.extend(authority.as_bytes());
                    bytes.extend(path.as_bytes());
                    // Ok, since we just introduced https:// in the start, which are valid bytes.
                    unsafe { HeaderValue::from_maybe_shared_unchecked(bytes.freeze()) }
                };

                let response = Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", uri);
                // Unwrap is ok; we know this is valid.
                ready((
                    response.body(Bytes::new()).unwrap(),
                    ClientCachePreference::Full,
                    ServerCachePreference::None,
                    CompressPreference::None,
                ))
            }),
        );
        self.extensions.add_prime(Box::new(|request, _, _| {
            let request: &FatRequest = unsafe { request.get_inner() };
            let uri =
                if request.uri().scheme_str() == Some("http") && request.uri().port().is_none() {
                    // redirect
                    let mut uri = request.uri().clone().into_parts();

                    let mut bytes = BytesMut::with_capacity(
                        SPECIAL_PATH.len()
                            + 1
                            + request.uri().path().len()
                            + request.uri().query().map_or(0, |s| s.len() + 1),
                    );
                    bytes.extend(SPECIAL_PATH.as_bytes());
                    bytes.extend(b"?");
                    bytes.extend(request.uri().path().as_bytes());
                    if let Some(query) = request.uri().query() {
                        bytes.extend(b"?");
                        bytes.extend(query.as_bytes());
                    }
                    // it must be a valid Uri
                    uri.path_and_query =
                        Some(uri::PathAndQuery::from_maybe_shared(bytes.freeze()).unwrap());
                    let uri = Uri::from_parts(uri).unwrap();
                    Some(uri)
                } else {
                    None
                };
            ready(uri)
        }));
    }

    /// Enables [HSTS](https://en.wikipedia.org/wiki/HSTS) on this [`Host`].
    ///
    /// You should be careful using this feature.
    /// If you do not plan to have a certificate for your domain
    /// for at least the following two years, take a look in the source code,
    /// copy paste it and lower the `max-age`.
    ///
    /// Also see [hstspreload.org](https://hstspreload.org/)
    #[cfg(feature = "https")]
    pub fn enable_hsts(&mut self) {
        self.extensions
            .add_package(Box::new(|mut response, request, _| {
                let response: &mut Response<_> = unsafe { response.get_inner() };
                let request: &FatRequest = unsafe { request.get_inner() };
                if request.uri().scheme_str() == Some("https") {
                    response
                        .headers_mut()
                        .entry("strict-transport-security")
                        .or_insert(HeaderValue::from_static(
                            "max-age=63072000; includeSubDomains; preload",
                        ));
                }

                ready(())
            }))
    }

    /// Whether or not this this host is secured with a certificate.
    ///
    /// See [`Host::certificate`].
    #[cfg(feature = "https")]
    #[inline]
    pub fn is_secure(&self) -> bool {
        self.certificate.is_some()
    }
    /// Whether or not this this host is secured with a certificate.
    ///
    /// See [`Host::certificate`].
    #[cfg(not(feature = "https"))]
    #[inline]
    pub(crate) fn is_secure(&self) -> bool {
        false
    }
}
impl Debug for Host {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use utility::CleanDebug;
        let mut d = f.debug_struct("Host");
        d.field("host_name", &CleanDebug::new(self.name));
        #[cfg(feature = "https")]
        d.field("certificate", &CleanDebug::new("[internal certificate]"));
        d.field("path", &self.path);
        d.field("extensions", &CleanDebug::new("[internal extension data]"));
        d.field("file_cache", &CleanDebug::new("[internal cache]"));
        d.field("response_cache", &CleanDebug::new("[internal cache]"));
        d.field("folder_default", &self.folder_default);
        d.field("extension_default", &self.extension_default);
        d.finish()
    }
}

/// A builder of [`Data`]. See [`Data::builder()`].
#[derive(Debug)]
#[must_use]
pub struct DataBuilder(Data);
impl DataBuilder {
    /// Adds `host` to the builder. See [`Dat::add_host`], which is called internally.
    #[inline]
    pub fn add_host(mut self, host: Host) -> Self {
        self.0.add_host(host.name, host);
        self
    }
    /// Puts the inner [`Data`] in a [`Arc`] and returns it.
    ///
    /// This works great with the overall flow of Kvarn. See [`run()`] for an example.
    #[inline]
    pub fn build(self) -> Arc<Data> {
        Arc::new(self.into_inner())
    }
    /// Converts `self` to a [`Data`].
    #[inline]
    pub fn into_inner(self) -> Data {
        self.0
    }
}

/// A collection of [`Host`]s, with exactly one default and
/// arbitrarily many other, indexed by [`Host.name`].
///
/// If only a default is specified, all requests, (e.g. those who lack a `host` header,
/// have none, or all other values of the header) are channelled to the default.
///
/// If the feature `https` is enabled, [`rustls::ResolvesServerCert`] in implemented
/// using this default and host name pattern.
#[derive(Debug)]
#[must_use]
pub struct Data {
    default: Host,
    by_name: HashMap<&'static str, Host>,
    has_secure: bool,
}
impl Data {
    /// Creates a new [`DataBuilder`] with `default_host` as the default.
    #[inline]
    pub fn builder(default_host: Host) -> DataBuilder {
        DataBuilder(Self {
            has_secure: default_host.is_secure(),
            default: default_host,
            by_name: HashMap::new(),
        })
    }
    /// Creates a new [`Data`] with `default_host` as the default.
    /// Consider using [`Data::builder`] for a more ergonomic API.
    #[inline]
    pub fn new(default_host: Host) -> Self {
        Self {
            has_secure: default_host.is_secure(),
            default: default_host,
            by_name: HashMap::new(),
        }
    }
    /// Creates a `Host` without certification, using the directories `./public` and `./templates`.
    #[inline]
    pub fn simple_non_secure(default_host_name: &'static str, extensions: Extensions) -> Self {
        Self {
            default: Host::non_secure(default_host_name, ".".into(), extensions),
            by_name: HashMap::new(),
            has_secure: false,
        }
    }
    /// Adds a [`Host`] to self.
    ///
    /// `host_name` should often be [`Host.name`].
    #[inline]
    pub fn add_host(&mut self, host_name: &'static str, host_data: Host) {
        if host_data.is_secure() {
            self.has_secure = true;
        }
        self.by_name.insert(host_name, host_data);
    }

    /// Returns a reference to the default [`Host`].
    ///
    /// Use [`Data::smart_get`] to get the appropriate host.
    #[inline]
    pub fn get_default(&self) -> &Host {
        &self.default
    }
    /// Gets a [`Host`] by name.
    #[inline]
    pub fn get_host(&self, host: &str) -> Option<&Host> {
        self.by_name.get(host)
    }
    /// Gets a [`Host`] by name, and returns the [`default`](Data::get_default) if none were found.
    #[inline]
    pub fn get_or_default(&self, host: &str) -> &Host {
        self.get_host(host).unwrap_or_else(|| self.get_default())
    }
    /// Gets a [`Host`] by name, if any, and returns it or the [`default`](Data::get_default)
    /// if `maybe_host` is [`None`] or [`Data::get_or_default`] returns [`None`].
    #[inline]
    pub fn maybe_get_or_default(&self, maybe_host: Option<&str>) -> &Host {
        match maybe_host {
            Some(host) => self.get_or_default(host),
            None => self.get_default(),
        }
    }
    /// Cleverly gets the host depending on [`header::HOST`] and the `sni_hostname`.
    #[inline]
    pub fn smart_get<'a>(
        &'a self,
        request: &Request<Body>,
        sni_hostname: Option<&str>,
    ) -> &'a Host {
        fn get_header(headers: &HeaderMap) -> Option<&str> {
            headers
                .get(header::HOST)
                .map(HeaderValue::to_str)
                .and_then(Result::ok)
        }

        let host = sni_hostname.or_else(|| get_header(request.headers()));

        self.maybe_get_or_default(host)
    }

    /// Returns if any [`Host`]s are [`Host::is_secure`].
    #[inline]
    pub fn has_secure(&self) -> bool {
        self.has_secure
    }

    /// Makes a [`rustls::ServerConfig`] from [`Data`].
    ///
    /// This takes [`Data`] in an [`Arc`] and clones it.
    ///
    /// You should not have to call this, since [`PortDescriptor::new`] and [`PortDescriptor::https`] calls it internally.
    /// Though, you could use the [`host`] system by itself, without the rest of Kvarn.
    #[cfg(feature = "https")]
    #[inline]
    #[must_use]
    pub fn make_config(self: &Arc<Self>) -> ServerConfig {
        let mut config = ServerConfig::new(NoClientAuth::new());
        let arc = Arc::clone(self);
        config.cert_resolver = arc;
        config.alpn_protocols = alpn();
        config
    }

    /// Clears all response caches.
    #[inline]
    pub async fn clear_response_caches(&self) {
        // Handle default host
        self.default.response_cache.lock().await.clear();
        // All other
        for host in self.by_name.values() {
            host.response_cache.lock().await.clear();
        }
    }
    /// Clears a single `uri` in `host`.
    ///
    /// # Returns
    ///
    /// (if host was found, cleared page)
    ///
    /// This will probably become a error enum in the future.
    ///
    /// It will lever return (false, true).
    pub async fn clear_page(&self, host: &str, uri: &Uri) -> (bool, bool) {
        let key = UriKey::path_and_query(uri);

        let mut found = false;
        let mut cleared = false;
        if host.is_empty() || host == "default" {
            found = true;
            let mut lock = self.default.response_cache.lock().await;
            if key
                .call_all(|key| lock.remove(key).into_option())
                .1
                .is_some()
            {
                cleared = true;
            }
        } else if let Some(host) = self.by_name.get(host) {
            found = true;
            let mut lock = host.response_cache.lock().await;
            if key
                .call_all(|key| lock.remove(key).into_option())
                .1
                .is_some()
            {
                cleared = true;
            }
        }
        (found, cleared)
    }
    /// Clears all file caches.
    #[inline]
    pub async fn clear_file_caches(&self) {
        self.default.file_cache.lock().await.clear();
        for host in self.by_name.values() {
            host.file_cache.lock().await.clear();
        }
    }
    /// Clears the `path` from all caches.
    ///
    /// This iterates over all caches and [locks](Mutex::lock) them, which takes a lot of time.
    /// Though, it's not blocking.
    pub async fn clear_file_in_cache<P: AsRef<Path>>(&self, path: &P) -> bool {
        let mut found = false;
        if self
            .default
            .file_cache
            .lock()
            .await
            .remove(path.as_ref())
            .into_option()
            .is_some()
        {
            found = true;
        }
        for host in self.by_name.values() {
            if host
                .file_cache
                .lock()
                .await
                .remove(path.as_ref())
                .into_option()
                .is_some()
            {
                found = true;
            }
        }
        found
    }
}
#[cfg(feature = "https")]
impl ResolvesServerCert for Data {
    #[inline]
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<sign::CertifiedKey> {
        // Mostly returns true, since we have a default
        // Will however return false if certificate is not present
        // in found host or default host.
        self.maybe_get_or_default(client_hello.server_name().map(|n| n.into()))
            .certificate
            .clone()
    }
}

/// An error regarding creation of a [`rustls::sign::CertifiedKey`].
#[cfg(feature = "https")]
#[derive(Debug)]
pub enum CertificateError {
    /// An error occurred while reading from the fs.
    Io(io::Error),
    /// The private key is of improper format.
    ImproperPrivateKeyFormat,
    /// THe certificate (public key) is of improper format.
    ImproperCertificateFormat,
    /// No key was found.
    NoKey,
    /// The private key doesn't match the public key.
    InvalidPrivateKey,
}
#[cfg(feature = "https")]
impl From<io::Error> for CertificateError {
    #[inline]
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Extracts a [`sign::CertifiedKey`] from `cert_path` and `private_key_path`.
///
/// # Errors
///
/// Will return any errors while reading the files, or any parsing errors.
#[cfg(feature = "https")]
pub fn get_certified_key(
    cert_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
) -> Result<sign::CertifiedKey, CertificateError> {
    let mut chain = io::BufReader::new(std::fs::File::open(&cert_path)?);
    let mut private_key = io::BufReader::new(std::fs::File::open(&private_key_path)?);

    let mut private_keys = Vec::with_capacity(4);
    private_keys.extend(match pemfile::pkcs8_private_keys(&mut private_key) {
        Ok(key) => key,
        Err(()) => return Err(CertificateError::ImproperPrivateKeyFormat),
    });
    if private_keys.is_empty() {
        private_keys.extend(match pemfile::rsa_private_keys(&mut private_key) {
            Ok(key) => key,
            Err(()) => return Err(CertificateError::ImproperPrivateKeyFormat),
        });
    }
    let key = match private_keys.get(0) {
        Some(key) => key,
        None => return Err(CertificateError::NoKey),
    };

    let key = sign::any_supported_type(key).map_err(|_| CertificateError::InvalidPrivateKey)?;
    let chain = match pemfile::certs(&mut chain) {
        Ok(cert) => cert,
        Err(()) => return Err(CertificateError::ImproperCertificateFormat),
    };

    Ok(sign::CertifiedKey::new(chain, Arc::new(key)))
}

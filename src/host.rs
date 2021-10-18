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
    /// Can be used to clear the cache and to pass to the read functions in [`read`].
    pub file_cache: Option<FileCache>,
    /// The response cache of this host.
    /// See [`comprash`] and [`Host::file_cache`] for more info.
    pub response_cache: Option<ResponseCache>,
    /// The [`LimitManager`] checking for spam attacks
    /// for this host.
    ///
    /// Having this host-specific enables different virtual
    /// hosts to have varying degrees of strictness.
    pub limiter: LimitManager,
    /// Settings for handling caching of responses with the `vary` header.
    pub vary: Vary,

    /// Other settings.
    pub options: Options,
}
impl Host {
    /// Creates a new [`Host`].
    /// Will read certificates in the specified locations
    /// and return an non-secure host if parsing fails.
    ///
    /// To achieve greater security, use [`Host::with_http_redirect`] and call [`Host::enable_hsts`].
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
        path: impl AsRef<Path>,
        extensions: Extensions,
        options: Options,
    ) -> Result<Self, (CertificateError, Self)> {
        let cert = get_certified_key(cert_path, private_key_path);
        match cert {
            Ok((cert, pk)) => Ok(Self::from_cert_and_pk(
                host_name, cert, pk, path, extensions, options,
            )),
            Err(err) => Err((err, Self::non_secure(host_name, path, extensions, options))),
        }
    }
    /// Creates a new [`Host`] from the [`rustls`]
    /// `cert` and `pk`. When they are in files, consider [`Self::new`]
    /// which reads from files.
    ///
    /// See the considerations of [`Self::new`] for security.
    ///
    /// # Examples
    ///
    /// ```nocomplie
    /// let certificate =
    ///     rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    /// let cert = vec![rustls::Certificate(certificate.serialize_der().unwrap())];
    /// let pk = rustls::PrivateKey(certificate.serialize_private_key_der());
    /// let pk = Arc::new(rustls::sign::any_supported_type(&pk).unwrap());
    ///
    /// Host::from_cert_and_pk(
    ///     "localhost",
    ///     cert,
    ///     pk,
    ///     PathBuf::from("tests"),
    ///     extensions,
    ///     host::Options::default(),
    /// )
    /// ```
    #[cfg(feature = "https")]
    pub fn from_cert_and_pk(
        host_name: &'static str,
        cert: Vec<rustls::Certificate>,
        pk: Arc<Box<dyn sign::SigningKey>>,
        path: impl AsRef<Path>,
        extensions: Extensions,
        options: Options,
    ) -> Self {
        let cert = sign::CertifiedKey::new(cert, pk);

        Self {
            name: host_name,
            certificate: Some(cert),
            path: path.as_ref().to_path_buf(),
            extensions,
            file_cache: Some(Mutex::new(Cache::default())),
            response_cache: Some(Mutex::new(Cache::default())),
            options,
            limiter: LimitManager::default(),
            vary: Vary::default(),
        }
    }
    /// Creates a new [`Host`] without a certificate.
    ///
    /// This host will only support non-encrypted HTTP/1 connections.
    /// Consider enabling the `https` flag and use a self-signed certificate or one from [Let's Encrypt](https://letsencrypt.org/).
    pub fn non_secure(
        host_name: &'static str,
        path: impl AsRef<Path>,
        extensions: Extensions,
        options: Options,
    ) -> Self {
        Self {
            name: host_name,
            #[cfg(feature = "https")]
            certificate: None,
            path: path.as_ref().to_path_buf(),
            extensions,
            file_cache: Some(Mutex::new(Cache::default())),
            response_cache: Some(Mutex::new(Cache::default())),
            options,
            limiter: LimitManager::default(),
            vary: Vary::default(),
        }
    }

    /// Same as [`Host::new`] with [`Host::set_http_redirect_to_https`].
    ///
    /// If [`Host::new`] returns an error, we log it as an [`log::Level::Error`]
    /// and continue without encryption.
    ///
    /// Consider [`Host::enable_hsts`] to harden the system.
    #[cfg(feature = "https")]
    pub fn with_http_redirect(
        host_name: &'static str,
        cert_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        extensions: Extensions,
        options: Options,
    ) -> Self {
        match Host::new(
            host_name,
            cert_path,
            private_key_path,
            path,
            extensions,
            options,
        ) {
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

    /// Adds a [`Prepare`] and a [`Prime`] extension (with a priority of `4`) which redirects requests using HTTP to HTTPS
    /// with a [`StatusCode::TEMPORARY_REDIRECT`].
    ///
    /// For more info about how it works, see the source of this function.
    #[cfg(feature = "https")]
    pub fn set_http_redirect_to_https(&mut self) -> &mut Self {
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
                    let bytes = build_bytes!(
                        b"https://",
                        authority.as_bytes(),
                        uri.path().as_bytes(),
                        uri.query().map_or(b"".as_ref(), |_| b"?".as_ref()),
                        uri.query().map_or(b"".as_ref(), |q| q.as_bytes())
                    );
                    // Ok, since we just introduced https:// in the start, which are valid bytes.
                    unsafe { HeaderValue::from_maybe_shared_unchecked(bytes) }
                };

                let response = Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", uri);
                // Unwrap is ok; we know this is valid.
                ready(
                    FatResponse::cache(response.body(Bytes::new()).unwrap())
                        .with_server_cache(ServerCachePreference::None)
                        .with_compress(CompressPreference::None),
                )
            }),
        );
        self.extensions.add_prime(
            Box::new(|request, _, _| {
                let request: &FatRequest = unsafe { request.get_inner() };
                let uri = if request.uri().scheme_str() == Some("http")
                    && request.uri().port().is_none()
                {
                    // redirect
                    Some(Uri::from_static(SPECIAL_PATH))
                } else {
                    None
                };
                ready(uri)
            }),
            extensions::Id::new(4, "Redirecting to HTTPS"),
        );
        self
    }

    /// Enables [HSTS](https://en.wikipedia.org/wiki/HSTS) on this [`Host`].
    ///
    /// The [`Package`] extension has a priority of `8`.
    ///
    /// You should be careful using this feature.
    /// If you do not plan to have a certificate for your domain
    /// for at least the following two years, take a look in the source code,
    /// copy paste it and lower the `max-age`.
    ///
    /// Also see [hstspreload.org](https://hstspreload.org/)
    #[cfg(feature = "https")]
    pub fn enable_hsts(&mut self) -> &mut Self {
        self.extensions.add_package(
            Box::new(|mut response, request, _| {
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
            }),
            extensions::Id::new(8, "Adding HSTS header"),
        );
        self
    }
    /// Disables client cache on this host.
    ///
    /// This makes all [`ClientCachePreference`]s `no-store`.
    /// Use Kvarn extensions' `force_cache` to force certain files to cache.
    pub fn disable_client_cache(&mut self) -> &mut Self {
        self.options.disable_client_cache();
        self
    }

    /// Disables the file system cache for this host.
    /// This can cause degraded performance under heavy load,
    /// but reduces the memoy used.
    pub fn disable_fs_cache(&mut self) -> &mut Self {
        self.file_cache = None;
        self
    }
    /// Disables the response cache for this host.
    /// This can cause degraded performance under heavy load,
    /// but reduces the memoy used.
    pub fn disable_response_cache(&mut self) -> &mut Self {
        self.response_cache = None;
        self
    }
    /// Disables all server caches.
    /// This can cause degraded performance under heavy load,
    /// but reduces the memoy used.
    ///
    /// Right now calls [`Self::disable_fs_cache`] and [`Self::disable_response_cache`].
    pub fn disable_server_cache(&mut self) -> &mut Self {
        self.disable_fs_cache().disable_response_cache()
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
        let mut d = f.debug_struct("Host");
        d.field("host_name", &self.name);
        #[cfg(feature = "https")]
        d.field("certificate", &"[internal certificate]".as_clean());
        d.field("path", &self.path);
        d.field("extensions", &"[internal extension data]".as_clean());
        d.field("file_cache", &"[internal cache]".as_clean());
        d.field("response_cache", &"[internal cache]".as_clean());
        d.field("settings", &self.options);
        d.finish()
    }
}
/// Options for [`Host`].
/// Values wrapped in [`Option`]s usually use hardcoded defaults when the value is [`None`].
///
/// This can easily be cloned to be shared across multiple hosts.
#[derive(Debug, Clone)]
#[must_use]
pub struct Options {
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
    /// Returns `cache-control` header to be `no-store` by default, if enabled.
    ///
    /// Useful if you have a developing site and don't want traditionally static content to be in the client cache.
    pub disable_client_cache: bool,
    /// Default data directory for public files.
    /// Default is `public`
    pub public_data_dir: Option<PathBuf>,

    /// Disables further caching by sending a [`StatusCode::NOT_MODIFIED`] when the
    /// `if-modified-since` header is sent and the resource is fresh.
    pub disable_if_modified_since: bool,

    /// Disables file system access for public files.
    ///
    /// This still enables custom error messages and reading of files through extensions.
    pub disable_fs: bool,
}
impl Options {
    /// Creates a new [`Options`] with default settings.
    ///
    /// All [`Option`]s are [`None`] and all booleans are `false`.
    pub fn new() -> Self {
        Self {
            folder_default: None,
            extension_default: None,
            disable_client_cache: false,
            public_data_dir: None,
            disable_if_modified_since: false,
            disable_fs: false,
        }
    }
    /// Disables client cache on this host.
    ///
    /// This makes all [`ClientCachePreference`]s `no-store`.
    /// Use Kvarn extensions' `force_cache` to force certain files to cache.
    pub fn disable_client_cache(&mut self) -> &mut Self {
        self.disable_client_cache = true;
        self
    }
    /// Disables accessing the file system for public files.
    ///
    /// See [`Self::disable_fs`] for more info.
    pub fn disable_fs(&mut self) -> &mut Self {
        self.disable_fs = true;
        self
    }
    /// Sets the relative directory (from the [`Host::path`]) to fetch data for the web in.
    /// Defaults to `public`
    pub fn set_public_data_dir(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.public_data_dir = Some(path.as_ref().to_path_buf());
        self
    }
}
impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

/// A builder of [`Data`]. See [`Data::builder()`].
#[derive(Debug)]
#[must_use]
pub struct DataBuilder(Data);
impl DataBuilder {
    /// Adds `host` to the builder. See [`Data::add_host`], which is called internally.
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
            default: Host::non_secure(default_host_name, ".", extensions, Options::default()),
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
        if let Some(cache) = &self.default.response_cache {
            // Handle default host
            cache.lock().await.clear();
            // All other
            for host in self.by_name.values() {
                if let Some(cache) = &host.response_cache {
                    cache.lock().await.clear();
                }
            }
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
            if let Some(cache) = &self.default.response_cache {
                let mut lock = cache.lock().await;
                if key
                    .call_all(|key| lock.remove(key).into_option())
                    .1
                    .is_some()
                {
                    cleared = true;
                }
            }
        } else if let Some(host) = self.by_name.get(host) {
            found = true;
            if let Some(cache) = &host.response_cache {
                let mut lock = cache.lock().await;
                if key
                    .call_all(|key| lock.remove(key).into_option())
                    .1
                    .is_some()
                {
                    cleared = true;
                }
            }
        }
        (found, cleared)
    }
    /// Clears all file caches.
    #[inline]
    pub async fn clear_file_caches(&self) {
        if let Some(cache) = &self.default.file_cache {
            cache.lock().await.clear();
        }
        for host in self.by_name.values() {
            if let Some(cache) = &host.file_cache {
                cache.lock().await.clear();
            }
        }
    }
    /// Clears the `path` from all caches.
    ///
    /// This iterates over all caches and [locks](Mutex::lock) them, which takes a lot of time.
    /// Though, it's not blocking.
    pub async fn clear_file_in_cache<P: AsRef<Path>>(&self, path: &P) -> bool {
        let mut found = false;
        if let Some(cache) = &self.default.file_cache {
            if cache
                .lock()
                .await
                .remove(path.as_ref())
                .into_option()
                .is_some()
            {
                found = true;
            }
        }
        for host in self.by_name.values() {
            if let Some(cache) = &host.file_cache {
                if cache
                    .lock()
                    .await
                    .remove(path.as_ref())
                    .into_option()
                    .is_some()
                {
                    found = true;
                }
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
) -> Result<(Vec<rustls::Certificate>, Arc<Box<dyn sign::SigningKey>>), CertificateError> {
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

    Ok((chain, Arc::new(key)))
}

/// The transformation on a request header to get the
/// "key" header value to store in the cache (in the [`comprash::HeaderCollection`]).
// It's a `Arc` to enable cloning of `VaryRule`.
pub(crate) type VaryTransformation = Pin<Arc<dyn Fn(&str) -> Cow<'static, str> + Send + Sync>>;

/// A rule for how to handle a single varied header.
///
/// Takes the name of the request header,
/// how to get the header to cache using,
/// and a default.
#[derive(Clone)]
pub(crate) struct VaryRule {
    name: &'static str,
    transformation: VaryTransformation,
    default: &'static str,
}
impl Debug for VaryRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaryRule")
            .field("name", &self.name)
            .field("transformation", &"[ transformation Fn ]".as_clean())
            .field("default", &self.default)
            .finish()
    }
}
impl VaryRule{
    pub(crate) fn name(&self) -> &'static str {
        self.name
    }
    pub(crate) fn default(&self) -> &'static str {
        self.default
    }
    pub(crate) fn transformation(&self) -> &VaryTransformation {
        &self.transformation
    }
}

/// The rules for handling and caching a request/response.
#[derive(Debug, Clone, Default)]
pub struct VarySettings {
    pub(crate) rules: Vec<VaryRule>,
}
impl VarySettings {
    /// Returns an empty set of rules.
    /// Will not cache any variants, except compressed.
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }
    /// Add a custom rule.
    ///
    /// The `request_header` is used when outputting the `vary` header
    /// and for the internal cache.
    ///
    /// `transformation` takes `request_header` and (hopefully, for performance)
    /// narrows the variants down to a finite number.
    ///
    /// > Prefer to return a limited set of strings from the transformation to
    /// > minimize cache size. If you generate [`String`]s,
    /// > limit the amount of different strings.
    ///
    /// If you have a large set or infinitely many variants outputted by `transformation`,
    /// the cache will suffer. Consider disabling the cache for the files affected by this rule
    /// to improve performance.
    pub fn add_rule(
        mut self,
        request_header: &'static str,
        transformation: impl Fn(&str) -> Cow<'static, str> + Send + Sync + 'static,
        default: &'static str,
    ) -> Self {
        if self.rules.len() > 4 {
            warn!("More than 4 headers affect the caching of requests. This will exponentially increase memory usage.")
        }
        self.rules.push(VaryRule {
            name: request_header,
            transformation: Arc::pin(transformation),
            default,
        });
        self
    }
}
/// A set of rules for the `vary` header.
///
/// See [`VarySettings::add_rule`] on adding rules
/// and [`extensions::RuleSet::add`] for linking the [`VarySettings`] to paths.
///
/// # Examples
///
/// ```
/// use kvarn::prelude::*;
///
/// # #[tokio::test]
/// # async fn example() {
/// fn test_lang (header: &str) -> &'static str {
///     let mut langs = utils::list_header(header);
///     langs.sort_by(|l1, l2| {
///         l2.quality
///             .partial_cmp(&l1.quality)
///             .unwrap_or(cmp::Ordering::Equal)
///     });
///
///     for lang in &langs {
///         // We take the first language; the values are sorted by quality, so the highest will be
///         // chosen.
///         match lang.value {
///             "sv" => return "sv",
///             "en-GB" | "en" => return "en-GB",
///             _ => ()
///         }
///     }
///     "en-GB"
/// }
///
/// let host = Host::non_secure("localhost", PathBuf::from("web"), Extensions::default(), host::Options::default());
///
/// host.vary.add_mut(
///     "/test_lang",
///     host::VarySettings::empty().add_rule(
///         "accept-language",
///         |header| Cow::Borrowed(test_lang(header)),
///         "en-GB",
///     ),
/// );
/// host.extensions.add_prepare_single(
///     "/test_lang",
///     prepare!(req, _host, _path, _addr {
///         let æ = req
///             .headers()
///             .get("accept-language")
///             .map(HeaderValue::to_str)
///             .and_then(Result::ok)
///             .map_or(false, |header| test_lang(header) == "sv");
///
///         let body = if æ {
///             "Hej!"
///         } else {
///             "Hello."
///         };
///
///         FatResponse::cache(Response::new(Bytes::from_static(body.as_bytes())))
///     }),
/// );
///
/// let data = Data::builder(host).build();
/// let port_descriptor = PortDescriptor::new(8080, data);
///
/// let shutdown_manager = run(run_config![port_descriptor]).await;
/// # }
/// ```
#[must_use]
pub type Vary = extensions::RuleSet<VarySettings>;
impl Vary {
    /// Gets the [`VarySettings`] from the ruleset using the path of `request`.
    pub fn rules_from_request<'a, T>(&'a self, request: &Request<T>) -> Cow<'a, VarySettings> {
        if let Some(rules) = self.get(request.uri().path()) {
            Cow::Borrowed(rules)
        } else {
            Cow::Owned(VarySettings::default())
        }
    }
}

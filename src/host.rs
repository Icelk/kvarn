//! Handling of multiple [`Host`]s on one instance of Kvarn.
//!
//! A single [`Host`] contains the certificate, caches, and preferences
//! which are needed to run a domain.
//!
//! This also implements the logic needed for [`rustls`] to resolve which [`Host`]
//! to use for a connection. This is done by having an optional default and
//! other defined by their SNI (or `host` header in HTTP/1). If no host is matched,
//! the request is dropped, like when a [unsecure connection is sent to a secure port](Host).

use crate::prelude::{internals::*, *};
#[cfg(feature = "https")]
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign, ServerConfig,
};

/// A set of settings for a [virtual host](https://en.wikipedia.org/wiki/Virtual_hosting),
/// allowing multiple DNS entries (domain names) to share a single IP address.
///
/// This is an integral part of Kvarn; the ability to host multiple
/// webpages on a single instance without crosstalk and with high performance
/// makes it a viable option.
///
/// Let's talk about the relations of [`Host::unsecure`] and [`PortDescriptor::unsecure`].
/// A host can be secure and contain a certificate (if the `https` feature is enabled).
/// A [`PortDescriptor`] can accept HTTPS or HTTP requests. [`PortDescriptor::new`] will
/// set up the descriptor to accept only HTTP requests if none of the hosts contains a certificate.
/// It accepts only HTTPS messages if any of the hosts have a certificate. Then, connections to
/// all the other hosts with no certificate are rejected.
///
/// For example, in [the reference implementation](https://github.com/Icelk/kvarn-reference),
/// I use [`PortDescriptor::unsecure`] to bind port 80 and
/// [`PortDescriptor::new`] to bind port 443. Then, all hosts are reachable on port 80,
/// but only the ones with a certificate on port 443.
///
/// # Examples
///
/// See [`RunConfig::execute()`].
#[must_use]
pub struct Host {
    /// The name of the host, will be used in matching the requests [SNI hostname](rustls::server::ClientHello::server_name())
    /// and `host` header to get the requested host to handle the request.
    pub name: &'static str,
    /// The certificate of this host, if any.
    #[cfg(feature = "https")]
    pub certificate: Option<Arc<sign::CertifiedKey>>,
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
    /// To achieve greater security, use [`Host::with_http_to_https_redirect`] and call [`Host::with_hsts`].
    ///
    /// See [`Host::unsecure`] for a non-failing function,
    /// available regardless of features.
    ///
    /// # Errors
    ///
    /// Will return any error from [`get_certified_key()`] with a [`Host`] containing no certificates.
    #[cfg(feature = "https")]
    pub fn try_read_fs(
        host_name: &'static str,
        cert_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        extensions: Extensions,
        options: Options,
    ) -> Result<Self, (CertificateError, Self)> {
        let cert = get_certified_key(cert_path, private_key_path);
        match cert {
            Ok((cert, pk)) => Ok(Self::new(host_name, cert, pk, path, extensions, options)),
            Err(err) => Err((err, Self::unsecure(host_name, path, extensions, options))),
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
    /// ```nocompile
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
    pub fn new(
        name: &'static str,
        cert: Vec<rustls::Certificate>,
        pk: Arc<dyn sign::SigningKey>,
        path: impl AsRef<Path>,
        extensions: Extensions,
        options: Options,
    ) -> Self {
        let cert = sign::CertifiedKey::new(cert, pk);

        Self {
            name,
            certificate: Some(Arc::new(cert)),
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
    /// Consider enabling the `https` feature and use a self-signed certificate or one from [Let's Encrypt](https://letsencrypt.org/).
    pub fn unsecure(
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

    /// Same as [`Host::try_read_fs`] with [`Host::with_http_to_https_redirect`].
    /// This does however consider the error from [`Host::try_read_fs`] to be ok.
    /// We log it as an [`log::Level::Error`]
    /// and continue without encryption.
    ///
    /// Consider running [`Host::try_read_fs`] with [`Host::with_http_to_https_redirect`]
    /// and [`Host::with_hsts`] to harden the system.
    #[cfg(feature = "https")]
    pub fn http_redirect_or_unsecure(
        host_name: &'static str,
        cert_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        extensions: Extensions,
        options: Options,
    ) -> Self {
        match Host::try_read_fs(
            host_name,
            cert_path,
            private_key_path,
            path,
            extensions,
            options,
        ) {
            Ok(mut host) => {
                host.with_http_to_https_redirect();
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

    /// Adds extensions to redirect unsecure HTTP requests to the secure HTTPS URI.
    ///
    /// See [`Extensions::with_http_to_https_redirect`].
    #[cfg(feature = "https")]
    pub fn with_http_to_https_redirect(&mut self) -> &mut Self {
        self.extensions.with_http_to_https_redirect();
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
    pub fn with_hsts(&mut self) -> &mut Self {
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
    /// This makes all [`comprash::ClientCachePreference`]s `no-store`.
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
        d.field("name", &self.name);
        #[cfg(feature = "https")]
        d.field("certificate", &"[internal certificate]".as_clean());
        d.field("path", &self.path);
        d.field("extensions", &"[internal extension data]".as_clean());
        d.field("file_cache", &"[internal cache]".as_clean());
        d.field("response_cache", &"[internal cache]".as_clean());
        d.field("limiter", &self.limiter);
        d.field("vary", &self.vary);
        d.field("options", &self.options);
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
    // # Miscellaneous
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
    /// Default data directory for public files.
    /// Default is `public`
    pub public_data_dir: Option<PathBuf>,

    // # Cache
    /// Returns `cache-control` header to be `no-store` by default, if enabled.
    ///
    /// Useful if you have a developing site and don't want traditionally static content to be in the client cache.
    pub disable_client_cache: bool,
    /// Disables further caching by sending a [`StatusCode::NOT_MODIFIED`] when the
    /// `if-modified-since` header is sent and the resource is fresh.
    pub disable_if_modified_since: bool,
    /// Filter to not cache certain [`StatusCode`]s.
    ///
    /// See [`CacheAction`] and [`default_status_code_cache_filter`] for more info.
    pub status_code_cache_filter: fn(StatusCode) -> CacheAction,

    // # Extensions
    /// Disables file system access for public files.
    ///
    /// This still enables custom error messages and reading of files through extensions.
    pub disable_fs: bool,
}
impl Options {
    /// Creates a new [`Options`] with default settings.
    ///
    /// All [`Option`]s are [`None`] and all booleans are `false`.
    /// [`Self::status_code_cache_filter`] uses [`default_status_code_cache_filter`].
    pub fn new() -> Self {
        Self {
            folder_default: None,
            extension_default: None,
            public_data_dir: None,

            disable_client_cache: false,
            disable_if_modified_since: false,
            status_code_cache_filter: default_status_code_cache_filter,

            disable_fs: false,
        }
    }
    /// Disables client cache on this host.
    ///
    /// This makes all [`comprash::ClientCachePreference`]s `no-store`.
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
    /// Defaults to `public`.
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
    /// Adds `host` to the builder.
    /// This will match the `host` header and SNI hostname for [`Host.name`].
    #[inline]
    pub fn insert(mut self, host: Host) -> Self {
        self.check_secure(&host);
        if self.0.first.is_none() {
            self.0.first = Some(host.name);
        }
        self.0.by_name.insert(host.name, host);
        self
    }
    /// Adds a default `host` which is the fallback for all requests with a requested host
    /// which does not match any host added using [`Self::insert`].
    ///
    /// > This is not needed when debugging, as the first [`Host`] to be inserted is used
    /// > for requests to `localhost`.
    ///
    /// **NOTE:** This should be used with care as all secure connections to this server
    /// with a SNI hostname that is not registered in this [`Data`], the client will get
    /// a security warning, as the certificate of the default host is used.
    /// This is fine with HTTP, as that only delivers the website.
    ///
    /// # Panics
    ///
    /// Panics if this function is called twice on the same struct.
    /// You should only set the default once.
    #[inline]
    pub fn default(mut self, host: Host) -> Self {
        assert!(
            self.0.default.is_none(),
            "Can not set default host multiple times."
        );
        self.check_secure(&host);
        self.0.default = Some(host);
        self
    }
    fn check_secure(&mut self, host: &Host) {
        if host.is_secure() {
            self.0.has_secure = true;
        }
    }
    /// Sets the limiter used before any data is read. Only when the [`LimitManager`] returns
    /// [`LimitAction::Drop`] will this do anything here.
    #[inline]
    pub fn set_pre_host_limiter(mut self, limiter: LimitManager) -> Self {
        self.0.pre_host_limiter = limiter;
        self
    }
    /// Puts the inner [`Data`] in a [`Arc`] and returns it.
    ///
    /// This works great with the overall flow of Kvarn. See [`RunConfig::execute()`] for an example.
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
/// > When called as `localhost`, the first is always used.
///
/// If the feature `https` is enabled, [`rustls::server::ResolvesServerCert`] in implemented
/// using this default and host name pattern.
#[derive(Debug)]
#[must_use]
pub struct Data {
    default: Option<Host>,
    by_name: HashMap<&'static str, Host>,
    first: Option<&'static str>,
    has_secure: bool,
    pre_host_limiter: LimitManager,
}
impl Data {
    /// Creates a new [`DataBuilder`] with `default_host` as the default.
    #[inline]
    pub fn builder() -> DataBuilder {
        DataBuilder(Self {
            default: None,
            by_name: HashMap::new(),
            first: None,
            has_secure: false,
            pre_host_limiter: LimitManager::default(),
        })
    }
    /// Creates a `Host` without certification, using the directories `./public` and `./templates`.
    /// The host is the default. See [`host`] for more info.
    #[inline]
    pub fn simple_non_secure(default_host_name: &'static str, extensions: Extensions) -> Self {
        Self {
            default: Some(Host::unsecure(
                default_host_name,
                ".",
                extensions,
                Options::default(),
            )),
            by_name: HashMap::new(),
            first: None,
            has_secure: false,
            pre_host_limiter: LimitManager::default(),
        }
    }

    /// Returns a reference to the default [`Host`].
    ///
    /// Use [`Data::smart_get`] to get the appropriate host.
    #[inline]
    pub fn get_default(&self) -> Option<&Host> {
        self.default.as_ref()
    }
    /// Gets a [`Host`] by name.
    #[inline]
    pub fn get_host(&self, host: &str) -> Option<&Host> {
        self.by_name.get(host)
    }
    /// Gets a [`Host`] by name, and returns the [`default`](Data::get_default) if none were found.
    #[inline]
    pub fn get_or_default(&self, host: &str) -> Option<&Host> {
        self.get_host(host)
            .or_else(|| self.get_default())
            .or_else(|| {
                let base_host = host.split(':').next();
                if base_host == Some("localhost")
                    || base_host == Some("127.0.0.1")
                    || base_host == Some("::1")
                {
                    self.first.and_then(|host| self.get_host(host))
                } else {
                    None
                }
            })
    }
    /// Gets a [`Host`] by name, if any, and returns it or the [`default`](Data::get_default)
    /// if `maybe_host` is [`None`] or [`Data::get_or_default`] returns [`None`].
    #[inline]
    pub fn maybe_get_or_default(&self, maybe_host: Option<&str>) -> Option<&Host> {
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
    ) -> Option<&'a Host> {
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
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        config.alpn_protocols = alpn();
        config
    }

    /// Gets the `pre_host_limiter` to manage limits before any of the request is read, or even a
    /// TLS session is initiated.
    pub(crate) fn limiter(&self) -> &LimitManager {
        &self.pre_host_limiter
    }

    /// Clears all response caches.
    #[inline]
    pub async fn clear_response_caches(&self) {
        // Handle default host
        if let Some(cache) = self
            .default
            .as_ref()
            .and_then(|h| h.response_cache.as_ref())
        {
            cache.lock().await.clear();
        }
        // All other
        for host in self.by_name.values() {
            if let Some(cache) = &host.response_cache {
                cache.lock().await.clear();
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
            if let Some(cache) = self
                .default
                .as_ref()
                .and_then(|h| h.response_cache.as_ref())
            {
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
        if let Some(cache) = self.default.as_ref().and_then(|h| h.file_cache.as_ref()) {
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
        if let Some(cache) = self.default.as_ref().and_then(|h| h.file_cache.as_ref()) {
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
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        // Mostly returns true, since we have a default
        // Will however return false if certificate is not present
        // in found host or default host.
        self.maybe_get_or_default(client_hello.server_name())
            .and_then(|host| host.certificate.as_ref())
            .cloned()
    }
}

/// All the supported ALPN protocols.
///
/// > ***Note:** this is often not needed, as the ALPN protocols
/// are set in [`host::Data::make_config()`].*
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

/// Per host filter output of whether or not to cache a response with some [`StatusCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[repr(u8)]
pub enum CacheAction {
    /// Cache this status code response.
    Cache,
    /// Don't cache, in hope following responses have status codes which can be cached.
    Drop,
}
impl CacheAction {
    /// Returns [`Self::Cache`] if `cache` is true. Else [`Self::Drop`].
    pub fn from_cache(cache: bool) -> Self {
        if cache {
            Self::Cache
        } else {
            Self::Drop
        }
    }
    /// Returns [`Self::Drop`] if `drop` is true. Else [`Self::Cache`].
    pub fn from_drop(drop: bool) -> Self {
        if drop {
            Self::Drop
        } else {
            Self::Cache
        }
    }
    /// Returns true if `self` is [`Self::cache`].
    #[must_use]
    pub fn into_cache(self) -> bool {
        matches!(self, Self::Cache)
    }
    /// Returns true if `self` is [`Self::Drop`].
    #[must_use]
    pub fn into_drop(self) -> bool {
        matches!(self, Self::Drop)
    }
}

/// This is the default for [`Host::status_code_cache_filter`].
///
/// This caches the request on every [`StatusCode`] except
/// [400..403] & [405..500).
pub fn default_status_code_cache_filter(code: StatusCode) -> CacheAction {
    CacheAction::from_drop(matches!(code.as_u16(), 400..=403 | 405..=499))
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

/// A pair of [`rustls::Certificate`] and [`sign::SigningKey`].
///
/// Returned from [`get_certified_key`].
#[cfg(feature = "https")]
pub type CertKeyPair = (Vec<rustls::Certificate>, Arc<dyn sign::SigningKey>);

/// Extracts a [`sign::CertifiedKey`] from `cert_path` and `private_key_path`.
///
/// # Errors
///
/// Will return any errors while reading the files, or any parsing errors.
#[cfg(feature = "https")]
pub fn get_certified_key(
    cert_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
) -> Result<CertKeyPair, CertificateError> {
    let mut chain = io::BufReader::new(std::fs::File::open(&cert_path)?);
    let mut private_key = io::BufReader::new(std::fs::File::open(&private_key_path)?);

    let mut private_keys = Vec::with_capacity(4);
    private_keys.extend(match rustls_pemfile::pkcs8_private_keys(&mut private_key) {
        Ok(key) => key,
        Err(_) => return Err(CertificateError::ImproperPrivateKeyFormat),
    });
    if private_keys.is_empty() {
        private_keys.extend(match rustls_pemfile::rsa_private_keys(&mut private_key) {
            Ok(key) => key,
            Err(_) => return Err(CertificateError::ImproperPrivateKeyFormat),
        });
    }
    let key = match private_keys.into_iter().next() {
        Some(key) => rustls::PrivateKey(key),
        None => return Err(CertificateError::NoKey),
    };

    let key = sign::any_supported_type(&key).map_err(|_| CertificateError::InvalidPrivateKey)?;
    let chain = match rustls_pemfile::certs(&mut chain) {
        Ok(cert) => cert,
        Err(_) => return Err(CertificateError::ImproperCertificateFormat),
    };

    let chain = chain.into_iter().map(rustls::Certificate).collect();

    Ok((chain, key))
}

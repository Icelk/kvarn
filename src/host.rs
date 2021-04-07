use crate::prelude::{internals::*, *};
use rustls::{
    internal::pemfile, sign, ClientHello, NoClientAuth, ResolvesServerCert, ServerConfig,
};
pub struct Host {
    pub host_name: &'static str,
    pub certificate: Option<sign::CertifiedKey>,
    pub path: PathBuf,
    pub extensions: Extensions,
    pub file_cache: FileCache,
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
    pub fn new<P: AsRef<Path>>(
        host_name: &'static str,
        cert_path: P,
        private_key_path: P,
        path: PathBuf,
        extensions: Extensions,
    ) -> Result<Self, (ServerConfigError, Self)> {
        let cert = get_certified_key(cert_path, private_key_path);
        // ToDo: redirect path which ends with . or / to it's index.html
        // extensions.add_prime(&|request, _| {
        //     let uri = unsafe { request.get_inner().uri() };

        //     ready()
        // });
        match cert {
            Ok(cert) => Ok(Self {
                host_name,
                certificate: Some(cert),
                path,
                extensions,
                folder_default: None,
                extension_default: None,
                file_cache: Mutex::new(Cache::with_size_limit(16 * 1024)), // 16KiB
                response_cache: Mutex::new(Cache::new()),
            }),
            Err(err) => Err((
                err,
                Self {
                    host_name,
                    certificate: None,
                    path,
                    extensions,
                    folder_default: None,
                    extension_default: None,
                    file_cache: Mutex::new(Cache::new()),
                    response_cache: Mutex::new(Cache::new()),
                },
            )),
        }
    }
    pub fn no_certification(
        host_name: &'static str,
        path: PathBuf,
        extensions: Extensions,
    ) -> Self {
        Self {
            host_name,
            certificate: None,
            path,
            extensions,
            folder_default: None,
            extension_default: None,
            file_cache: Mutex::new(Cache::with_size_limit(16 * 1024)), // 16KiB
            response_cache: Mutex::new(Cache::new()),
        }
    }

    pub fn with_http_redirect<P: AsRef<Path>>(
        host_name: &'static str,
        cert_path: P,
        private_key_path: P,
        path: PathBuf,
        extensions: Extensions,
    ) -> Self {
        match Host::new(host_name, cert_path, private_key_path, path, extensions) {
            Ok(mut host) => {
                host.set_http_redirect_to_https();
                host
            }
            Err((err, host_without_cert)) => {
                warn!(
                    "Failed to get certificate! Not running host on HTTPS. {:?}",
                    err
                );
                host_without_cert
            }
        }
    }

    pub fn get_folder_default_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.folder_default
            .as_ref()
            .map(String::as_str)
            .unwrap_or(default)
    }
    pub fn get_extension_default_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.extension_default
            .as_ref()
            .map(String::as_str)
            .unwrap_or(default)
    }
    pub fn set_folder_default(&mut self, default: String) {
        self.folder_default = Some(default);
    }
    pub fn set_extension_default(&mut self, default: String) {
        self.extension_default = Some(default);
    }

    pub fn set_http_redirect_to_https(&mut self) {
        const SPECIAL_PATH: &'static str = "/../to_https";
        self.extensions
            .add_prepare_single(SPECIAL_PATH.to_string(), &|mut request, _, _, _| {
                // "/../ path" is special; it will not be accepted from outside.
                // Therefore, we can unwrap on values, making the assumption I implemented them correctly below.
                let request: &FatRequest = unsafe { request.get_inner() };
                let uri = request.uri();
                let uri = {
                    let authority = uri
                        .authority()
                        .map(http::uri::Authority::as_str)
                        .unwrap_or("");
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
            });
        self.extensions.add_prime(&|request, _| {
            let request: &FatRequest = unsafe { request.get_inner() };
            let uri = match request.uri().scheme_str() == Some("http")
                && request.uri().port().is_none()
            {
                // redirect
                true => {
                    let mut uri = request.uri().clone().into_parts();

                    let mut bytes = BytesMut::with_capacity(
                        SPECIAL_PATH.len()
                            + 1
                            + request.uri().path().len()
                            + request.uri().query().map(|s| s.len() + 1).unwrap_or(0),
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
                        Some(http::uri::PathAndQuery::from_maybe_shared(bytes.freeze()).unwrap());
                    let uri = Uri::from_parts(uri).unwrap();
                    Some(uri)
                }
                false => None,
            };
            ready(uri)
        });
    }

    pub fn enable_hsts(&mut self) {
        self.extensions.add_package(&|mut response, request| {
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
        })
    }

    pub fn is_secure(&self) -> bool {
        self.certificate.is_some()
    }
}
impl Debug for Host {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Host {{ certificate, path: {:?}, extensions, fs_cache, folder_default: {:?}, extension_default: {:?} }}",
            self.path, self.folder_default, self.extension_default,
        )
    }
}

#[derive(Debug)]
pub struct HostDataBuilder(HostData);
impl HostDataBuilder {
    pub fn add_host(mut self, host_data: Host) -> Self {
        self.0.add_host(host_data.host_name, host_data);
        self
    }
    pub fn build(self) -> Arc<HostData> {
        Arc::new(self.0)
    }
}
#[derive(Debug)]
pub struct HostData {
    default: Host,
    by_name: HashMap<&'static str, Host>,
    has_secure: bool,
}
impl HostData {
    pub fn builder(default_host: Host) -> HostDataBuilder {
        HostDataBuilder(Self {
            has_secure: default_host.is_secure(),
            default: default_host,
            by_name: HashMap::new(),
        })
    }
    pub fn new(default_host: Host) -> Self {
        Self {
            has_secure: default_host.is_secure(),
            default: default_host,
            by_name: HashMap::new(),
        }
    }
    /// Creates a `Host` without certification, using the directories `./public` and `./templates`.
    pub fn simple(default_host_name: &'static str, extensions: Extensions) -> Self {
        Self {
            default: Host::no_certification(default_host_name, ".".into(), extensions),
            by_name: HashMap::new(),
            has_secure: false,
        }
    }
    pub fn add_host(&mut self, host_name: &'static str, host_data: Host) {
        if host_data.is_secure() {
            self.has_secure = true;
        }
        self.by_name.insert(host_name, host_data);
    }

    pub fn get_default(&self) -> &Host {
        &self.default
    }
    pub fn get_host(&self, host: &str) -> Option<&Host> {
        self.by_name.get(host)
    }
    pub fn get_or_default(&self, host: &str) -> &Host {
        self.get_host(host).unwrap_or(&self.get_default())
    }
    pub fn maybe_get_or_default(&self, maybe_host: Option<&str>) -> &Host {
        match maybe_host {
            Some(host) => self.get_or_default(host),
            None => &self.get_default(),
        }
    }
    pub fn smart_get<'a>(
        &'a self,
        request: &Request<Body>,
        sni_hostname: Option<&str>,
    ) -> &'a Host {
        fn get_header(headers: &HeaderMap) -> Option<&str> {
            headers
                .get(header::HOST)
                .map(HeaderValue::to_str)
                .map(Result::ok)
                .flatten()
        }

        let host = sni_hostname.or_else(|| get_header(request.headers()));

        self.maybe_get_or_default(host)
    }

    pub fn has_secure(&self) -> bool {
        self.has_secure
    }

    pub fn make_config(arc: &Arc<Self>) -> ServerConfig {
        let mut config = ServerConfig::new(NoClientAuth::new());
        let arc = Arc::clone(arc);
        config.cert_resolver = arc;
        config
    }

    pub async fn clear_response_caches(&self) {
        // Handle default host
        self.default.response_cache.lock().await.clear();
        // All other
        for (_, host) in self.by_name.iter() {
            host.response_cache.lock().await.clear();
        }
    }
    /// # Returns
    /// (found host, cleared page)
    pub async fn clear_page(&self, host: &str, uri: &Uri) -> (bool, bool) {
        let key = UriKey::path_and_query(uri);

        let mut found = false;
        let mut cleared = false;
        if host == "" || host == "default" {
            found = true;
            let mut lock = self.default.response_cache.lock().await;
            if key.call_all(|key| lock.remove(key).to_option()).1.is_some() {
                cleared = true;
            }
        } else {
            match self.by_name.get(host) {
                Some(host) => {
                    found = true;
                    let mut lock = host.response_cache.lock().await;
                    if key.call_all(|key| lock.remove(key).to_option()).1.is_some() {
                        cleared = true;
                    }
                }
                None => {}
            }
        }
        (found, cleared)
    }
    pub async fn clear_file_caches(&self) {
        self.default.file_cache.lock().await.clear();
        for (_, host) in self.by_name.iter() {
            host.file_cache.lock().await.clear();
        }
    }
    pub async fn clear_file_in_cache<P: AsRef<Path>>(&self, path: &P) -> bool {
        let mut found = false;
        if self
            .default
            .file_cache
            .lock()
            .await
            .remove(path.as_ref())
            .to_option()
            .is_some()
        {
            found = true;
        }
        for (_, host) in self.by_name.iter() {
            if host
                .file_cache
                .lock()
                .await
                .remove(path.as_ref())
                .to_option()
                .is_some()
            {
                found = true;
            }
        }
        found
    }
}
impl ResolvesServerCert for HostData {
    fn resolve(&self, client_hello: ClientHello) -> Option<sign::CertifiedKey> {
        // Mostly returns true, since we have a default
        // Will however return false if certificate is not present in host
        if let Some(name) = client_hello.server_name() {
            self.by_name
                .get(name.into())
                .unwrap_or(&self.default)
                .certificate
                .clone()
        } else {
            // Else, get default certificate
            self.default.certificate.clone()
        }
    }
}
#[derive(Debug)]
pub struct HostBinding {
    host_data: Arc<HostData>,
    host: Option<*const Host>,
}
impl HostBinding {
    pub fn new(data: Arc<HostData>) -> Self {
        Self {
            host_data: data,
            host: None,
        }
    }

    pub fn get_host(&self) -> Option<&Host> {
        unsafe { self.host.map(|ptr| &*ptr) }
    }
    pub fn get_default(&self) -> &Host {
        &self.host_data.default
    }
    pub fn get_host_or_default(&self) -> &Host {
        unsafe {
            self.host
                .map(|ptr| &*ptr)
                .unwrap_or(&self.host_data.default)
        }
    }
    pub fn get_or_set_host(&mut self, host: &str) -> &Host {
        match self.host {
            Some(host) => unsafe { &*host },
            None => match self.host_data.get_host(host) {
                Some(host) => {
                    self.host = Some(host);
                    host
                }
                None => &self.host_data.default,
            },
        }
    }
    pub fn set_host(&mut self, host: &str) -> Result<(), ()> {
        let data = self.host_data.get_host(host).ok_or(())?;
        self.host = Some(data as *const Host);
        Ok(())
    }
}

#[derive(Debug)]
pub enum ServerConfigError {
    IO(io::Error),
    ImproperPrivateKeyFormat,
    ImproperCertificateFormat,
    NoKey,
    InvalidPrivateKey,
}
impl From<io::Error> for ServerConfigError {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}

/// Get a certified key to use (maybe) when adding domain certificates to the server
pub fn get_certified_key<P: AsRef<Path>>(
    cert_path: P,
    private_key_path: P,
) -> Result<sign::CertifiedKey, ServerConfigError> {
    let mut chain = io::BufReader::new(std::fs::File::open(&cert_path)?);
    let mut private_key = io::BufReader::new(std::fs::File::open(&private_key_path)?);

    let mut private_keys = Vec::with_capacity(4);
    private_keys.extend(match pemfile::pkcs8_private_keys(&mut private_key) {
        Ok(key) => key,
        Err(()) => return Err(ServerConfigError::ImproperPrivateKeyFormat),
    });
    if private_keys.is_empty() {
        private_keys.extend(match pemfile::rsa_private_keys(&mut private_key) {
            Ok(key) => key,
            Err(()) => return Err(ServerConfigError::ImproperPrivateKeyFormat),
        });
    }
    let key = match private_keys.get(0) {
        Some(key) => key,
        None => return Err(ServerConfigError::NoKey),
    };

    let key = sign::any_supported_type(key).map_err(|_| ServerConfigError::InvalidPrivateKey)?;
    let chain = match pemfile::certs(&mut chain) {
        Ok(cert) => cert,
        Err(()) => return Err(ServerConfigError::ImproperCertificateFormat),
    };

    Ok(sign::CertifiedKey::new(chain, Arc::new(key)))
}

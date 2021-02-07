use crate::prelude::{fs::*, *};
use rustls::{
    internal::pemfile, sign, ClientHello, NoClientAuth, ResolvesServerCert, ServerConfig,
};

#[derive(Debug)]
struct HostStorage {
    pub cache: sync::Mutex<cache::types::ResponseCacheInner>,
    pub bindings: FunctionBindings,
    pub bindings_http_override: Option<FunctionBindings>,
}
impl HostStorage {
    pub fn new(bindings: FunctionBindings, max_cache_entities: usize) -> Self {
        Self {
            cache: sync::Mutex::new(cache::Cache::with_max(max_cache_entities)),
            bindings,
            bindings_http_override: None,
        }
    }
}

pub const HTTP_REDIRECT_NO_HOST: &[u8] = b"\
HTTP/1.1 505 HTTP Version Not Supported\r\n\
Content-Type: text/html\r\n\
Connection: keep-alive\r\n\
Content-Encoding: identity\r\n\
Content-Length: 514\r\n\
\r\n\
<html>\
    <head>\
        <title>Failed to redirect</title>\
    </head>\
    <body>\
        <center>\
            <h1>Failed to redirect you to security</h1>\
            <hr>\
            <p>You have accessed this site using the HTTP1.1 protocol. It is not secure. Your agent (e.g. browser) is not sending an <code>Host</code> header, so we weren't aviable to redirect you automatically.</p>\
            <p>Please try to access this website with <code>https://</code> before the URL, not <code>http://</code>. If this error persists, please contact the website administrator.</p>\
        </center>\
    </body>\
</html>\
";
pub(crate) const HOST_RESPONSE_MAX_ENTITIES: usize = 512;
pub struct Host {
    pub certificate: Option<sign::CertifiedKey>,
    pub path: PathBuf,
    storage: HostStorage,

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
        cert_path: P,
        private_key_path: P,
        path: P,
        bindings: Option<FunctionBindings>,
    ) -> Result<Self, (ServerConfigError, Self)> {
        let cert = get_certified_key(cert_path, private_key_path);
        match cert {
            Ok(cert) => Ok(Self {
                certificate: Some(cert),
                path: path.as_ref().to_owned(),
                storage: match bindings {
                    Some(bindings) => HostStorage::new(bindings, HOST_RESPONSE_MAX_ENTITIES),
                    None => HostStorage::new(FunctionBindings::new(), HOST_RESPONSE_MAX_ENTITIES),
                },
                folder_default: None,
                extension_default: None,
            }),
            Err(err) => Err((
                err,
                Self {
                    certificate: None,
                    path: path.as_ref().to_owned(),
                    storage: match bindings {
                        Some(bindings) => HostStorage::new(bindings, HOST_RESPONSE_MAX_ENTITIES),
                        None => {
                            HostStorage::new(FunctionBindings::new(), HOST_RESPONSE_MAX_ENTITIES)
                        }
                    },
                    folder_default: None,
                    extension_default: None,
                },
            )),
        }
    }
    pub fn no_certification<P: AsRef<Path>>(path: P, bindings: Option<FunctionBindings>) -> Self {
        Self {
            certificate: None,
            path: path.as_ref().to_owned(),
            storage: match bindings {
                Some(bindings) => HostStorage::new(bindings, HOST_RESPONSE_MAX_ENTITIES),
                None => HostStorage::new(FunctionBindings::new(), HOST_RESPONSE_MAX_ENTITIES),
            },
            folder_default: None,
            extension_default: None,
        }
    }

    pub fn with_http_redirect<P: AsRef<Path>>(
        cert_path: P,
        private_key_path: P,
        path: P,
        bindings: Option<FunctionBindings>,
    ) -> Self {
        match Host::new(cert_path, private_key_path, path, bindings) {
            Ok(mut host) => {
                host.set_http_redirect_to_https();
                host
            }
            Err((err, host_without_cert)) => {
                eprintln!(
                    "Failed to get certificate! Not running host on HTTPS. {:?}",
                    err
                );
                host_without_cert
            }
        }
    }

    /// Gets the lock of response cache.
    #[inline]
    pub fn get_cache(&self) -> Option<sync::MutexGuard<'_, cache::types::ResponseCacheInner>> {
        #[cfg(feature = "no-response-cache")]
        return None;
        #[cfg(not(feature = "no-response-cache"))]
        match self.storage.cache.lock() {
            Ok(lock) => Some(lock),
            Err(..) => panic!("Lock is poisoned!"),
        }
    }
    pub fn get_bindings(&self) -> &FunctionBindings {
        &self.storage.bindings
    }
    pub fn get_binding_overrides(&self) -> Option<&FunctionBindings> {
        self.storage.bindings_http_override.as_ref()
    }
    pub fn set_binding_overrides(&mut self, bindings: Option<FunctionBindings>) {
        self.storage.bindings_http_override = bindings;
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
        let mut bindings = FunctionBindings::new();

        bindings.bind_dir("/", |buffer, request, _| {
            match request.headers().get("host").and_then(to_option_str) {
                Some(host) => {
                    buffer.extend_from_slice(
                        b"HTTP/1.1 308 Permanent Redirect\r\nlocation: https://",
                    );
                    buffer.extend_from_slice(host.as_bytes());
                    buffer.extend_from_slice(
                        request
                            .uri()
                            .path_and_query()
                            .map(|p| p.as_str().as_bytes())
                            .unwrap_or(b"/"),
                    );
                    buffer.extend_from_slice(b"\r\ncontent-length: 0\r\n\r\n");
                }
                None => {
                    buffer.extend_from_slice(HTTP_REDIRECT_NO_HOST);
                }
            };
            (Html, StaticClient)
        });

        self.storage.bindings_http_override = Some(bindings);
    }

    pub fn is_secure(&self) -> bool {
        self.certificate.is_some()
    }
}
impl Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Host {{ certificate, path: {:?}, storage: {:?} }}",
            self.path, self.storage,
        )
    }
}

#[derive(Debug)]
pub struct HostDataBuilder(HostData);
impl HostDataBuilder {
    pub fn add_host(mut self, host_name: String, host_data: Host) -> Self {
        self.0.add_host(host_name, host_data);
        self
    }
    pub fn build(self) -> Arc<HostData> {
        Arc::new(self.0)
    }
}
#[derive(Debug)]
pub struct HostData {
    default: Host,
    by_name: HashMap<String, Host>,
    has_secure: bool,
}
impl HostData {
    pub fn builder(default: Host) -> HostDataBuilder {
        HostDataBuilder(Self {
            has_secure: default.is_secure(),
            default,
            by_name: HashMap::new(),
        })
    }
    pub fn new(default: Host) -> Self {
        Self {
            has_secure: default.is_secure(),
            default,
            by_name: HashMap::new(),
        }
    }
    /// Creates a `Host` without certification, using the directories `/public` and `/templates`.
    pub fn simple(bindings: Option<FunctionBindings>) -> Self {
        Self {
            default: Host::no_certification(".", bindings),
            by_name: HashMap::new(),
            has_secure: false,
        }
    }
    pub fn add_host(&mut self, host_name: String, host_data: Host) {
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

    pub fn has_secure(&self) -> bool {
        self.has_secure
    }

    pub fn build(self) -> Arc<Self> {
        Arc::new(self)
    }
    pub fn make_config(arc: &Arc<Self>) -> ServerConfig {
        let mut config = ServerConfig::new(NoClientAuth::new());
        let arc = Arc::clone(arc);
        config.cert_resolver = arc;
        config
    }

    pub fn clear_all_caches(&self) -> usize {
        let mut cleared = 0;

        // Handle default host
        match self.default.get_cache() {
            Some(mut lock) => {
                lock.clear();
                cleared += 1;
            }
            None => {}
        }
        // All other
        for (_, host) in self.by_name.iter() {
            match host.get_cache() {
                Some(mut lock) => {
                    lock.clear();
                    cleared += 1;
                }
                None => {}
            }
        }
        cleared
    }
    pub fn clear_page(&self, host: &str, uri: &http::Uri) -> (usize, bool) {
        let mut found = false;
        let mut cleared = 0;
        if host == "" || host == "default" {
            found = true;
            match self.default.get_cache() {
                Some(mut lock) => {
                    cleared += if lock.remove(uri).is_some() { 1 } else { 0 };
                }
                None => {}
            }
        } else {
            for (name, host_data) in self.by_name.iter() {
                if host == name {
                    found = true;
                    match host_data.get_cache() {
                        Some(mut lock) => {
                            cleared += if lock.remove(uri).is_some() { 1 } else { 0 };
                        }
                        None => {}
                    }
                }
            }
        }
        (cleared, found)
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
    let mut chain = io::BufReader::new(File::open(&cert_path)?);
    let mut private_key = io::BufReader::new(File::open(&private_key_path)?);

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

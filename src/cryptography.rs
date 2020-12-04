use crate::prelude::{fs::*, *};
use rustls::{
    internal::pemfile, sign, ClientHello, NoClientAuth, ResolvesServerCert, ServerConfig,
};

#[derive(Debug)]
struct HostStorage {
    pub cache: sync::Mutex<cache::types::ResponseCacheInner>,
    pub bindings: FunctionBindings,
}
impl HostStorage {
    pub fn new(bindings: FunctionBindings, max_cache_entities: usize) -> Self {
        Self {
            cache: sync::Mutex::new(cache::Cache::with_max(max_cache_entities)),
            bindings,
        }
    }
}

pub(crate) const HOST_RESPONSE_MAX_ENTITIES: usize = 512;
pub struct Host {
    pub certificate: Option<sign::CertifiedKey>,
    pub path: PathBuf,
    storage: HostStorage,
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
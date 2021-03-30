use crate::comprash::{Cache, CachedCompression, FileCache, PathQuery, ResponseCache, UriKey};
use crate::extensions::Extensions;
use crate::prelude::{fs::*, *};
use rustls::{
    internal::pemfile, sign, ClientHello, NoClientAuth, ResolvesServerCert, ServerConfig,
};
use tokio::sync::Mutex;

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
    pub extensions: Extensions,
    pub file_cache: FileCache,
    pub response_cache: Mutex<Cache<UriKey, CachedCompression>>,

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
        path: PathBuf,
        extensions: Extensions,
    ) -> Result<Self, (ServerConfigError, Self)> {
        let cert = get_certified_key(cert_path, private_key_path);
        match cert {
            Ok(cert) => Ok(Self {
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
    pub fn no_certification(path: PathBuf, extensions: Extensions) -> Self {
        Self {
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
        cert_path: P,
        private_key_path: P,
        path: PathBuf,
        extensions: Extensions,
    ) -> Self {
        match Host::new(cert_path, private_key_path, path, extensions) {
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
        self.extensions.add_prime(&|uri| match uri.scheme_str() {
            Some("http") => {
                let mut uri = uri.clone().into_parts();
                let authority = match uri.authority {
                    Some(authority) => {
                        let authority = format!("https{}", &authority.as_str()[4..]);
                        let authority = Vec::from(authority);
                        // it must be a valid URI; unwrap is OK

                        Some(http::uri::Authority::from_maybe_shared(authority).unwrap())
                    }
                    None => None,
                };
                uri.authority = authority;

                // again, must be valid
                Some(http::Uri::from_parts(uri).unwrap())
            }
            _ => None,
        })
    }

    pub fn is_secure(&self) -> bool {
        self.certificate.is_some()
    }
}
impl Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    default: (String, Host),
    by_name: HashMap<String, Host>,
    has_secure: bool,
}
impl HostData {
    pub fn builder(default_host_name: String, default_host: Host) -> HostDataBuilder {
        HostDataBuilder(Self {
            has_secure: default_host.is_secure(),
            default: (default_host_name, default_host),
            by_name: HashMap::new(),
        })
    }
    pub fn new(default_host_name: String, default_host: Host) -> Self {
        Self {
            has_secure: default_host.is_secure(),
            default: (default_host_name, default_host),
            by_name: HashMap::new(),
        }
    }
    /// Creates a `Host` without certification, using the directories `./public` and `./templates`.
    pub fn simple(default_host_name: String, extensions: Extensions) -> Self {
        Self {
            default: (
                default_host_name,
                Host::no_certification(".".into(), extensions),
            ),
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

    pub fn get_default(&self) -> &(String, Host) {
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

    pub async fn clear_all_caches(&self) -> usize {
        // Handle default host
        self.default.1.file_cache.lock().await.clear();
        // All other
        for (_, host) in self.by_name.iter() {
            host.file_cache.lock().await.clear();
        }
        1 + self.by_name.len()
    }
    /// Returns `Ok` if it cleared a page.
    pub async fn clear_page(&self, host: &str, uri: &http::Uri) -> Result<(), ()> {
        let key = UriKey::path_and_query(uri);

        let mut found = false;
        if host == "" || host == "default" {
            let mut lock = self.default.1.response_cache.lock().await;
            if key.call_all(|key| lock.remove(key).to_option()).1.is_some() {
                found = true;
            }
        } else {
            match self.by_name.get(host) {
                Some(host) => {
                    let mut lock = host.response_cache.lock().await;
                    if key.call_all(|key| lock.remove(key).to_option()).1.is_some() {
                        found = true;
                    }
                }
                None => {}
            }
        }
        match found {
            false => Err(()),
            true => Ok(()),
        }
    }
}
impl ResolvesServerCert for HostData {
    fn resolve(&self, client_hello: ClientHello) -> Option<sign::CertifiedKey> {
        // Mostly returns true, since we have a default
        // Will however return false if certificate is not present in host
        if let Some(name) = client_hello.server_name() {
            self.by_name
                .get(name.into())
                .unwrap_or(&self.default.1)
                .certificate
                .clone()
        } else {
            // Else, get default certificate
            self.default.1.certificate.clone()
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
        &self.host_data.default.1
    }
    pub fn get_host_or_default(&self) -> &Host {
        unsafe {
            self.host
                .map(|ptr| &*ptr)
                .unwrap_or(&self.host_data.default.1)
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
                None => &self.host_data.default.1,
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

use crate::*;
use application::Body;
use bytes::{Bytes, BytesMut};
use comprash::{ClientCachePreference, CompressPreference, ServerCachePreference};
use http::Uri;
use std::future::Future;

pub type RetFut<T> = Box<dyn Future<Output = T>>;
pub type FsCache = ();
pub type Request = http::Request<application::Body>;
pub type Response = (
    http::Response<BytesMut>,
    ClientCachePreference,
    ServerCachePreference,
    CompressPreference,
);

pub type Prime = &'static (dyn Fn(&Uri) -> Option<Uri> + Sync);
pub type Pre = &'static (dyn Fn(&mut Request, FsCache) -> RetFut<Option<Response>> + Sync);
pub type Prepare = &'static (dyn Fn(&Request, FsCache) -> RetFut<Response> + Sync);
pub type Present = &'static (dyn Fn(PresentData) -> RetFut<()> + Sync);
pub type Package = &'static (dyn Fn(&mut http::Response<Bytes>) -> RetFut<()> + Sync);
pub type Post = &'static (dyn Fn(&Bytes, &mut application::ResponsePipe) -> RetFut<()> + Sync);

/// # Safety
/// It's not safe at all. This type must not be stored.
/// Only one pointer should *own* the data; this should be created, passed to an extension, and destroyed. Then the next extension can kick in.
pub struct PresentData {
    // Regarding request
    address: net::SocketAddr,
    request: *const http::Request<Body>,
    host: *const Host,
    path: *const Path,
    // Regarding response
    server_cache_preference: ServerCachePreference,
    client_cache_preference: ClientCachePreference,
    response: *mut http::Response<Bytes>,
    // Regarding extension
    args: Vec<String>,
}
impl PresentData {
    pub fn address(&self) -> net::SocketAddr {
        self.address
    }
    pub fn request(&self) -> &http::Request<Body> {
        unsafe { &*self.request }
    }
    pub fn host(&self) -> &Host {
        unsafe { &*self.host }
    }
    pub fn path(&self) -> &Path {
        unsafe { &*self.path }
    }
    pub fn server_cache_preference(&mut self) -> &mut ServerCachePreference {
        &mut self.server_cache_preference
    }
    pub fn client_cache_preference(&mut self) -> &mut ClientCachePreference {
        &mut self.client_cache_preference
    }
    pub fn response_mut(&mut self) -> &mut http::Response<Bytes> {
        unsafe { &mut *self.response }
    }
    pub fn response(&mut self) -> &http::Response<Bytes> {
        unsafe { &*self.response }
    }
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

/// Contains all extensions.
/// See [extensions.md](../extensions.md) for more info.
///
/// ToDo: remove and list? Give mut access to underlying `Vec`s and `HashMap`s or a `Entry`-like interface?
pub struct Extensions {
    prime: Vec<Prime>,
    pre: HashMap<String, Pre>,
    prepare_single: HashMap<String, Prepare>,
    prepare_dir: Vec<(String, Prepare)>,
    present_internal: HashMap<String, Present>,
    present_file: HashMap<String, Present>,
    package: Vec<Package>,
    post: Vec<Post>,
}
impl Extensions {
    pub fn new() -> Self {
        Self {
            prime: Vec::new(),
            pre: HashMap::new(),
            prepare_single: HashMap::new(),
            prepare_dir: Vec::new(),
            present_internal: HashMap::new(),
            present_file: HashMap::new(),
            package: Vec::new(),
            post: Vec::new(),
        }
    }

    /// Adds a prime extension.
    pub fn add_prime(&mut self, extension: Prime) {
        self.prime.push(extension);
    }
    /// Adds a pre extension.
    pub fn add_pre(&mut self, path: String, extension: Pre) {
        self.pre.insert(path, extension);
    }
    /// Adds a prepare extension for a single URI.
    pub fn add_prepare_single(&mut self, path: String, extension: Prepare) {
        self.prepare_single.insert(path, extension);
    }
    /// Adds a prepare extension for a whole directory.
    pub fn add_prepare_dir(&mut self, path: String, extension: Prepare) {
        self.prepare_dir.push((path, extension));
    }
    /// Adds a present internal extension, called with files starting with `!> `.
    pub fn add_present_internal(&mut self, name: String, extension: Present) {
        self.present_internal.insert(name, extension);
    }
    /// Adds a present file extension, called with file extensions matching `name`.
    pub fn add_present_file(&mut self, name: String, extension: Present) {
        self.present_file.insert(name, extension);
    }
    /// Adds a package extension, used to make last-minute changes to response.
    pub fn add_package(&mut self, extension: Package) {
        self.package.push(extension);
    }
    /// Adds a post extension, used for HTTP/2 push
    pub fn add_post(&mut self, extension: Post) {
        self.post.push(extension);
    }
}

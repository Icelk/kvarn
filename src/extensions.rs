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
pub type Present = &'static (dyn Fn(&mut PresentData<'_>) + Sync);
pub type Package = &'static (dyn Fn(&mut http::Response<BytesMut>) + Sync);
pub type Post = &'static (dyn Fn(&Bytes, &mut application::ResponsePipe) + Sync);

pub struct PresentData<'a> {
    // Regarding request
    pub address: net::SocketAddr,
    pub request: &'a http::Request<Body>,
    pub host: &'a Host,
    // Regarding response
    pub server_cache_preference: ServerCachePreference,
    pub client_cache_preference: ClientCachePreference,
    // Regarding extension
    pub args: Vec<String>,
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

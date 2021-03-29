use crate::*;
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
pub struct PresentData<'a> {
    _priv: &'a (),
}

/// Contains all extensions.
/// See [extensions.md](../extensions.md) for more info.
///
/// ToDo: remove and list? Give mut access to underlying `Vec`s and `HashMap`s or a `Entry`-like interface?
pub struct Extensions {
    prime: Vec<&'static (dyn Fn(&Uri) -> Option<Uri> + Sync)>,
    pre: HashMap<
        String,
        &'static (dyn Fn(&mut Request, FsCache) -> RetFut<Option<Response>> + Sync),
    >,
    prepare_single:
        HashMap<String, &'static (dyn Fn(&Request, FsCache) -> RetFut<Response> + Sync)>,
    prepare_dir: Vec<(
        String,
        &'static (dyn Fn(&Request, FsCache) -> RetFut<Response> + Sync),
    )>,
    present_internal: HashMap<String, &'static (dyn Fn(&mut PresentData<'_>) + Sync)>,
    present_file: HashMap<String, &'static (dyn Fn(&mut PresentData<'_>) + Sync)>,
    package: Vec<&'static (dyn Fn(&mut http::Response<BytesMut>) + Sync)>,
    post: Vec<&'static (dyn Fn(&Bytes, &mut application::ResponsePipe) + Sync)>,
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
    pub fn add_prime(&mut self, extension: &'static (dyn Fn(&Uri) -> Option<Uri> + Sync)) {
        self.prime.push(extension);
    }
    /// Adds a pre extension.
    pub fn add_pre(
        &mut self,
        path: String,
        extension: &'static (dyn Fn(&mut Request, FsCache) -> RetFut<Option<Response>> + Sync),
    ) {
        self.pre.insert(path, extension);
    }
    /// Adds a prepare extension for a single URI.
    pub fn add_prepare_single(
        &mut self,
        path: String,
        extension: &'static (dyn Fn(&Request, FsCache) -> RetFut<Response> + Sync),
    ) {
        self.prepare_single.insert(path, extension);
    }
    /// Adds a prepare extension for a whole directory.
    pub fn add_prepare_dir(
        &mut self,
        path: String,
        extension: &'static (dyn Fn(&Request, FsCache) -> RetFut<Response> + Sync),
    ) {
        self.prepare_dir.push((path, extension));
    }
    /// Adds a present internal extension, called with files starting with `!> `.
    pub fn add_present_interna(
        &mut self,
        name: String,
        extension: &'static (dyn Fn(&mut PresentData<'_>) + Sync),
    ) {
        self.present_internal.insert(name, extension);
    }
    /// Adds a present file extension, called with file extensions matching `name`.
    pub fn add_present_file(
        &mut self,
        name: String,
        extension: &'static (dyn Fn(&mut PresentData<'_>) + Sync),
    ) {
        self.present_file.insert(name, extension);
    }
    /// Adds a package extension, used to make last-minute changes to response.
    pub fn add_package(
        &mut self,
        extension: &'static (dyn Fn(&mut http::Response<BytesMut>) + Sync),
    ) {
        self.package.push(extension);
    }
    /// Adds a post extension, used for HTTP/2 push
    pub fn add_post(
        &mut self,
        extension: &'static (dyn Fn(&Bytes, &mut application::ResponsePipe) + Sync),
    ) {
        self.post.push(extension);
    }
}

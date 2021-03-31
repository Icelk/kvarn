//! # Extensions framework for Kvarn.
//!
//! Here, all extensions code is housed
//!
//! ## Unsafe pointers
//!
//! ### Background
//! In the extension code, I sometimes have to pass references of data to `Futures` to avoid cloning,
//! which sometimes is not an option (such as when a `TcpStream` is part of said data).
//! You cannot share references with `Futures`, and so I've opted to go the unsafe route. Literally.
//!
//! ### Implementation
//! In this module, there are several `Wrapper` types. They ***must not*** be stored.
//! It's safe to get the underlying type is you are inside the extension which received the data;
//! I'm awaiting you, guaranteeing the data isn't touched by anyone but the single extension.
//! If you use it later, I probably have dropped the data.
use crate::*;
use application::Body;
use comprash::{ClientCachePreference, CompressPreference, ServerCachePreference};
use http::Uri;
use prelude::*;
use std::future::Future;

pub type RetFut<T> = Box<dyn Future<Output = T>>;
pub type FsCache = ();
pub type Request = http::Request<application::Body>;
pub type Response = (
    http::Response<Bytes>,
    ClientCachePreference,
    ServerCachePreference,
    CompressPreference,
);

pub type Prime = &'static (dyn Fn(&Uri) -> Option<Uri> + Sync);
pub type Pre = &'static (dyn Fn(RequestWrapperMut, FsCache) -> RetFut<Option<Response>> + Sync);
pub type Prepare = &'static (dyn Fn(RequestWrapper, FsCache) -> RetFut<Response> + Sync);
pub type Present = &'static (dyn Fn(PresentDataWrapper) -> RetFut<()> + Sync);
pub type Package = &'static (dyn Fn(ResponseWrapperMut) -> RetFut<()> + Sync);
pub type Post = &'static (dyn Fn(Bytes, ResponsePipeWrapperMut) -> RetFut<()> + Sync);

pub const EXTENSION_PREFIX: &[u8] = &[BANG, PIPE, SPACE];
pub const EXTENSION_AND: &[u8] = &[SPACE, AMPERSAND, PIPE, SPACE];

macro_rules! get_unsafe {
    ($main:ty, $return:ty) => {
        impl $main {
            pub(crate) fn new(data: &$return) -> Self {
                Self(data)
            }
            /// See [module level documentation](crate::extensions).
            pub unsafe fn get_inner(&self) -> &$return {
                &*self.0
            }
        }
    };
}
macro_rules! get_unsafe_mut {
    ($main:ty, $return:ty) => {
        impl $main {
            pub(crate) fn new(data: &mut $return) -> Self {
                Self(data)
            }
            /// See [module level documentation](crate::extensions).
            pub unsafe fn get_inner(&mut self) -> &mut $return {
                &mut *self.0
            }
        }
    };
}

pub struct RequestWrapper(*const Request);
get_unsafe!(RequestWrapper, Request);

pub struct RequestWrapperMut(*mut Request);
get_unsafe_mut!(RequestWrapperMut, Request);
pub struct ResponseWrapperMut(*mut http::Response<Bytes>);
get_unsafe_mut!(ResponseWrapperMut, http::Response<Bytes>);

pub struct ResponsePipeWrapperMut(*mut application::ResponsePipe);
get_unsafe_mut!(ResponsePipeWrapperMut, application::ResponsePipe);

// impl
pub struct PresentDataWrapper(PresentData);
impl PresentDataWrapper {
    /// # Safety
    /// See [module level documentation](crate::extensions).
    ///
    /// It's safe to call this if it's within the future of your extension.
    /// Else, the data will have been dropped.
    ///
    /// You **must** not store this type.
    pub unsafe fn get_inner(&mut self) -> &mut PresentData {
        &mut self.0
    }
}

/// Add data pretending to present state in creating the response.
///
/// Can be acquired from [`PresentDataWrapper`].
///
/// See [module level documentation](crate::extensions).
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
#[derive(Clone)]
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

#[derive(Debug)]
pub struct PresentExtensions {
    data: Bytes,
    // Will have the start and end of name of extensions as first tuple,
    // then the name/argument start and length as second.
    // There wil be several names starting on same position.
    extensions: Vec<((usize, usize), (usize, usize))>,
}
impl PresentExtensions {
    pub fn new(data: Bytes) -> Option<Self> {
        let mut extensions_args =
            Vec::with_capacity(
                data.iter()
                    .fold(1, |acc, byte| if *byte == SPACE { acc + 1 } else { acc }),
            );

        if !data.starts_with(EXTENSION_PREFIX)
            || data[EXTENSION_PREFIX.len()..].starts_with(EXTENSION_AND)
        {
            return None;
        }
        let mut start = EXTENSION_PREFIX.len();
        let mut last_name = None;
        for (pos, byte) in data.iter().enumerate().skip(3) {
            if start > pos {
                continue;
            }
            let byte = *byte;

            if byte == SPACE || byte == CR || byte == LF {
                if str::from_utf8(&data[start..pos]).is_err() {
                    return None;
                }
                let len = pos - start;
                let span = (start, len);
                match last_name {
                    Some(name) => extensions_args.push((name, span)),
                    None => {
                        last_name = Some((start, len));
                        extensions_args.push((span, span))
                    }
                }
                if byte == CR || byte == LF {
                    return Some(Self {
                        data,
                        extensions: extensions_args,
                    });
                }
                start = if data[pos..].starts_with(EXTENSION_AND) {
                    last_name = None;
                    pos + EXTENSION_AND.len()
                } else {
                    pos + 1
                };
            }
        }

        None
    }
    pub fn iter(&self) -> PresentExtensionsIter {
        PresentExtensionsIter {
            data: &self,
            index: 0,
        }
    }
}
#[derive(Debug)]
pub struct PresentExtensionsIter<'a> {
    data: &'a PresentExtensions,
    index: usize,
}
impl<'a> Iterator for PresentExtensionsIter<'a> {
    type Item = PresentArguments<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.index;
        if start == self.data.extensions.len() {
            return None;
        }
        let name = self.data.extensions[start].0;

        let mut iter = self.data.extensions[start + 1..].iter();

        while let Some(current) = iter.next() {
            self.index += 1;
            if current.0 != name {
                break;
            }
        }
        // Cannot change name ↑ on last item; the end of each *peeks* forward one. If it's next to the end, add one.
        if self.index + 1 == self.data.extensions.len() {
            self.index += 1
        };
        Some(PresentArguments {
            data: self.data,
            data_index: start,
            len: self.index - start,
            index: 1,
        })
    }
}
#[derive(Debug)]
pub struct PresentArguments<'a> {
    data: &'a PresentExtensions,
    data_index: usize,
    len: usize,
    index: usize,
}
impl<'a> PresentArguments<'a> {
    pub fn name(&self) -> &str {
        // .1 and .0 should be the same; the name of (usize, usize) should have the same name as it's first argument.
        let (start, len) = self.data.extensions[self.data_index].0;
        // safe, because we checked for str in creation of [`PresentExtensions`].
        unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) }
    }
}
impl<'a> Iterator for PresentArguments<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.len {
            return None;
        }
        let (start, len) = self.data.extensions[self.data_index + self.index].1;
        self.index += 1;
        // Again, safe because we checked for str in creation of [`PresentExtensions`].
        Some(unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) })
    }
}

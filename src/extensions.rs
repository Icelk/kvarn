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
use crate::prelude::{internals::*, *};

pub type RetFut<T> = Pin<Box<(dyn Future<Output = T> + Send)>>;
pub type RetSyncFut<T> = Pin<Box<(dyn Future<Output = T> + Send + Sync)>>;

pub type Prime = &'static (dyn Fn(RequestWrapper, SocketAddr) -> RetFut<Option<Uri>> + Sync);
pub type Pre = &'static (dyn Fn(RequestWrapperMut, HostWrapper) -> RetFut<Option<(FatResponse, RetSyncFut<()>)>>
              + Sync);
pub type Prepare = &'static (dyn Fn(RequestWrapperMut, HostWrapper, PathWrapper, SocketAddr) -> RetFut<FatResponse>
              + Sync);

pub type Present = &'static (dyn Fn(PresentDataWrapper) -> RetFut<()> + Sync);
pub type Package = &'static (dyn Fn(EmptyResponseWrapperMut, RequestWrapper) -> RetFut<()> + Sync);
pub type Post = &'static (dyn Fn(
    RequestWrapper,
    Bytes,
    ResponsePipeWrapperMut,
    SocketAddr,
    HostWrapper,
) -> RetFut<()>
              + Sync);
pub type If = &'static (dyn Fn(&FatRequest) -> bool + Sync);

pub fn invalid_method(
    _: RequestWrapper,
    cache: HostWrapper,
    _: PathWrapper,
) -> RetFut<FatResponse> {
    Box::pin(async move {
        (
            utility::default_error(
                StatusCode::METHOD_NOT_ALLOWED,
                Some(unsafe { &cache.get_inner().file_cache }),
            )
            .await,
            ClientCachePreference::Full,
            ServerCachePreference::Full,
            CompressPreference::Full,
        )
    })
}

pub const PRESENT_INTERNAL_PREFIX: &[u8] = &[BANG, PIPE, SPACE];
pub const PRESENT_INTERNAL_AND: &[u8] = &[SPACE, AMPERSAND, PIPE, SPACE];

#[macro_export]
macro_rules! ext {
    ($($item:tt)*) => {
        Box::pin(async move { $($item)* })
    };
}
// ToDo: Add macro to declare whole extension functions. Perhaps one per extension type? That can then also get_inner on types.

macro_rules! impl_get_unsafe {
    ($main:ident, $return:ty) => {
        pub struct $main(*const $return);
        impl $main {
            pub(crate) fn new(data: &$return) -> Self {
                Self(data)
            }
            /// See [module level documentation](crate::extensions).
            pub unsafe fn get_inner(&self) -> &$return {
                &*self.0
            }
        }
        unsafe impl Send for $main {}
        unsafe impl Sync for $main {}
    };
}
macro_rules! impl_get_unsafe_mut {
    ($main:ident, $return:ty) => {
        pub struct $main(*mut $return);
        impl $main {
            pub(crate) fn new(data: &mut $return) -> Self {
                Self(data)
            }
            /// See [module level documentation](crate::extensions).
            pub unsafe fn get_inner(&mut self) -> &mut $return {
                &mut *self.0
            }
        }
        unsafe impl Send for $main {}
        unsafe impl Sync for $main {}
    };
}

impl_get_unsafe!(RequestWrapper, FatRequest);
impl_get_unsafe_mut!(RequestWrapperMut, FatRequest);
impl_get_unsafe_mut!(EmptyResponseWrapperMut, Response<()>);
impl_get_unsafe_mut!(ResponsePipeWrapperMut, application::ResponsePipe);
impl_get_unsafe!(HostWrapper, Host);
impl_get_unsafe!(PathWrapper, Path);

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
#[derive(Debug)]
pub struct PresentData {
    // Regarding request
    address: SocketAddr,
    request: *const Request<Bytes>,
    host: *const Host,
    path: *const Path,
    // Regarding response
    server_cache_preference: ServerCachePreference,
    client_cache_preference: ClientCachePreference,
    response: *mut Response<Bytes>,
    // Regarding extension
    args: PresentArguments,
}
impl PresentData {
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn request(&self) -> &Request<Bytes> {
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
    pub fn response_mut(&mut self) -> &mut Response<Bytes> {
        unsafe { &mut *self.response }
    }
    pub fn response(&self) -> &Response<Bytes> {
        unsafe { &*self.response }
    }
    pub fn args(&self) -> &PresentArguments {
        &self.args
    }
}
unsafe impl Send for PresentData {}
unsafe impl Sync for PresentData {}

/// Contains all extensions.
/// See [extensions.md](../extensions.md) for more info.
///
/// ToDo: remove and list? Give mut access to underlying `Vec`s and `HashMap`s or a `Entry`-like interface?
#[derive(Clone)]
pub struct Extensions {
    prime: Vec<Prime>,
    pre: HashMap<String, Pre>,
    prepare_single: HashMap<String, Prepare>,
    prepare_fn: Vec<(If, Prepare)>,
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
            prepare_fn: Vec::new(),
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
    /// Adds a prepare extension run if `function` return `true`.
    pub fn add_prepare_fn(&mut self, function: If, extension: Prepare) {
        self.prepare_fn.push((function, extension));
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

    pub async fn resolve_prime(&self, request: &FatRequest, address: SocketAddr) -> Option<Uri> {
        for prime in self.prime.iter() {
            if let Some(prime) = prime(RequestWrapper::new(request), address).await {
                return Some(prime);
            }
        }
        None
    }
    pub async fn resolve_pre(
        &self,
        request: &mut FatRequest,
        host: &Host,
    ) -> Option<(FatResponse, RetSyncFut<()>)> {
        match self.pre.get(request.uri().path()) {
            Some(extension) => {
                extension(RequestWrapperMut::new(request), HostWrapper::new(host)).await
            }
            None => None,
        }
    }
    pub async fn resolve_prepare(
        &self,
        request: &mut FatRequest,
        host: &Host,
        path: &Path,
        address: SocketAddr,
    ) -> Option<FatResponse> {
        match self.prepare_single.get(request.uri().path()) {
            Some(extension) => Some(
                extension(
                    RequestWrapperMut::new(request),
                    HostWrapper::new(host),
                    PathWrapper::new(path),
                    address,
                )
                .await,
            ),
            None => {
                for (function, extension) in &self.prepare_fn {
                    match function(request) {
                        true => {
                            return Some(
                                extension(
                                    RequestWrapperMut::new(request),
                                    HostWrapper::new(host),
                                    PathWrapper::new(path),
                                    address,
                                )
                                .await,
                            );
                        }
                        false => continue,
                    }
                }
                None
            }
        }
    }
    pub async fn resolve_present(
        &self,
        request: &mut Request<Body>,
        response: &mut Response<Bytes>,
        client_cache_preference: ClientCachePreference,
        server_cache_preference: ServerCachePreference,
        host: &Host,
        address: SocketAddr,
        path: &Path,
    ) -> io::Result<()> {
        pub struct LazyRequestBody<'a> {
            request: &'a mut FatRequest,
            result: Option<Request<Bytes>>,
        }
        impl<'a> LazyRequestBody<'a> {
            pub async fn get(&mut self) -> io::Result<&Request<Bytes>> {
                match self.result {
                    Some(ref result) => Ok(result),
                    None => {
                        let buffer = self.request.body_mut().read_to_bytes().await?;
                        let request = utility::empty_clone_request(&self.request).map(|()| buffer);
                        self.result.replace(request);
                        Ok(self.result.as_ref().unwrap())
                    }
                }
            }
        }

        let mut request = LazyRequestBody {
            request,
            result: None,
        };

        if let Some(extensions) = PresentExtensions::new(Bytes::clone(response.body())) {
            *response.body_mut() = response.body_mut().split_off(extensions.data_start());
            for extension_name_args in extensions.iter() {
                match self.present_internal.get(extension_name_args.name()) {
                    Some(extension) => {
                        let data = PresentData {
                            address,
                            request: request.get().await?,
                            host,
                            path,
                            server_cache_preference,
                            client_cache_preference,
                            response,
                            args: extension_name_args,
                        };
                        let data = PresentDataWrapper(data);
                        extension(data).await;
                    }
                    // No extension, do nothing.
                    None => {}
                }
            }
        }
        match path
            .extension()
            .and_then(|s| s.to_str())
            .and_then(|s| self.present_file.get(s))
        {
            Some(extension) => {
                let data = PresentData {
                    address,
                    request: request.get().await?,
                    host,
                    path,
                    server_cache_preference,
                    client_cache_preference,
                    response,
                    args: PresentArguments::empty(),
                };
                let data = PresentDataWrapper(data);
                extension(data).await;
            }
            None => {}
        }
        Ok(())
    }
    pub async fn resolve_package(&self, response: &mut Response<()>, request: &FatRequest) {
        for extension in &self.package {
            extension(
                EmptyResponseWrapperMut::new(response),
                RequestWrapper::new(request),
            )
            .await;
        }
    }
    pub async fn resolve_post(
        &self,
        request: &FatRequest,
        bytes: Bytes,
        response_pipe: &mut ResponsePipe,
        addr: SocketAddr,
        host: &Host,
    ) {
        for extension in self.post.iter().take(self.post.len() - 1) {
            extension(
                RequestWrapper::new(request),
                Bytes::clone(&bytes),
                ResponsePipeWrapperMut::new(response_pipe),
                addr,
                HostWrapper::new(host),
            )
            .await;
        }
        if let Some(extension) = self.post.last() {
            extension(
                RequestWrapper::new(request),
                bytes,
                ResponsePipeWrapperMut::new(response_pipe),
                addr,
                HostWrapper::new(host),
            )
            .await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct PresentExtensions {
    data: Bytes,
    // Will have the start and end of name of extensions as first tuple,
    // then the name/argument start and length as second.
    // There wil be several names starting on same position.
    extensions: Arc<Vec<((usize, usize), (usize, usize))>>,
    data_start: usize,
}
impl PresentExtensions {
    pub fn new(data: Bytes) -> Option<Self> {
        let mut extensions_args =
            Vec::with_capacity(
                data.iter()
                    .fold(1, |acc, byte| if *byte == SPACE { acc + 1 } else { acc }),
            );

        if !data.starts_with(PRESENT_INTERNAL_PREFIX)
            || data[PRESENT_INTERNAL_PREFIX.len()..].starts_with(PRESENT_INTERNAL_AND)
        {
            return None;
        }
        let mut start = PRESENT_INTERNAL_PREFIX.len();
        let mut last_name = None;
        let mut has_cr = false;
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
                if byte == CR {
                    has_cr = true;
                }
                if byte == CR || byte == LF {
                    return Some(Self {
                        data,
                        extensions: Arc::new(extensions_args),
                        data_start: pos + if has_cr { 2 } else { 1 },
                    });
                }
                start = if data[pos..].starts_with(PRESENT_INTERNAL_AND) {
                    last_name = None;
                    pos + PRESENT_INTERNAL_AND.len()
                } else {
                    pos + 1
                };
            }
        }

        None
    }
    pub fn empty() -> Self {
        Self {
            data: Bytes::new(),
            extensions: Arc::new(Vec::new()),
            data_start: 0,
        }
    }
    pub fn iter(&self) -> PresentExtensionsIter {
        PresentExtensionsIter {
            data: Self::clone(&self),
            index: 0,
        }
    }
    pub fn data_start(&self) -> usize {
        self.data_start
    }
}
#[derive(Debug)]
pub struct PresentExtensionsIter {
    data: PresentExtensions,
    index: usize,
}
impl Iterator for PresentExtensionsIter {
    type Item = PresentArguments;
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
            data: PresentExtensions::clone(&self.data),
            data_index: start,
            len: self.index - start,
        })
    }
}
#[derive(Debug)]
pub struct PresentArguments {
    data: PresentExtensions,
    data_index: usize,
    len: usize,
}
impl PresentArguments {
    pub fn empty() -> Self {
        Self {
            data: PresentExtensions::empty(),
            data_index: 0,
            len: 0,
        }
    }
    pub fn name(&self) -> &str {
        // .1 and .0 should be the same; the name of (usize, usize) should have the same name as it's first argument.
        let (start, len) = self.data.extensions[self.data_index].0;
        // safe, because we checked for str in creation of [`PresentExtensions`].
        unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) }
    }
    pub fn iter(&self) -> PresentArgumentsIter {
        PresentArgumentsIter {
            data: &self.data,
            data_index: self.data_index,
            back_index: self.len,
            index: 1,
        }
    }
}

#[derive(Debug)]
pub struct PresentArgumentsIter<'a> {
    data: &'a PresentExtensions,
    data_index: usize,
    back_index: usize,
    index: usize,
}
impl<'a> Iterator for PresentArgumentsIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.back_index {
            return None;
        }
        let (start, len) = self.data.extensions[self.data_index + self.index].1;
        self.index += 1;
        // Again, safe because we checked for str in creation of [`PresentExtensions`].
        Some(unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) })
    }
}
impl<'a> DoubleEndedIterator for PresentArgumentsIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        // todo!("wrong?");
        if self.index == self.back_index {
            return None;
        }
        let (start, len) = self.data.extensions[self.data_index + self.back_index - 1].1;
        self.back_index -= 1;
        // Again, safe because we checked for str in creation of [`PresentExtensions`].
        Some(unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) })
    }
}

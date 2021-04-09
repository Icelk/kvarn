//! Here, all extensions code is housed
//!
//!
//! ## Unsafe pointers
//!
//! This modules contains extensive usage of unsafe pointers.
//!
//!
//! ### Background
//!
//! In the extension code, I sometimes have to pass references of data to `Futures` to avoid cloning,
//! which sometimes is not an option (such as when a `TcpStream` is part of said data).
//! You cannot share references with `Futures`, and so I've opted to go the unsafe route. Literally.
//!
//!
//! ### Implementation
//!
//! In this module, there are several `Wrapper` types. They ***must not*** be stored.
//! It's safe to get the underlying type is you are inside the extension which received the data;
//! I'm awaiting you, guaranteeing the data isn't touched by anyone but the single extension.
//! If you use it later, I probably have dropped the data.
use crate::prelude::{internals::*, *};

pub type RetFut<T> = Pin<Box<(dyn Future<Output = T> + Send)>>;
pub type RetSyncFut<T> = Pin<Box<(dyn Future<Output = T> + Send + Sync)>>;

pub type Prime =
    Box<(dyn Fn(RequestWrapper, HostWrapper, SocketAddr) -> RetFut<Option<Uri>> + Sync + Send)>;
pub type Pre = Box<
    (dyn Fn(
        RequestWrapperMut,
        HostWrapper,
        SocketAddr,
    ) -> RetFut<Option<(FatResponse, RetSyncFut<()>)>>
         + Sync
         + Send),
>;
pub type Prepare = Box<
    (dyn Fn(RequestWrapperMut, HostWrapper, PathWrapper, SocketAddr) -> RetFut<FatResponse>
         + Sync
         + Send),
>;

pub type Present = Box<(dyn Fn(PresentDataWrapper) -> RetFut<()> + Sync + Send)>;
pub type Package =
    Box<(dyn Fn(EmptyResponseWrapperMut, RequestWrapper) -> RetFut<()> + Sync + Send)>;
pub type Post = Box<
    (dyn Fn(RequestWrapper, Bytes, ResponsePipeWrapperMut, SocketAddr, HostWrapper) -> RetFut<()>
         + Sync
         + Send),
>;
pub type If = Box<(dyn Fn(&FatRequest) -> bool + Sync + Send)>;

pub const PRESENT_INTERNAL_PREFIX: &[u8] = &[BANG, PIPE, SPACE];
pub const PRESENT_INTERNAL_AND: &[u8] = &[SPACE, AMPERSAND, PIPE, SPACE];

macro_rules! get_unsafe_wrapper {
    ($main:ident, $return:ty, $ret_str:expr) => {
        #[doc = "A wrapper type for `"]
        #[doc = $ret_str]
        #[doc = "`.\n\nSee [module level documentation](crate::extensions) for more information."]
        pub struct $main(*const $return);
        impl $main {
            pub(crate) fn new(data: &$return) -> Self {
                Self(data)
            }
            /// See [module level documentation](crate::extensions).
            #[inline(always)]
            pub unsafe fn get_inner(&self) -> &$return {
                &*self.0
            }
        }
        unsafe impl Send for $main {}
        unsafe impl Sync for $main {}
    };
    ($main:ident, $return:ty) => {
        get_unsafe_wrapper!($main, $return, stringify!($return));
    }
}
macro_rules! get_unsafe_mut_wrapper {
    ($main:ident, $return:ty, $ret_str:expr) => {
        #[doc = "A wrapper type for `"]
        #[doc = $ret_str]
        #[doc = "`.\n\nSee [module level documentation](crate::extensions) for more information."]
        pub struct $main(*mut $return);
        impl $main {
            pub(crate) fn new(data: &mut $return) -> Self {
                Self(data)
            }
            /// See [module level documentation](crate::extensions).
            #[inline(always)]
            pub unsafe fn get_inner(&mut self) -> &mut $return {
                &mut *self.0
            }
        }
        unsafe impl Send for $main {}
        unsafe impl Sync for $main {}
    };
    ($main:ident, $return:ty) => {
        get_unsafe_mut_wrapper!($main, $return, stringify!($return));
    };
}

get_unsafe_wrapper!(RequestWrapper, FatRequest);
get_unsafe_mut_wrapper!(RequestWrapperMut, FatRequest);
get_unsafe_mut_wrapper!(EmptyResponseWrapperMut, Response<()>);
get_unsafe_mut_wrapper!(ResponsePipeWrapperMut, application::ResponsePipe);
get_unsafe_wrapper!(HostWrapper, Host);
get_unsafe_wrapper!(PathWrapper, Path);

pub struct PresentDataWrapper(PresentData);
impl PresentDataWrapper {
    /// # Safety
    /// See [module level documentation](crate::extensions).
    ///
    /// It's safe to call this if it's within the future of your extension.
    /// Else, the data will have been dropped.
    ///
    /// You **must** not store this type.
    #[inline(always)]
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
    request: *const FatRequest,
    body: *mut LazyRequestBody,
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
    #[inline(always)]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    #[inline(always)]
    pub fn request(&self) -> &FatRequest {
        unsafe { &*self.request }
    }
    #[inline(always)]
    pub fn body(&mut self) -> &mut LazyRequestBody {
        unsafe { &mut *self.body }
    }
    #[inline(always)]
    pub fn host(&self) -> &Host {
        unsafe { &*self.host }
    }
    #[inline(always)]
    pub fn path(&self) -> &Path {
        unsafe { &*self.path }
    }
    #[inline(always)]
    pub fn server_cache_preference(&mut self) -> &mut ServerCachePreference {
        &mut self.server_cache_preference
    }
    #[inline(always)]
    pub fn client_cache_preference(&mut self) -> &mut ClientCachePreference {
        &mut self.client_cache_preference
    }
    #[inline(always)]
    pub fn response_mut(&mut self) -> &mut Response<Bytes> {
        unsafe { &mut *self.response }
    }
    #[inline(always)]
    pub fn response(&self) -> &Response<Bytes> {
        unsafe { &*self.response }
    }
    #[inline(always)]
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
    /// Creates a empty [`Extensions`].
    ///
    /// It is strongly recommended to use [`Extensions::new()`] instead.
    #[inline]
    pub fn empty() -> Self {
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
    /// Creates a new [`Extensions`] and adds a few essential extensions.
    ///
    /// For now the following extensions are added.
    /// - a Prime extension redirecting the user from `<path>/` to `<path>/index.html` and
    ///   `<path>.` to `<path>.html` is included.
    ///   This was earlier part of parsing of the path, but was moved to an extension for consistency and performance; now `/`, `index.`, and `index.html` is the same entity in cache.
    /// - Package extension to set `Referrer-Policy` header to `no-referrer` for max security and privacy.
    ///   This is only done when no other `Referrer-Policy` header has been set earlier in the response.
    pub fn new() -> Self {
        let mut new = Self::empty();

        new.add_prime(Box::new(|request, host, _| {
            enum Ending {
                Dot,
                Slash,
                Other,
            }
            impl Ending {
                fn from_uri(uri: &Uri) -> Self {
                    if uri.path().ends_with(".") {
                        Self::Dot
                    } else if uri.path().ends_with("/") {
                        Self::Slash
                    } else {
                        Self::Other
                    }
                }
            }
            let uri: &Uri = unsafe { request.get_inner() }.uri();
            let host: &Host = unsafe { host.get_inner() };
            let append = match Ending::from_uri(uri) {
                Ending::Other => return ready(None),
                Ending::Dot => host.get_extension_default_or("html"),
                Ending::Slash => host.get_folder_default_or("index.html"),
            };

            let mut uri = uri.clone().into_parts();

            let path = uri
                .path_and_query
                .as_ref()
                .map(uri::PathAndQuery::path)
                .unwrap_or("/");
            let query = uri
                .path_and_query
                .as_ref()
                .map(uri::PathAndQuery::query)
                .flatten();
            let path_and_query = build_bytes!(
                path.as_bytes(),
                append.as_bytes(),
                if query.is_none() { "" } else { "?" }.as_bytes(),
                query.unwrap_or("").as_bytes()
            );

            // This is ok, we only added bytes from a String, which are guaranteed to be valid for a URI path
            uri.path_and_query =
                Some(uri::PathAndQuery::from_maybe_shared(path_and_query).unwrap());

            // Again ok, see ↑
            let uri = Uri::from_parts(uri).unwrap();

            ready(Some(uri))
        }));
        new.add_package(Box::new(|mut response, _| {
            let response: &mut Response<()> = unsafe { response.get_inner() };
            response
                .headers_mut()
                .entry("referrer-policy")
                .or_insert(HeaderValue::from_static("no-referrer"));

            ready(())
        }));

        new
    }
    /// Adds a prime extension.
    #[inline(always)]
    pub fn add_prime(&mut self, extension: Prime) {
        self.prime.push(extension);
    }
    /// Adds a pre extension.
    #[inline(always)]
    pub fn add_pre(&mut self, path: String, extension: Pre) {
        self.pre.insert(path, extension);
    }
    /// Adds a prepare extension for a single URI.
    #[inline(always)]
    pub fn add_prepare_single(&mut self, path: String, extension: Prepare) {
        self.prepare_single.insert(path, extension);
    }
    /// Adds a prepare extension run if `function` return `true`.
    #[inline(always)]
    pub fn add_prepare_fn(&mut self, function: If, extension: Prepare) {
        self.prepare_fn.push((function, extension));
    }
    /// Adds a present internal extension, called with files starting with `!> `.
    #[inline(always)]
    pub fn add_present_internal(&mut self, name: String, extension: Present) {
        self.present_internal.insert(name, extension);
    }
    /// Adds a present file extension, called with file extensions matching `name`.
    #[inline(always)]
    pub fn add_present_file(&mut self, name: String, extension: Present) {
        self.present_file.insert(name, extension);
    }
    /// Adds a package extension, used to make last-minute changes to response.
    #[inline(always)]
    pub fn add_package(&mut self, extension: Package) {
        self.package.push(extension);
    }
    /// Adds a post extension, used for HTTP/2 push
    #[inline(always)]
    pub fn add_post(&mut self, extension: Post) {
        self.post.push(extension);
    }

    pub(crate) async fn resolve_prime(
        &self,
        request: &mut FatRequest,
        host: &Host,
        address: SocketAddr,
    ) {
        for prime in self.prime.iter() {
            if let Some(prime) = prime(
                RequestWrapper::new(request),
                HostWrapper::new(host),
                address,
            )
            .await
            {
                *request.uri_mut() = prime;
            }
        }
    }
    pub(crate) async fn resolve_pre(
        &self,
        request: &mut FatRequest,
        host: &Host,
        address: SocketAddr,
    ) -> Option<(FatResponse, RetSyncFut<()>)> {
        match self.pre.get(request.uri().path()) {
            Some(extension) => {
                extension(
                    RequestWrapperMut::new(request),
                    HostWrapper::new(host),
                    address,
                )
                .await
            }
            None => None,
        }
    }
    pub(crate) async fn resolve_prepare(
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
    pub(crate) async fn resolve_present(
        &self,
        request: &mut Request<Body>,
        response: &mut Response<Bytes>,
        client_cache_preference: ClientCachePreference,
        server_cache_preference: ServerCachePreference,
        host: &Host,
        address: SocketAddr,
        path: &Path,
    ) -> io::Result<()> {
        let mut body = LazyRequestBody::new(request.body_mut());
        let body = &mut body;

        if let Some(extensions) = PresentExtensions::new(Bytes::clone(response.body())) {
            *response.body_mut() = response.body_mut().split_off(extensions.data_start());
            for extension_name_args in extensions.iter() {
                match self.present_internal.get(extension_name_args.name()) {
                    Some(extension) => {
                        let data = PresentData {
                            address,
                            request,
                            body,
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
                    request,
                    body,
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
    pub(crate) async fn resolve_package(&self, response: &mut Response<()>, request: &FatRequest) {
        for extension in &self.package {
            extension(
                EmptyResponseWrapperMut::new(response),
                RequestWrapper::new(request),
            )
            .await;
        }
    }
    pub(crate) async fn resolve_post(
        &self,
        request: &FatRequest,
        bytes: Bytes,
        response_pipe: &mut ResponsePipe,
        addr: SocketAddr,
        host: &Host,
    ) {
        for extension in self
            .post
            .iter()
            .take(self.post.len().checked_sub(1).unwrap_or(0))
        {
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
#[derive(Debug)]
pub struct LazyRequestBody {
    body: *mut application::Body,
    result: Option<Bytes>,
}
impl LazyRequestBody {
    /// This struct must be `Dropped` before `body` or Undefined Behaviour occurs.
    ///
    /// The `body` is converted to a `*mut` which can be dereferenced safely, as long as we wait for this to be dropped.
    /// It can also not be referenced in any other way while this is not dropped.
    #[inline(always)]
    pub(crate) fn new(body: &mut application::Body) -> Self {
        Self { body, result: None }
    }
    /// Reads the `Bytes` from the request body.
    #[inline]
    pub async fn get(&mut self) -> io::Result<&Bytes> {
        match self.result {
            Some(ref result) => Ok(result),
            None => {
                let buffer = unsafe { &mut *self.body }.read_to_bytes().await?;
                self.result.replace(buffer);
                Ok(self.result.as_ref().unwrap())
            }
        }
    }
}
unsafe impl Send for LazyRequestBody {}
unsafe impl Sync for LazyRequestBody {}

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
    #[inline]
    pub fn iter(&self) -> PresentExtensionsIter {
        PresentExtensionsIter {
            data: Self::clone(&self),
            index: 0,
        }
    }
    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn empty() -> Self {
        Self {
            data: PresentExtensions::empty(),
            data_index: 0,
            len: 0,
        }
    }
    #[inline]
    pub fn name(&self) -> &str {
        // .1 and .0 should be the same; the name of (usize, usize) should have the same name as it's first argument.
        let (start, len) = self.data.extensions[self.data_index].0;
        // safe, because we checked for str in creation of [`PresentExtensions`].
        unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) }
    }
    #[inline]
    pub fn iter(&self) -> PresentArgumentsIter<'_> {
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
    #[inline]
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
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.index == self.back_index {
            return None;
        }
        let (start, len) = self.data.extensions[self.data_index + self.back_index - 1].1;
        self.back_index -= 1;
        // Again, safe because we checked for str in creation of [`PresentExtensions`].
        Some(unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) })
    }
}
mod macros {
    #[macro_export]
    macro_rules! box_fut {
    ($($item:tt)*) => {
            Box::pin(async move { $($item)* })
        };
    }

    /// The ultimate extension-creation macro.
    ///
    /// This is used in the various other macros which expand to extensions; **use them instead**!
    ///
    ///
    /// # Examples
    ///
    /// This is similar to the `prepare!` macro.
    /// ```
    /// # use kvarn::*;
    /// extension!(|
    ///     request: RequestWrapperMut,
    ///     host: HostWrapper,
    ///     path: PathWrapper |
    ///     addr: SocketAddr |,
    ///     ,
    ///     { println!("Hello world, from extension macro!"); }
    /// );
    /// ```
    #[macro_export]
    macro_rules! extension {
        (| $($wrapper_param:ident: $wrapper_param_type:ty $(,)?)* |$(,)? $($param:ident: $param_type:ty $(,)?)* |, $($clone:ident)*, $($code:tt)*) => {{
            use $crate::extensions::*;
            use $crate::prelude::*;
            std::boxed::Box::new(move |
                $(mut $wrapper_param: $wrapper_param_type,)*
                $(mut $param: $param_type,)*
            | {
                $(let $clone = Arc::clone(&$clone);)*
                Box::pin(async move {
                    $(let $wrapper_param = unsafe { $wrapper_param.get_inner() };)*

                    $($code)*
                })
            })
        }}
    }

    /// Will make a prime extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::*;
    /// let extension = prime!(req, host, addr {
    ///     utility::default_error_response(StatusCode::BAD_REQUEST, host).await
    /// });
    /// ```
    #[macro_export]
    macro_rules! prime {
        ($request:ident, $host:ident, $addr:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$request: RequestWrapper, $host: HostWrapper | $addr: SocketAddr|, $($($clone)*)*, $code)
        }
    }
    /// Will make a pre extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::*;
    /// let extension = pre!(req, host, addr {
    ///     Some((utility::default_error_response(StatusCode::BAD_REQUEST, host).await, ready(())))
    /// });
    /// ```
    #[macro_export]
    macro_rules! pre {
        ($request:ident, $host:ident, $addr:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$request: RequestWrapperMut, $host: HostWrapper | $addr: SocketAddr|, $($($clone)*)*, $code)
        }
    }

    /// Will make a prepare extension.
    ///
    /// See example bellow. Where `times_called` is defined in the arguments of the macro, you can enter several `Arc`s to capture from the environment.
    /// They will be cloned before being moved to the future, mitigating the error `cannot move out of 'times_called', a captured variable in an 'Fn' closure`.
    /// **Only `Arc`s** will work, since the variable has to be `Send` and `Sync`.
    ///
    /// You have to have kvarn imported as `kvarn`.
    ///
    ///
    /// # Examples
    ///
    /// > **These examples are applicable to all other extension-creation macros,
    /// > but with different parameters. See their respective documentation.**
    ///
    /// ```
    /// # use kvarn::*;
    /// use std::sync::{Arc, atomic};
    ///
    /// let times_called = Arc::new(atomic::AtomicUsize::new(0));
    ///
    /// prepare!(req, host, path, addr, move |times_called| {
    ///     let times_called = times_called.fetch_add(1, atomic::Ordering::Relaxed);
    ///     println!("Called {} time(s). Request {:?}", times_called, req);
    ///
    ///     utility::default_error_response(StatusCode::NOT_FOUND, host).await
    /// });
    /// ```
    ///
    /// To capture no variables, just leave out the `move ||`.
    /// ```
    /// # use kvarn::*;
    /// prepare!(req, host, path, addr {
    ///     utility::default_error_response(StatusCode::METHOD_NOT_ALLOWED, host).await
    /// });
    /// ```
    #[macro_export]
    macro_rules! prepare {
        ($request:ident, $host:ident, $path:ident, $addr:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            $crate::extension!(|
                $request: RequestWrapperMut,
                $host: HostWrapper,
                $path: PathWrapper |
                $addr: SocketAddr |,
                $($($clone)*)*,
                $code
            )
        }
    }
    /// Will make a present extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::*;
    /// let extension = present!(data {
    ///     println!("Calling uri {}", data.request().uri());
    /// });
    /// ```
    #[macro_export]
    macro_rules! present {
        ($data:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$data: PresentDataWrapper | |, $($($clone)*)*, $code)
        }
    }
    /// Will make a package extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::*;
    /// let extension = package!(response, request {
    ///     response.headers_mut().insert("x-author", HeaderValue::from_static("Icelk"));
    ///     println!("Response headers {:#?}", response.headers());
    /// });
    /// ```
    #[macro_export]
    macro_rules! package {
        ($response:ident, $request:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$response: EmptyResponseWrapperMut, $request: RequestWrapper | |, $($($clone)*)*, $code)
        }
    }
    /// Will make a post extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::*;
    /// let extension = post!(request, bytes, response, address, host {
    ///     let valid_utf8 = response.headers().get("content-type").map(HeaderValue::to_str)
    ///         .and_then(Result::ok).map(|s| s.contains("utf8")).unwrap_or(false);
    ///     
    ///     match valid_utf8 {
    ///         true => match str::from_utf8(&bytes) {
    ///             Ok(s) => println!("Sent response in cleartext: '{}'", s),
    ///             Err(_) => println!("Response is UTF-8, but the bytes are not. Probably compressed."),
    ///         },
    ///         false => println!("Response is not UTF-8."),
    ///     }
    /// });
    /// ```
    #[macro_export]
    macro_rules! post {
        ($request:ident, $bytes:ident, $response:ident, $addr:ident, $host:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$request: RequestWrapper, $response: EmptyResponseWrapperMut, $host: HostWrapper | $bytes: Bytes, $addr: SocketAddr|, $($($clone)*)*, $code)
        }
    }
}

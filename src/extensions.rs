//! Here, all extensions code is housed.
//!
//! Check out [the page about extensions at kvarn.org](https://kvarn.org/extensions/) for more info.
//!
//! If you want to make new extensions for others to use, make sure to check other extensions,
//! so the priorities are valid. This can be done by using the debug implementation on [`Extensions`].
//! ```
//! # use kvarn::prelude::*;
//! let extensions = Extensions::new();
//! println!("The currently mounted extensions: {:#?}", extensions);
//! ```

use crate::prelude::{internals::*, *};
use wrappers::{
    EmptyResponseWrapperMut, HostWrapper, PathOptionWrapper, PresentDataWrapper, RequestWrapper,
    RequestWrapperMut, ResponseBodyPipeWrapperMut, ResponsePipeWrapperMut,
};

/// A return type for a `dyn` [`Future`].
///
/// Used as the return type for all extensions,
/// so they can be stored.
pub type RetFut<T> = Pin<Box<(dyn Future<Output = T> + Send)>>;
/// Same as [`RetFut`] but also implementing [`Sync`].
///
/// Mostly used for extensions used across yield bounds.
pub type RetSyncFut<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

/// A prime extension.
///
/// Can be created using the [`prime!`] macro.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
///
/// # Arguments
///
/// - An immutable reference to the request.
/// - An immutable reference to the host this request is to.
/// - The [`SocketAddr`] of the requester.
pub type Prime =
    Box<(dyn Fn(RequestWrapper, HostWrapper, SocketAddr) -> RetFut<Option<Uri>> + Sync + Send)>;
/// A prepare extension.
///
/// Can be created using the [`prepare!`] macro.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
///
/// # Arguments
///
/// - A mutable reference to the request.
/// - An immutable reference to the host this request is to.
/// - An [`Option`] of a [`Path`]. See the docs at [`prepare!`] for when this is [`None`].
/// - The [`SocketAddr`] of the requester.
pub type Prepare = Box<
    (dyn Fn(RequestWrapperMut, HostWrapper, PathOptionWrapper, SocketAddr) -> RetFut<FatResponse>
         + Sync
         + Send),
>;
/// A present extension.
///
/// Can be created using the [`present!`] macro.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
///
/// # Arguments
///
/// [`PresentData`] contains all the references to the data needed.
///
/// > The use of a separate struct for all the references is a product of the previous design,
/// > before the macros and [`utils::SuperUnsafePointer`]s. Then, you had to do the `unsafe` dereferencing
/// > yourself. Only having to dereference one struct was easier.
pub type Present = Box<(dyn Fn(PresentDataWrapper) -> RetFut<()> + Sync + Send)>;
/// A package extension.
///
/// Can be created using the [`package!`] macro.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
///
/// # Arguments
///
/// - A mutable reference to a [`Response`] without the body.
/// - An immutable reference to the request.
/// - An immutable reference to the host this request is to.
pub type Package =
    Box<(dyn Fn(EmptyResponseWrapperMut, RequestWrapper, HostWrapper) -> RetFut<()> + Sync + Send)>;
/// A post extension.
///
/// Can be created using the [`post!`] macro.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
///
/// # Arguments
///
/// - An immutable reference to the request.
/// - An immutable reference to the host this request is to.
/// - A mutable reference to the [`ResponsePipe`].
/// - The plain text of the body of the response.
/// - The [`SocketAddr`] of the requester.
pub type Post = Box<
    (dyn Fn(RequestWrapper, HostWrapper, ResponsePipeWrapperMut, Bytes, SocketAddr) -> RetFut<()>
         + Sync
         + Send),
>;
/// Dynamic function to check if a extension should be ran.
///
/// Used with [`Prepare`] extensions
pub type If = Box<(dyn Fn(&FatRequest, &Host) -> bool + Sync + Send)>;
/// A [`Future`] for writing to a [`ResponsePipe`] after the response is sent.
///
/// Used with [`Prepare`] extensions
pub type ResponsePipeFuture = Box<
    dyn FnOnce(extensions::ResponseBodyPipeWrapperMut, extensions::HostWrapper) -> RetSyncFut<()>
        + Send
        + Sync,
>;

/// A extension Id. The [`Self::priority`] is used for sorting extensions
/// and [`Self::name`] for debugging which extensions are mounted.
///
/// Higher `priority` extensions are ran first.
/// The debug name is useful when you want to see which priorities
/// other extensions use. This is beneficial when creating "plug-and-play" extensions.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Id {
    priority: i32,
    name: Option<&'static str>,
    no_override: bool,
}
impl Id {
    /// Creates a new Id with `priority` and a `name`.
    pub fn new(priority: i32, name: &'static str) -> Self {
        Self {
            priority,
            name: Some(name),
            no_override: false,
        }
    }
    /// Creates a Id without a name. This is considered a bad practice,
    /// as you cannot see which extensions are mounted to the
    /// [`Extensions`].
    ///
    /// See [`Self::name`] for details about how this affects output.
    pub fn without_name(priority: i32) -> Self {
        Self {
            priority,
            name: None,
            no_override: false,
        }
    }
    /// Always inserts this extension.
    /// If an extension with the same `priority` exist, the `priority` is decremented and tried again.
    pub fn no_override(mut self) -> Self {
        self.no_override = true;
        self
    }
    /// Returns the name of this Id.
    ///
    /// If the Id is created with [`Self::without_name`],
    /// this returns `Unnamed`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name.unwrap_or("Unnamed")
    }
    /// Returns the priority of this extension.
    #[must_use]
    pub fn priority(&self) -> i32 {
        self.priority
    }
}
impl Display for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\" with priority {}", self.name(), self.priority())
    }
}
impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        self.priority().eq(&other.priority())
    }
}
impl Eq for Id {}
impl Ord for Id {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.priority().cmp(&other.priority())
    }
}
impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Returns a future accepted by all the [`extensions`]
/// yielding immediately with `value`.
#[inline]
pub fn ready<T: 'static + Send>(value: T) -> RetFut<T> {
    Box::pin(core::future::ready(value))
}

macro_rules! add_sort_list {
    ($list: expr, $id: expr, $($other: expr, )+) => {
        let mut id = $id;
        loop {
            match $list.binary_search_by(|probe| id.cmp(&probe.0)) {
                Ok(_) if id.no_override => {
                    if let Some(priority) = id.priority.checked_sub(1) {
                        id.priority = priority;
                    } else {
                        panic!("reached minimum priority when trying to not override extension");
                    }
                    continue;
                }
                Ok(pos) => {
                    $list[pos] = (id, $($other, )*);
                    break;
                }
                Err(pos) => {
                    $list.insert(pos, (id, $($other, )*));
                    break;
                }
            };
        }
    };
}

/// Contains all extensions.
/// See [kvarn.org on extensions](https://kvarn.org/extensions/) for more info.
///
/// `TODO`: remove and list? Give mut access to underlying `Vec`s and `HashMap`s or a `Entry`-like interface?
#[must_use]
pub struct Extensions {
    prime: Vec<(Id, Prime)>,
    prepare_single: HashMap<String, Prepare>,
    prepare_fn: Vec<(Id, If, Prepare)>,
    present_internal: HashMap<String, Present>,
    present_file: HashMap<String, Present>,
    package: Vec<(Id, Package)>,
    post: Vec<(Id, Post)>,
}
impl Extensions {
    /// Creates a empty [`Extensions`].
    ///
    /// It is strongly recommended to use [`Extensions::new()`] instead.
    #[inline]
    pub fn empty() -> Self {
        Self {
            prime: Vec::new(),
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
    /// For now the following extensions are added. The number in parentheses is the priority.
    /// - A Prime extension (-64) redirecting the user from `<path>/` to `<path>/index.html` and
    ///   `<path>.` to `<path>.html`.
    ///   This was earlier part of parsing of the path, but was moved to an extension for consistency and performance; now `/`, `index.`, and `index.html` is the same entity in cache.
    /// - A Package extension (8) to set `referrer-policy` header to `no-referrer` for max security and privacy.
    ///   This is only done when no other `referrer-policy` header has been set earlier in the response.
    /// - A CORS extension to deny all CORS requests. See [`Self::with_cors`] for CORS management.
    /// - The default [`Csp`] which only allows requests from `self` and allows unsafe inline
    ///   styles. **This should to a large extent mitigate XSS.**
    pub fn new() -> Self {
        let mut new = Self::empty();

        new.with_uri_redirect()
            .with_no_referrer()
            .with_disallow_cors()
            .with_csp(Csp::default().arc());

        new
    }

    /// Adds a prime extension to redirect [`Uri`]s ending with `.` and `/`.
    ///
    /// This routs the requests according to [`host::Options::folder_default`] and
    /// [`host::Options::extension_default`].
    /// See respective documentation for more info.
    pub fn with_uri_redirect(&mut self) -> &mut Self {
        self.add_prime(
            Box::new(|request, host, _| {
                enum Ending {
                    Dot,
                    Slash,
                    Other,
                }
                impl From<&Uri> for Ending {
                    fn from(uri: &Uri) -> Self {
                        if uri.path().ends_with('.') {
                            Self::Dot
                        } else if uri.path().ends_with('/') {
                            Self::Slash
                        } else {
                            Self::Other
                        }
                    }
                }
                let uri: &Uri = unsafe { request.get_inner() }.uri();
                let host: &Host = unsafe { host.get_inner() };
                let append = match Ending::from(uri) {
                    Ending::Other => return ready(None),
                    Ending::Dot => host.options.extension_default.as_deref().unwrap_or("html"),
                    Ending::Slash => host
                        .options
                        .folder_default
                        .as_deref()
                        .unwrap_or("index.html"),
                };

                let mut uri = uri.clone().into_parts();

                let path = uri
                    .path_and_query
                    .as_ref()
                    .map_or("/", uri::PathAndQuery::path);
                let query = uri
                    .path_and_query
                    .as_ref()
                    .and_then(uri::PathAndQuery::query);
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
            }),
            Id::new(-100, "Expanding . and / to reduce URI size"),
        );
        self
    }
    /// Adds a [`Package`] extension to set the `referrer-policy` to `no-referrer`
    /// for maximum privacy and security.
    /// This is added when calling [`Extensions::new`].
    pub fn with_no_referrer(&mut self) -> &mut Self {
        self.add_package(
            Box::new(|mut response, _, _| {
                let response: &mut Response<()> = unsafe { response.get_inner() };
                response
                    .headers_mut()
                    .entry("referrer-policy")
                    .or_insert(HeaderValue::from_static("no-referrer"));

                ready(())
            }),
            Id::new(10, "Set the referrer-policy header to no-referrer"),
        );
        self
    }

    /// Adds a [`Prepare`] and a [`Prime`] extension (with a priority of `4`) which redirects requests using HTTP to HTTPS
    /// with a [`StatusCode::TEMPORARY_REDIRECT`].
    ///
    /// For more info about how it works, see the source of this function.
    #[cfg(feature = "https")]
    pub fn with_http_to_https_redirect(&mut self) -> &mut Self {
        const SPECIAL_PATH: &str = "/./to_https";
        self.add_prepare_single(
            SPECIAL_PATH.to_string(),
            Box::new(|mut request, _, _, _| {
                // "/./ path" is special; it will not be accepted from outside; any path containing './' gets rejected.
                // Therefore, we can unwrap on values, making the assumption I implemented them correctly below.
                let request: &FatRequest = unsafe { request.get_inner() };
                let uri = request.uri();
                let uri = {
                    let authority = uri.authority().map_or("", uri::Authority::as_str);
                    let bytes = build_bytes!(
                        b"https://",
                        authority.as_bytes(),
                        uri.path().as_bytes(),
                        uri.query().map_or(b"".as_ref(), |_| b"?".as_ref()),
                        uri.query().map_or(b"".as_ref(), |q| q.as_bytes())
                    );
                    // Ok, since we just introduced https:// in the start, which are valid bytes.
                    unsafe { HeaderValue::from_maybe_shared_unchecked(bytes) }
                };

                let response = Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", uri);
                // Unwrap is ok; we know this is valid.
                ready(
                    FatResponse::cache(response.body(Bytes::new()).unwrap())
                        .with_server_cache(ServerCachePreference::None)
                        .with_compress(CompressPreference::None),
                )
            }),
        );
        self.add_prime(
            Box::new(|request, _, _| {
                let request: &FatRequest = unsafe { request.get_inner() };
                let uri = if request.uri().scheme_str() == Some("http")
                    && request.uri().port().is_none()
                {
                    // redirect
                    Some(Uri::from_static(SPECIAL_PATH))
                } else {
                    None
                };
                ready(uri)
            }),
            extensions::Id::new(4, "Redirecting to HTTPS"),
        );
        self
    }

    /// Adds a [`Prime`] extension.
    pub fn add_prime(&mut self, extension: Prime, id: Id) {
        add_sort_list!(self.prime, id, extension,);
    }
    /// Adds a [`Prepare`] extension for a single URI.
    pub fn add_prepare_single(&mut self, path: impl AsRef<str>, extension: Prepare) {
        self.prepare_single
            .insert(path.as_ref().to_owned(), extension);
    }
    /// Adds a [`Prepare`] extension run if `function` return `true`. Higher [`Id::priority()`] extensions are ran first.
    pub fn add_prepare_fn(&mut self, predicate: If, extension: Prepare, id: Id) {
        add_sort_list!(self.prepare_fn, id, predicate, extension,);
    }
    /// Adds a [`Present`] internal extension, called with files starting with `!> `.
    pub fn add_present_internal(&mut self, name: impl AsRef<str>, extension: Present) {
        self.present_internal
            .insert(name.as_ref().to_owned(), extension);
    }
    /// Adds a [`Present`] file extension, called with file extensions matching `name`.
    pub fn add_present_file(&mut self, name: impl AsRef<str>, extension: Present) {
        self.present_file
            .insert(name.as_ref().to_owned(), extension);
    }
    /// Adds a [`Package`] extension, used to make last-minute changes to response. Higher [`Id::priority()`] extensions are ran first.
    pub fn add_package(&mut self, extension: Package, id: Id) {
        add_sort_list!(self.package, id, extension,);
    }
    /// Adds a [`Post`] extension, used for HTTP/2 push Higher [`Id::priority()`] extensions are ran first.
    pub fn add_post(&mut self, extension: Post, id: Id) {
        add_sort_list!(self.post, id, extension,);
    }

    /// The returned [`Uri`] should be the path of the request.
    /// The original request isn't modified, so prepare extensions can rely on it.
    pub(crate) async fn resolve_prime(
        &self,
        request: &mut FatRequest,
        host: &Host,
        address: SocketAddr,
    ) -> Option<Uri> {
        let mut uri = None;
        for (_, prime) in &self.prime {
            if let Some(prime) = prime(
                RequestWrapper::new(request),
                HostWrapper::new(host),
                address,
            )
            .await
            {
                if prime.path().starts_with("/./") {
                    uri = Some(prime);
                } else {
                    *request.uri_mut() = prime;
                }
            }
        }
        uri
    }
    pub(crate) async fn resolve_prepare(
        &self,
        request: &mut FatRequest,
        overide_uri: Option<&Uri>,
        host: &Host,
        path: &Option<PathBuf>,
        address: SocketAddr,
    ) -> Option<FatResponse> {
        if let Some(extension) = self
            .prepare_single
            .get(overide_uri.unwrap_or_else(|| request.uri()).path())
        {
            Some(
                extension(
                    RequestWrapperMut::new(request),
                    HostWrapper::new(host),
                    PathOptionWrapper::new(path),
                    address,
                )
                .await,
            )
        } else {
            for (_, function, extension) in &self.prepare_fn {
                if function(request, host) {
                    return Some(
                        extension(
                            RequestWrapperMut::new(request),
                            HostWrapper::new(host),
                            PathOptionWrapper::new(path),
                            address,
                        )
                        .await,
                    );
                }
            }
            None
        }
    }
    // It's an internal function, which should be the same style as all the other `resolve_*` functions.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn resolve_present(
        &self,
        request: &mut Request<Body>,
        response: &mut Response<Bytes>,
        client_cache_preference: &mut ClientCachePreference,
        server_cache_preference: &mut ServerCachePreference,
        host: &Host,
        address: SocketAddr,
    ) -> io::Result<()> {
        let mut body = LazyRequestBody::new(request.body_mut());
        let body = &mut body;
        let path = utils::parse::uri(request.uri().path());

        if let Some(extensions) = PresentExtensions::new(Bytes::clone(response.body())) {
            *response.body_mut() = response.body_mut().split_off(extensions.data_start());
            for extension_name_args in extensions {
                if let Some(extension) = self.present_internal.get(extension_name_args.name()) {
                    let mut data = PresentData {
                        address,
                        request,
                        body,
                        host,
                        path: path.map(|p| p as *const _),
                        server_cache_preference,
                        client_cache_preference,
                        response,
                        args: extension_name_args,
                    };
                    let data = PresentDataWrapper::new(&mut data);
                    extension(data).await;
                }
            }
        }
        if let Some(extension) = path
            .and_then(Path::extension)
            .and_then(std::ffi::OsStr::to_str)
            .and_then(|s| self.present_file.get(s))
        {
            let mut data = PresentData {
                address,
                request,
                body,
                host,
                path: path.map(|p| p as *const _),
                server_cache_preference,
                client_cache_preference,
                response,
                args: PresentArguments::empty(),
            };
            let data = PresentDataWrapper::new(&mut data);
            extension(data).await;
        }
        Ok(())
    }
    pub(crate) async fn resolve_package(
        &self,
        response: &mut Response<()>,
        request: &FatRequest,
        host: &Host,
    ) {
        for (_, extension) in &self.package {
            extension(
                EmptyResponseWrapperMut::new(response),
                RequestWrapper::new(request),
                HostWrapper::new(host),
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
        for (_, extension) in self.post.iter().take(self.post.len().saturating_sub(1)) {
            extension(
                RequestWrapper::new(request),
                HostWrapper::new(host),
                ResponsePipeWrapperMut::new(response_pipe),
                Bytes::clone(&bytes),
                addr,
            )
            .await;
        }
        if let Some((_, extension)) = self.post.last() {
            extension(
                RequestWrapper::new(request),
                HostWrapper::new(host),
                ResponsePipeWrapperMut::new(response_pipe),
                bytes,
                addr,
            )
            .await;
        }
    }
}
impl Default for Extensions {
    fn default() -> Self {
        Self::new()
    }
}
impl Debug for Extensions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        macro_rules! map {
            ($slice: expr) => {
                &$slice
                    .iter()
                    .map(|ext| (ext.0.as_clean(), "internal extension".as_clean()))
                    .collect::<Vec<_>>()
            };
        }
        f.debug_struct("Extensions")
            .field("prime", map!(self.prime))
            .field("prepare_single", map!(self.prepare_single))
            .field("prepare_fn", map!(self.prepare_fn))
            .field("present_internal", map!(self.present_internal))
            .field("present_file", map!(self.present_file))
            .field("package", map!(self.package))
            .field("post", map!(self.post))
            .finish()
    }
}

/// Add data pretending to present state in creating the response.
///
/// Can be acquired from [`PresentDataWrapper`].
///
/// See [module level documentation](crate::extensions).
#[allow(missing_debug_implementations)]
pub struct PresentData {
    // Regarding request
    address: SocketAddr,
    request: *const FatRequest,
    body: *mut LazyRequestBody,
    host: *const Host,
    path: Option<*const Path>,
    // Regarding response
    server_cache_preference: *mut ServerCachePreference,
    client_cache_preference: *mut ClientCachePreference,
    response: *mut Response<Bytes>,
    // Regarding extension
    args: PresentArguments,
}
#[allow(missing_docs)]
impl PresentData {
    #[inline]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    #[inline]
    pub fn request(&self) -> &FatRequest {
        unsafe { &*self.request }
    }
    #[inline]
    pub fn body(&mut self) -> &mut LazyRequestBody {
        unsafe { &mut *self.body }
    }
    #[inline]
    pub fn host(&self) -> &Host {
        unsafe { &*self.host }
    }
    #[inline]
    pub fn path(&self) -> Option<&Path> {
        unsafe { self.path.map(|p| &*p) }
    }
    #[inline]
    pub fn server_cache_preference(&mut self) -> &mut ServerCachePreference {
        unsafe { &mut *self.server_cache_preference }
    }
    #[inline]
    pub fn client_cache_preference(&mut self) -> &mut ClientCachePreference {
        unsafe { &mut *self.client_cache_preference }
    }
    #[inline]
    pub fn response_mut(&mut self) -> &mut Response<Bytes> {
        unsafe { &mut *self.response }
    }
    #[inline]
    pub fn response(&self) -> &Response<Bytes> {
        unsafe { &*self.response }
    }
    #[inline]
    pub fn args(&self) -> &PresentArguments {
        &self.args
    }
}
unsafe impl Send for PresentData {}
unsafe impl Sync for PresentData {}

/// A [`Request`] [`Body`] which is lazily read.
#[derive(Debug)]
#[must_use]
pub struct LazyRequestBody {
    body: *mut Body,
    result: Option<Bytes>,
}
impl LazyRequestBody {
    /// This struct must be `dropped` before `body` or Undefined Behaviour occurs.
    ///
    /// The `body` is converted to a `*mut` which can be dereferenced safely, as long as we wait for this to be dropped.
    /// It can also not be referenced in any other way while this is not dropped.
    #[inline]
    pub(crate) fn new(body: &mut Body) -> Self {
        Self { body, result: None }
    }
    /// Reads the `Bytes` from the request body.
    ///
    /// # Errors
    ///
    /// Returns any errors from reading the inner [`Body`].
    #[inline]
    pub async fn get(&mut self) -> io::Result<&Bytes> {
        if let Some(ref result) = self.result {
            Ok(result)
        } else {
            let buffer = unsafe { &mut *self.body }.read_to_bytes().await?;
            self.result.replace(buffer);
            // ok; we've just assigned to it
            Ok(self.result.as_ref().unwrap())
        }
    }
}
unsafe impl Send for LazyRequestBody {}
unsafe impl Sync for LazyRequestBody {}

/// A set of rules applicable to certain paths.
/// See the note at [`Self::new`] on how paths are matched.
#[must_use]
#[derive(Debug)]
pub struct RuleSet<R> {
    rules: Vec<(String, R)>,
}
impl<R> RuleSet<R> {
    /// Creates a new ruleset without any rules.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }
    /// Adds `rule` to `path`.
    ///
    /// To use this with [`Host::vary`], use [`Self::add_mut`], which this uses internally.
    ///
    /// By default, `path` will only match requests with the exact path.
    /// This can be changed by appending `*` to the end of the path, which
    /// will then check if the request path start with `path`.
    pub fn add(mut self, path: impl AsRef<str>, rule: R) -> Self {
        self.add_mut(path, rule);
        self
    }
    /// Same as [`Self::add`] but operating on a mutable reference.
    pub fn add_mut(&mut self, path: impl AsRef<str>, rule: R) -> &mut Self {
        let path = path.as_ref().to_owned();

        self.rules.push((path, rule));

        self.rules.sort_by(|a, b| {
            use std::cmp::Ordering;
            if a.0.ends_with('*') == b.0.ends_with('*') {
                b.0.len().cmp(&a.0.len())
            } else if a.0.ends_with('*') {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });

        self
    }

    /// Puts `self` in a [`Arc`].
    ///
    /// Useful for e.g. adding a [`Cors`] ruleset with [`Extensions::with_cors`].
    #[must_use]
    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }
    /// Gets the rule (if any) at `uri_path`.
    ///
    /// For info about how this is matched, see [`Self::add`].
    #[must_use]
    pub fn get(&self, uri_path: &str) -> Option<&R> {
        for (path, allow) in &self.rules {
            if path == uri_path
                || (path
                    .strip_suffix('*')
                    .map_or(false, |path| uri_path.starts_with(path)))
            {
                return Some(allow);
            }
        }
        None
    }
}

/// ## Unsafe pointers
///
/// This modules contains extensive usage of unsafe pointers.
///
/// ### Background
///
/// In the extension code, I sometimes have to pass references of data to `Futures` to avoid cloning,
/// which sometimes is not an option (such as when a `TcpStream` is part of said data).
/// You cannot share references with `Futures`, and so I've opted to go the unsafe route. Literally.
/// Various contracts ensure this isn't unsafe or UB.
///
/// ### Safety
///
/// In this module, there are several `Wrapper` types. They ***must not*** be stored.
/// It's safe to get the underlying type inside the extension which received the data;
/// the future is awaited and the referenced data is guaranteed to not be touched by
/// anyone but the receiving extension. If you use it later, the data can be used
/// or have been dropped.
pub mod wrappers {
    use super::{FatRequest, Host, PathBuf, PresentData, Response, ResponseBodyPipe, ResponsePipe};

    macro_rules! get_unsafe_wrapper {
    ($main:ident, $return:ty, $link:ty) => {
        #[doc = "A wrapper type for [`"]
        #[doc = stringify!($link)]
        #[doc = "`].\n\nSee [module level documentation](crate::extensions) for more information."]
        #[allow(missing_debug_implementations)]
        #[must_use]
        pub struct $main(*const $return);
        impl $main {
            pub(crate) fn new(data: &$return) -> Self {
                Self(data)
            }
            /// # Safety
            ///
            /// See [module level documentation](crate::extensions::wrappers).
            #[inline]
            #[must_use = "must use extracted reference"]
            pub unsafe fn get_inner(&self) -> &$return {
                &*self.0
            }
        }
        unsafe impl Send for $main {}
        unsafe impl Sync for $main {}
    };
    ($main:ident, $return:ty) => {
        get_unsafe_wrapper!($main, $return, $return);
    };
}
    macro_rules! get_unsafe_mut_wrapper {
    ($main:ident, $return:ty, $link:ty) => {
        #[doc = "A wrapper type for [`"]
        #[doc = stringify!($link)]
        #[doc = "`].\n\nSee [module level documentation](crate::extensions::wrappers) for more information."]
        #[allow(missing_debug_implementations)]
        #[must_use]
        pub struct $main(*mut $return);
        impl $main {
            pub(crate) fn new(data: &mut $return) -> Self {
                Self(data)
            }
            /// # Safety
            ///
            /// See [module level documentation](crate::extensions::wrappers).
            #[inline]
            #[must_use = "must use extracted reference"]
            pub unsafe fn get_inner(&mut self) -> &mut $return {
                &mut *self.0
            }
        }
        unsafe impl Send for $main {}
        unsafe impl Sync for $main {}
    };
    ($main:ident, $return:ty) => {
        get_unsafe_mut_wrapper!($main, $return, $return);
    };
}

    get_unsafe_wrapper!(RequestWrapper, FatRequest);
    get_unsafe_mut_wrapper!(RequestWrapperMut, FatRequest);
    get_unsafe_mut_wrapper!(EmptyResponseWrapperMut, Response<()>, Response);
    get_unsafe_mut_wrapper!(ResponsePipeWrapperMut, ResponsePipe);
    get_unsafe_wrapper!(HostWrapper, Host);
    get_unsafe_wrapper!(PathOptionWrapper, Option<PathBuf>);
    get_unsafe_mut_wrapper!(PresentDataWrapper, PresentData);
    get_unsafe_mut_wrapper!(ResponseBodyPipeWrapperMut, ResponseBodyPipe);
}

mod macros {
    /// Makes a pinned future, compatible with [`crate::RetFut`] and [`crate::RetSyncFut`]
    ///
    /// # Examples
    ///
    /// This creates a future which prints `Hello world!` and awaits it.
    /// ```
    /// # async {
    /// # use kvarn::box_fut;
    /// let fut = box_fut!({
    ///     println!("Hello world!");
    /// });
    /// fut.await;
    /// # };
    /// ```
    #[macro_export]
    macro_rules! box_fut {
        ($code:block) => {
            Box::pin(async move { $code })
        };
    }

    /// The ultimate extension-creation macro.
    ///
    /// This is used in the various other macros which expand to extensions; **use them instead**!
    ///
    /// # Examples
    ///
    /// This is similar to the `prepare!` macro.
    /// ```
    /// # use kvarn::prelude::*;
    /// extension!(|
    ///     request: RequestWrapperMut,
    ///     host: HostWrapper,
    ///     path: PathOptionWrapper |
    ///     addr: SocketAddr |,
    ///     ,
    ///     { println!("Hello world, from extension macro!"); }
    /// );
    /// ```
    #[macro_export]
    macro_rules! extension {
        (| $($wrapper_param:ident: $wrapper_param_type:ty $(,)?)* |$(,)? $($param:ident: $param_type:ty $(,)?)* |, $($clone:ident)*, $code:block) => {{
            #[allow(unused_imports)]
            use $crate::extensions::{*, wrappers::*};
            use $crate::prelude::utils::SuperUnsafePointer;
            #[allow(unused_mut)]
            Box::new(move |
                $(mut $wrapper_param: $wrapper_param_type,)*
                $(mut $param: $param_type,)*
            | {
                // SAFETY: This is safe because we know the future will be ran immediately when it's
                // returned.
                // The closure owns a Arc and Kvarn's internals guarantees the future will be
                // ran in the closure's lifetime.
                $(let $clone = unsafe { SuperUnsafePointer::new(&$clone) };)*
                Box::pin(async move {
                    // SAFETY: as stated in [`kvarn::extensions`], it's safe to get the inner
                    // value of wrapper struct inside the extension.
                    $(let $wrapper_param = unsafe { $wrapper_param.get_inner() };)*
                    // SAFETY: See the comments above.
                    $(let $clone = unsafe { $clone.get() };)*

                    $code
                }) as RetSyncFut<_>
            })
        }}
    }

    /// Will make a [`Prime`](super::Prime) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = prime!(req, host, addr {
    ///     default_error_response(StatusCode::BAD_REQUEST, host, None).await
    /// });
    /// ```
    #[macro_export]
    macro_rules! prime {
        ($request:ident, $host:ident, $addr:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$request: RequestWrapper, $host: HostWrapper | $addr: SocketAddr|, $($($clone)*)*, $code)
        }
    }
    /// Will make a [`Prepare`](super::Prepare) extension.
    ///
    /// > The `path` will be [`None`] if and only if [`crate::host::Options::disable_fs`] is true *or* percent
    /// > decoding failed. `request.uri().path()` will not have it's percent encoding decoded.
    ///
    /// See example bellow. Where `times_called` is defined in the arguments of the macro, you can enter several `Arc`s to capture from the environment.
    /// They will be cloned before being moved to the future, mitigating the error `cannot move out of 'times_called', a captured variable in an 'Fn' closure`.
    /// **Only `Arc`s** will work, since the variable has to be `Send` and `Sync`.
    ///
    /// You have to have kvarn imported as `kvarn`.
    ///
    /// # Examples
    ///
    /// > **These examples are applicable to all other extension-creation macros,
    /// > but with different parameters. See their respective documentation.**
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// use std::sync::{Arc, atomic};
    ///
    /// let times_called = Arc::new(atomic::AtomicUsize::new(0));
    ///
    /// prepare!(req, host, path, addr, move |times_called| {
    ///     let times_called = times_called.fetch_add(1, atomic::Ordering::Relaxed);
    ///     println!("Called {} time(s). Request {:?}", times_called, req);
    ///
    ///     default_error_response(StatusCode::NOT_FOUND, host, None).await
    /// });
    /// ```
    ///
    /// To capture no variables, just leave out the `move ||`.
    /// ```
    /// # use kvarn::prelude::*;
    /// prepare!(req, host, path, addr {
    ///     default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None).await
    /// });
    /// ```
    #[macro_export]
    macro_rules! prepare {
        ($request:ident, $host:ident, $path:ident, $addr:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            $crate::extension!(|
                $request: RequestWrapperMut,
                $host: HostWrapper,
                $path: PathOptionWrapper |
                $addr: SocketAddr |,
                $($($clone)*)*,
                $code
            )
        }
    }
    /// Will make a [`Present`](super::Present) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::prelude::*;
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
    /// Will make a [`Package`](super::Package) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = package!(response, request, host {
    ///     response.headers_mut().insert("x-author", HeaderValue::from_static("Icelk"));
    ///     println!("Response headers {:#?}", response.headers());
    /// });
    /// ```
    #[macro_export]
    macro_rules! package {
        ($response:ident, $request:ident, $host:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$response: EmptyResponseWrapperMut, $request: RequestWrapper, $host: HostWrapper | |, $($($clone)*)*, $code)
        }
    }
    /// Will make a [`Post`](super::Post) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    ///
    /// # Examples
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = post!(request, host, response_pipe, bytes, addr {
    ///     match response_pipe {
    ///         application::ResponsePipe::Http1(c) => println!("This is a HTTP/1 connection. {:?}", c),
    ///         application::ResponsePipe::Http2(c) => println!("This is a HTTP/2 connection. {:?}", c),
    ///     }
    /// });
    /// ```
    #[macro_export]
    macro_rules! post {
        ($request:ident, $host:ident, $response_pipe:ident, $bytes:ident, $addr:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$request: RequestWrapper, $host: HostWrapper, $response_pipe: ResponsePipeWrapperMut | $bytes: Bytes, $addr: SocketAddr|, $($($clone)*)*, $code)
        }
    }
    #[allow(unused_imports)]
    use super::ResponsePipeFuture;
    /// Creates a [`ResponsePipeFuture`].
    ///
    /// # Examples
    /// ```
    /// # use kvarn::prelude::*;
    /// prepare!(req, host, path, addr {
    ///     let response = default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None).await;
    ///     response.with_future(response_pipe_fut!(response_pipe, host {
    ///         response_pipe.send(Bytes::from_static(b"This will be appended to the body!")).await;
    ///     }))
    /// });
    /// ```
    #[macro_export]
    macro_rules! response_pipe_fut {
        ($response:ident, $host:ident $(, move |$($clone:ident $(,)?)+|)? $code:block) => {
            extension!(|$response: ResponseBodyPipeWrapperMut, $host: HostWrapper| |, $($($clone)*)*, $code)
        }
    }
}

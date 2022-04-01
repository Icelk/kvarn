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

/// A return type for a `dyn` [`Future`].
///
/// Used as the return type for all extensions,
/// so they can be stored.
pub type RetFut<'a, T> = Pin<Box<(dyn Future<Output = T> + Send + 'a)>>;
/// Same as [`RetFut`] but also implementing [`Sync`].
///
/// Mostly used for extensions used across yield bounds.
pub type RetSyncFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;

/// A prime extension.
///
/// Can be created using the [`prime!`] macro.
///
/// Requires an object which implements the [`PrimeCall`] trait. See it for details on arguments.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
pub type Prime = Box<dyn PrimeCall>;
/// Implement this to pass your extension to [`Extensions::add_prime`].
pub trait PrimeCall: Send + Sync {
    /// # Arguments
    ///
    /// - An immutable reference to the request.
    /// - An immutable reference to the host this request is to.
    /// - The [`SocketAddr`] of the requester.
    fn call<'a>(
        &'a self,
        request: &'a FatRequest,
        host: &'a Host,
        addr: SocketAddr,
    ) -> RetFut<'a, Option<Uri>>;
}
impl<
        F: for<'a> Fn(&'a FatRequest, &'a Host, SocketAddr) -> RetFut<'a, Option<Uri>> + Send + Sync,
    > PrimeCall for F
{
    fn call<'a>(
        &'a self,
        request: &'a FatRequest,
        host: &'a Host,
        addr: SocketAddr,
    ) -> RetFut<'a, Option<Uri>> {
        self(request, host, addr)
    }
}
/// A prepare extension.
///
/// Keep in mind you have to supply the response content type in the headers. Kvarn defaults to HTML.
/// You also have to handle all the methods (except `HEAD`). So, if you ignore methods, your
/// endpoint will behave the same regardless of if the client sends a `POST` or `GET` request.
///
/// Can be created using the [`prepare!`] macro.
///
/// Requires an object which implements the [`PrepareCall`] trait. See it for details on arguments.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
pub type Prepare = Box<dyn PrepareCall>;
/// Implement this to pass your extension to [`Extensions::add_prepare_fn`] or
/// [`Extensions::add_prepare_single`].
pub trait PrepareCall: Send + Sync {
    /// # Arguments
    ///
    /// - A mutable reference to the request.
    /// - An immutable reference to the host this request is to.
    /// - An [`Option`] of a [`Path`]. See the docs at [`prepare!`] for when this is [`None`].
    /// - The [`SocketAddr`] of the requester.
    fn call<'a>(
        &'a self,
        request: &'a mut FatRequest,
        host: &'a Host,
        path: Option<&'a Path>,
        addr: SocketAddr,
    ) -> RetFut<'a, FatResponse>;
}
impl<
        F: for<'a> Fn(
                &'a mut FatRequest,
                &'a Host,
                Option<&Path>,
                SocketAddr,
            ) -> RetFut<'a, FatResponse>
            + Send
            + Sync,
    > PrepareCall for F
{
    fn call<'a>(
        &'a self,
        request: &'a mut FatRequest,
        host: &'a Host,
        path: Option<&Path>,
        addr: SocketAddr,
    ) -> RetFut<'a, FatResponse> {
        self(request, host, path, addr)
    }
}
/// A present extension.
///
/// Can be created using the [`present!`] macro.
///
/// Requires an object which implements the [`PresentCall`] trait. See it for details on arguments.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
pub type Present = Box<dyn PresentCall>;
/// Implement this to pass your extension to [`Extensions::add_present_file`] or
/// [`Extensions::add_present_internal`].
pub trait PresentCall: Send + Sync {
    /// # Arguments
    ///
    /// [`PresentData`] contains all the references to the data needed.
    ///
    /// > The use of a separate struct for all the references is a product of the previous design,
    /// > before the macros and [`utils::SuperUnsafePointer`]s. Then, you had to do the `unsafe` dereferencing
    /// > yourself. Only having to dereference one struct was easier.
    fn call<'a>(&'a self, present_data: &'a mut PresentData) -> RetFut<'a, ()>;
}
impl<F: for<'a> Fn(&'a mut PresentData) -> RetFut<'a, ()> + Send + Sync> PresentCall for F {
    fn call<'a>(&'a self, present_data: &'a mut PresentData) -> RetFut<'a, ()> {
        self(present_data)
    }
}
/// A package extension.
///
/// Can be created using the [`package!`] macro.
///
/// Requires an object which implements the [`PackageCall`] trait. See it for details on arguments.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
pub type Package = Box<dyn PackageCall>;
/// Implement this to pass your extension to [`Extensions::add_package`].
pub trait PackageCall: Send + Sync {
    /// # Arguments
    ///
    /// - A mutable reference to a [`Response`] without the body.
    /// - An immutable reference to the request.
    /// - An immutable reference to the host this request is to.
    fn call<'a>(
        &'a self,
        response: &'a mut Response<()>,
        request: &'a FatRequest,
        host: &'a Host,
    ) -> RetFut<'a, ()>;
}
impl<
        'b,
        F: for<'a> Fn(&'a mut Response<()>, &'a FatRequest, &'a Host) -> RetFut<'a, ()>
            + Send
            + Sync
            + 'b,
    > PackageCall for &'b F
{
    fn call<'a>(
        &'a self,
        response: &'a mut Response<()>,
        request: &'a FatRequest,
        host: &'a Host,
    ) -> RetFut<'a, ()> {
        self(response, request, host)
    }
}
/// A post extension.
///
/// Can be created using the [`post!`] macro.
///
/// Requires an object which implements the [`PostCall`] trait. See it for details on arguments.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
pub type Post = Box<dyn PostCall>;
/// Implement this to pass your extension to [`Extensions::add_post`].
pub trait PostCall: Send + Sync {
    /// # Arguments
    ///
    /// - An immutable reference to the request.
    /// - An immutable reference to the host this request is to.
    /// - A mutable reference to the [`ResponsePipe`].
    /// - The plain text of the body of the response.
    /// - The [`SocketAddr`] of the requester.
    fn call<'a>(
        &'a self,
        request: &'a FatRequest,
        host: &'a Host,
        response_pipe: &'a mut ResponsePipe,
        identity_body: Bytes,
        addr: SocketAddr,
    ) -> RetFut<'a, ()>;
}
impl<
        'b,
        F: for<'a> Fn(
                &'a FatRequest,
                &'a Host,
                &'a mut ResponsePipe,
                Bytes,
                SocketAddr,
            ) -> RetFut<'a, ()>
            + Send
            + Sync
            + 'b,
    > PostCall for F
{
    fn call<'a>(
        &'a self,
        request: &'a FatRequest,
        host: &'a Host,
        response_pipe: &'a mut ResponsePipe,
        identity_body: Bytes,
        addr: SocketAddr,
    ) -> RetFut<'a, ()> {
        self(request, host, response_pipe, identity_body, addr)
    }
}
/// Dynamic function to check if a extension should be ran.
///
/// Used with [`Prepare`] extensions
pub type If = Box<(dyn Fn(&FatRequest, &Host) -> bool + Sync + Send)>;
/// A [`Future`] for writing to a [`ResponsePipe`] after the response is sent.
///
/// Used with [`Prepare`] extensions in their returned [`FatResponse`].
pub type ResponsePipeFuture = Box<dyn ResponsePipeFutureCall>;
/// Implement this to pass your future to [`FatResponse::with_future`].
pub trait ResponsePipeFutureCall: Send + Sync {
    /// # Arguments
    ///
    /// - A mutable reference to the [`ResponseBodyPipe`].
    /// - An immutable reference to the host this request is to.
    fn call<'a>(
        &'a mut self,
        response_body_pipe: &'a mut ResponseBodyPipe,
        host: &'a Host,
    ) -> RetFut<'a, ()>;
}

/// A extension Id. The [`Self::priority`] is used for sorting extensions
/// and [`Self::name`] for debugging which extensions are mounted.
///
/// Higher `priority` extensions are ran first.
/// The debug name is useful when you want to see which priorities
/// other extensions use. This is beneficial when creating "plug-and-play" extensions.
///
/// If two extensions with identical [`priority`](Self::priority)s are inserted, the latter will override the
/// prior. This only effects extensions of the same type.
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
    /// If an extension with the same [`priority`](Self::priority) exist, the `priority` is decremented and tried again.
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
pub fn ready<'a, T: 'a + Send>(value: T) -> RetFut<'a, T> {
    Box::pin(core::future::ready(value))
}

macro_rules! add_sorted_list {
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
macro_rules! remove_sorted_list {
    ($list: expr, $id: expr) => {
        $list
            .binary_search_by(|probe| probe.0.cmp(&$id))
            .ok()
            .map(|pos| $list.remove(pos))
    };
}

/// Contains all extensions.
/// See [kvarn.org on extensions](https://kvarn.org/extensions/) for more info.
#[must_use]
pub struct Extensions {
    prime: Vec<(Id, Prime)>,
    prepare_single: HashMap<String, Prepare>,
    prepare_fn: Vec<(Id, If, Prepare)>,
    present_internal: HashMap<String, Present>,
    present_file: HashMap<String, Present>,
    package: Vec<(Id, Package)>,
    post: Vec<(Id, Post)>,
    // also update Debug implementation when adding fields
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
    /// - A [nonce](Self::with_nonce) implementation for easy nonce setup. (requires `nonce`
    ///   feature).
    /// - The default [`Csp`] which only allows requests from `self` and allows unsafe inline
    ///   styles. **This should to a large extent mitigate XSS.**
    pub fn new() -> Self {
        let mut new = Self::empty();

        new.with_uri_redirect()
            .with_no_referrer()
            .with_disallow_cors()
            .with_csp(Csp::default().arc());

        #[cfg(feature = "nonce")]
        {
            new.with_nonce();
        }

        new
    }

    /// Adds a prime extension to redirect [`Uri`]s ending with `.` and `/`.
    ///
    /// This routs the requests according to [`host::Options::folder_default`] and
    /// [`host::Options::extension_default`].
    /// See respective documentation for more info.
    pub fn with_uri_redirect(&mut self) -> &mut Self {
        self.add_prime(
            prime!(request, host, _, {
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
                let append = match Ending::from(request.uri()) {
                    Ending::Other => return None,
                    Ending::Dot => host.options.extension_default.as_deref().unwrap_or("html"),
                    Ending::Slash => host
                        .options
                        .folder_default
                        .as_deref()
                        .unwrap_or("index.html"),
                };

                let mut uri = request.uri().clone().into_parts();

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

                Some(uri)
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
            package!(response, _, _, {
                response
                    .headers_mut()
                    .entry("referrer-policy")
                    .or_insert(HeaderValue::from_static("no-referrer"));
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
            SPECIAL_PATH,
            prepare!(request, _, _, _, {
                // "/./ path" is special; it will not be accepted from outside; any path containing './' gets rejected.
                // Therefore, we can unwrap on values, making the assumption I implemented them correctly below.
                // let request: &FatRequest = unsafe { request.get_inner() };
                let uri = request.uri();
                let uri = {
                    let authority = uri.authority().map_or("", uri::Authority::as_str);
                    let bytes = build_bytes!(
                        b"https://",
                        authority.as_bytes(),
                        uri.path().as_bytes(),
                        uri.query().map_or(b"".as_ref(), |_| b"?".as_ref()),
                        uri.query().map_or(b"".as_ref(), str::as_bytes)
                    );
                    // Ok, since we just introduced https:// in the start, which are valid bytes.
                    unsafe { HeaderValue::from_maybe_shared_unchecked(bytes) }
                };

                let response = Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", uri);
                // Unwrap is ok; we know this is valid.
                FatResponse::cache(response.body(Bytes::new()).unwrap())
                    .with_server_cache(comprash::ServerCachePreference::None)
                    .with_compress(comprash::CompressPreference::None)
            }),
            // Box::new(|mut request, _, _, _| {
            // }),
        );
        self.add_prime(
            prime!(request, _, _, {
                let uri = if request.uri().scheme_str() == Some("http")
                    && request.uri().port().is_none()
                {
                    // redirect
                    Some(Uri::from_static(SPECIAL_PATH))
                } else {
                    None
                };
                uri
            }),
            extensions::Id::new(4, "Redirecting to HTTPS"),
        );
        self
    }
    /// Adds a [`Present`] extension triggered by the internal extension `nonce` which adds nonce
    /// tags to all scripts with `nonce=` tags.
    /// You MUST NOT have server caching enabled.
    ///
    /// This integrates with your [`csp`] - if any `nonce` extension is added, the corresponding
    /// information is added to the `content-security-policy` header.
    ///
    /// See [kvarn.org](https://kvarn.org/nonce.) for more details.
    #[cfg(feature = "nonce")]
    pub fn with_nonce(&mut self) -> &mut Self {
        use bytes::BufMut;
        use rand::Rng;

        self.add_present_internal(
            "nonce",
            present!(ext, {
                let data: [u8; 16] = rand::thread_rng().gen();
                let mut s = BytesMut::with_capacity(24);
                unsafe { s.set_len(24) };

                let wrote = base64::encode_config_slice(&data, base64::STANDARD, &mut s);
                // if didn't write whole, add padding of `=`.
                s[wrote..].fill(b'=');

                let body = ext.response().body();
                let mut new_body = BytesMut::with_capacity(body.len() + 24*4);
                let mut last_start = 0;

                let iter = memchr::memmem::find_iter(body, b"nonce=");

                for occurrence in iter {
                    // +6 as that's the length of b"nonce="
                    let rest = &body[occurrence + 6..];
                    let first = rest.first();
                    let end = match first {
                        Some(b'"') => memchr::memchr(b'"', &rest[1..]),
                        Some(b'\'') => memchr::memchr(b'\'', &rest[1..]),
                        _ => None,
                    };
                    // we shortened the list by 1
                    let end = end.map(|v| v + 1 + 6);
                    new_body.extend_from_slice(&body[last_start..occurrence + 6]);
                    if let Some(end) = end {
                        let double = *first.unwrap() == b'"';
                        last_start = occurrence + end;

                        if double {
                            new_body.put_u8(b'"');
                        } else {
                            new_body.put_u8(b'\'');
                        }
                        new_body.extend_from_slice(&s);

                        if double {
                            new_body.put_u8(b'"');
                        } else {
                            new_body.put_u8(b'\'');
                        }
                    } else {
                        new_body.extend_from_slice(b"\"\"");
                        last_start = occurrence + 6 + 2;
                    }
                }

                new_body.extend_from_slice(&body[last_start.min(body.len())..]);

                *ext.response_mut().body_mut() = new_body.freeze();
                utils::replace_header(
                    ext.response_mut().headers_mut(),
                    "csp-nonce",
                    HeaderValue::from_maybe_shared(s.freeze()).expect("base64 is valid for a header value")
                );

                if *ext.server_cache_preference() != comprash::ServerCachePreference::None {
                    error!("Enabled nonce on page with server caching enabled! This is critical for XSS resilience.\n\
                           nonces don't work with server caching.");
                    *ext.server_cache_preference() = comprash::ServerCachePreference::None;
                }
            }),
        );
        self
    }

    /// Adds a [`Prime`] extension.
    pub fn add_prime(&mut self, extension: Prime, id: Id) {
        add_sorted_list!(self.prime, id, extension,);
    }
    /// Removes the [`Prime`] extension (if any) with `id`.
    pub fn remove_prime(&mut self, id: Id) {
        remove_sorted_list!(self.prime, id);
    }
    /// Get a reference to the [`Prime`] extensions.
    pub fn get_prime(&self) -> &[(Id, Prime)] {
        &self.prime
    }
    /// Adds a [`Prepare`] extension for a single URI.
    pub fn add_prepare_single(&mut self, path: impl AsRef<str>, extension: Prepare) {
        self.prepare_single
            .insert(path.as_ref().to_owned(), extension);
    }
    /// Removes the [`Prepare`] extension (if any) at `path`.
    pub fn remove_prepare_single(&mut self, path: impl AsRef<str>) {
        self.prepare_single.remove(path.as_ref());
    }
    /// Get a reference to the [`Prepare`] extensions bound to a path.
    #[must_use]
    pub fn get_prepare_single(&self) -> &HashMap<String, Prepare> {
        &self.prepare_single
    }
    /// Adds a [`Prepare`] extension run if `function` return `true`. Higher [`Id::priority()`] extensions are ran first.
    pub fn add_prepare_fn(&mut self, predicate: If, extension: Prepare, id: Id) {
        add_sorted_list!(self.prepare_fn, id, predicate, extension,);
    }
    /// Removes the [`Prepare`] extension (if any) with `id`.
    pub fn remove_prepare_fn(&mut self, id: Id) {
        remove_sorted_list!(self.prepare_fn, id);
    }
    /// Get a reference to the [`Prepare`] extensions using [predicates](If).
    pub fn get_prepare_fn(&self) -> &[(Id, If, Prepare)] {
        &self.prepare_fn
    }
    /// Adds a [`Present`] internal extension, called with files starting with `!> `.
    pub fn add_present_internal(&mut self, name: impl AsRef<str>, extension: Present) {
        self.present_internal
            .insert(name.as_ref().to_owned(), extension);
    }
    /// Removes the [`Present`] internal extension (if any) at `path`.
    pub fn remove_present_internal(&mut self, path: impl AsRef<str>) {
        self.present_internal.remove(path.as_ref());
    }
    /// Get a reference to the [`Present`] internal extensions bound to a path.
    #[must_use]
    pub fn get_present_internal(&self) -> &HashMap<String, Present> {
        &self.present_internal
    }
    /// Adds a [`Present`] file extension, called with file extensions matching `name`.
    pub fn add_present_file(&mut self, name: impl AsRef<str>, extension: Present) {
        self.present_file
            .insert(name.as_ref().to_owned(), extension);
    }
    /// Removes the [`Present`] file extension (if any) at `path`.
    pub fn remove_present_file(&mut self, path: impl AsRef<str>) {
        self.present_file.remove(path.as_ref());
    }
    /// Get a reference to the [`Present`] file extensions bound to a path.
    #[must_use]
    pub fn get_present_file(&self) -> &HashMap<String, Present> {
        &self.present_file
    }
    /// Adds a [`Package`] extension, used to make last-minute changes to response. Higher [`Id::priority()`] extensions are ran first.
    pub fn add_package(&mut self, extension: Package, id: Id) {
        add_sorted_list!(self.package, id, extension,);
    }
    /// Removes the [`Package`] extension (if any) with `id`.
    pub fn remove_package(&mut self, id: Id) {
        remove_sorted_list!(self.package, id);
    }
    /// Get a reference to the [`Package`] extensions.
    pub fn get_package(&self) -> &[(Id, Package)] {
        &self.package
    }
    /// Adds a [`Post`] extension, used for HTTP/2 push Higher [`Id::priority()`] extensions are ran first.
    pub fn add_post(&mut self, extension: Post, id: Id) {
        add_sorted_list!(self.post, id, extension,);
    }
    /// Removes the [`Post`] extension (if any) with `id`.
    pub fn remove_post(&mut self, id: Id) {
        remove_sorted_list!(self.post, id);
    }
    /// Get a reference to the [`Package`] extensions.
    pub fn get_post(&self) -> &[(Id, Post)] {
        &self.post
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
            if let Some(prime) = prime.call(request, host, address).await {
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
                extension
                    .call(request, host, path.as_deref(), address)
                    .await,
            )
        } else {
            for (_, function, extension) in &self.prepare_fn {
                if function(request, host) {
                    return Some(
                        extension
                            .call(request, host, path.as_deref(), address)
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
        client_cache_preference: &mut comprash::ClientCachePreference,
        server_cache_preference: &mut comprash::ServerCachePreference,
        host: &Host,
        address: SocketAddr,
    ) {
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
                    extension.call(&mut data).await;
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
            extension.call(&mut data).await;
        }
    }
    pub(crate) async fn resolve_package(
        &self,
        response: &mut Response<()>,
        request: &FatRequest,
        host: &Host,
    ) {
        for (_, extension) in &self.package {
            extension.call(response, request, host).await;
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
            extension
                .call(request, host, response_pipe, Bytes::clone(&bytes), addr)
                .await;
        }
        if let Some((_, extension)) = self.post.last() {
            extension
                .call(request, host, response_pipe, bytes, addr)
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
        let mut s = f.debug_struct(utils::ident_str!(Extensions));
        utils::fmt_fields!(
            s,
            (self.prime, map!(self.prime)),
            (self.prepare_single, map!(self.prepare_single)),
            (self.prepare_fn, map!(self.prepare_fn)),
            (self.present_internal, map!(self.present_internal)),
            (self.present_file, map!(self.present_file)),
            (self.package, map!(self.package)),
            (self.post, map!(self.post)),
        );
        s.finish()
    }
}

/// Add data pretending to present state in creating the response.
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
    server_cache_preference: *mut comprash::ServerCachePreference,
    client_cache_preference: *mut comprash::ClientCachePreference,
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
    pub fn server_cache_preference(&mut self) -> &mut comprash::ServerCachePreference {
        unsafe { &mut *self.server_cache_preference }
    }
    #[inline]
    pub fn client_cache_preference(&mut self) -> &mut comprash::ClientCachePreference {
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
/// See the note at [`Self::empty`] on how paths are matched.
#[must_use]
#[derive(Debug)]
pub struct RuleSet<R> {
    rules: Vec<(String, R)>,
}
impl<R> RuleSet<R> {
    /// Creates a new ruleset without any rules.
    pub fn empty() -> Self {
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
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// extension!(
    ///     kvarn::extensions::PrepareCall,
    ///     FatResponse,
    ///     | request: &'a mut FatRequest,
    ///     host: &'a Host,
    ///     path: Option<&'a Path>,
    ///     addr: SocketAddr |, , {
    ///         println!("Hello world, from extension macro!");
    ///         FatResponse::no_cache(Response::new(Bytes::from_static(b"Hi!")))
    ///     }
    /// );
    /// ```
    #[macro_export]
    macro_rules! extension {
        // pat to also match _
        // the $meta and $mut (in move || section) signals that this needs to be mut - if both are
        // specified (see `response_pipe_fut` below), the impl and provided variables are mutable.
        //
        // `name` for the params is used to locally bind the params, as the `param` can be `_`.
        ($trait: ty, $ret: ty, $(($meta:tt) ,)? | $($param:tt:$param_type:ty:$name:ident ),* |, $(($($(($mut:tt))? $move:ident:$ty:ty),+))?, $code:block) => {{
            // we go through all this hassle of having a closure to capture dynamic environment.
            struct Ext<F: for<'a> Fn($($param_type,)* $($(&'a $($mut)? $ty,)+)?) -> $crate::extensions::RetFut<'a, $ret> + Send + Sync> {
                ext_function_private: F,
                $($($move:$ty,)+)?
            }
            impl<F: for<'a> Fn($($param_type,)* $($(&'a $($mut)? $ty,)+)?) -> $crate::extensions::RetFut<'a, $ret> + Send + Sync> $trait for Ext<F> {
                fn call<'a>(
                    &'a $($meta)? self,
                    $($name: $param_type,)*
                ) -> $crate::extensions::RetFut<'a, $ret> {
                    let Self {
                        ext_function_private,
                        $($($move,)+)?
                    } = self;
                    (ext_function_private)($($name,)* $($($move,)+)?)
                }
            }
            Box::new(Ext {
                ext_function_private: move |$($param,)* $($($move,)+)?| {
                    Box::pin(async move {
                        $code
                    })
                },
                $($($move,)+)?
            })
        }};
    }

    /// Will make a [`Prime`](super::Prime) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    /// See [`super::PrimeCall`] for a list of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = prime!(_, _host, _addr, {
    ///     Some(Uri::from_static("https://doc.icelk.dev/"))
    /// });
    /// ```
    #[macro_export]
    macro_rules! prime {
        // pat to also match `_`
        ($request:pat, $host:pat, $addr:pat, $(move |$($move:ident:$ty:ty ),+|)? $code:block) => {
            $crate::extension!($crate::extensions::PrimeCall, Option<$crate::prelude::Uri>, |$request: &'a $crate::FatRequest:a1, $host: &'a $crate::prelude::Host:a2, $addr: $crate::prelude::SocketAddr:a3|, $(($($move:$ty),+))?, $code)
        }
    }
    /// Will make a [`Prepare`](super::Prepare) extension.
    ///
    /// See [`super::PrepareCall`] for a list of arguments.
    ///
    /// > The `path` will be [`None`] if and only if [`crate::host::Options::disable_fs`] is true *or* percent
    /// > decoding failed. `request.uri().path()` will not have it's percent encoding decoded.
    ///
    /// See example below. Where `times_called` is defined in the arguments of the macro, you can enter several `Arc`s to capture from the environment.
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
    /// prepare!(req, host, _path, _, move |times_called: Arc<atomic::AtomicUsize>| {
    ///     let times_called = times_called.fetch_add(1, atomic::Ordering::Relaxed);
    ///     println!("Called {} time(s). Request {:?}", times_called, req);
    ///
    ///     default_error_response(StatusCode::NOT_FOUND, host, None).await
    /// });
    /// ```
    ///
    /// To capture no variables, just leave out the `move ||`.
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// prepare!(_request, host, _, _addr, {
    ///     default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None).await
    /// });
    /// ```
    #[macro_export]
    macro_rules! prepare {
        // pat to also match `_`
        ($request:pat, $host:pat, $path:pat, $addr:pat, $(move |$($move:ident:$ty:ty),+|)? $code:block) => {
            $crate::extension!($crate::extensions::PrepareCall, $crate::FatResponse, |
                $request: &'a mut $crate::FatRequest: a1,
                $host: &'a $crate::prelude::Host: a2,
                $path: Option<&'a $crate::prelude::Path>: a3,
                $addr: $crate::prelude::SocketAddr: a4 |,
                $(($($move:$ty),+))?,
                $code
            )
        }
    }
    /// Will make a [`Present`](super::Present) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    /// See [`super::PresentCall`] for a list of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = present!(data, {
    ///     println!("Calling uri {}", data.request().uri());
    /// });
    /// ```
    #[macro_export]
    macro_rules! present {
        ($data:pat, $(move |$($move:ident:$ty:ty ),+|)? $code:block) => {
            $crate::extension!($crate::extensions::PresentCall, (), |$data: &'a mut $crate::extensions::PresentData: a1|, $(($($move:$ty),+))?, $code)
        }
    }
    /// Will make a [`Package`](super::Package) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    /// See [`super::PackageCall`] for a list of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = package!(response, _, _, {
    ///     response.headers_mut().insert("x-author", HeaderValue::from_static("Icelk"));
    ///     println!("Response headers {:#?}", response.headers());
    /// });
    /// ```
    #[macro_export]
    macro_rules! package {
        ($response:pat, $request:pat, $host:pat, $(move |$($move:ident:$ty:ty ),+|)? $code:block) => {
            $crate::extension!($crate::extensions::PackageCall, (), |$response: &'a mut $crate::prelude::Response<()>: a1, $request: &'a $crate::FatRequest: a2, $host: &'a $crate::prelude::Host: a3 |, $(($($move:$ty),+))?, $code)
        }
    }
    /// Will make a [`Post`](super::Post) extension.
    ///
    /// See [`prepare!`] for usage and useful examples.
    /// See [`super::PostCall`] for a list of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = post!(_, _, response_pipe, _, _, {
    ///     match response_pipe {
    ///         application::ResponsePipe::Http1(c) => println!("This is a HTTP/1 connection. {:?}", c),
    ///         application::ResponsePipe::Http2(c) => println!("This is a HTTP/2 connection. {:?}", c),
    ///     }
    /// });
    /// ```
    #[macro_export]
    macro_rules! post {
        ($request:pat, $host:pat, $response_pipe:pat, $bytes:pat, $addr:pat, $(move |$($move:ident:$ty:ty ),+|)? $code:block) => {
            $crate::extension!($crate::extensions::PostCall, (), |$request: &'a $crate::FatRequest: a1, $host: &'a $crate::prelude::Host: a2, $response_pipe: &'a mut $crate::application::ResponsePipe: a3, $bytes: $crate::prelude::Bytes: a4, $addr: $crate::prelude::SocketAddr: a5|, $(($($move:$ty),+))?, $code)
        }
    }
    /// Creates a [`super::ResponsePipeFuture`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// prepare!(_req, host, _, _, {
    ///     let response = default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None).await;
    ///     response.with_future(response_pipe_fut!(response_pipe, host, {
    ///         response_pipe.send(Bytes::from_static(b"This will be appended to the body!")).await;
    ///     }))
    /// });
    /// ```
    #[macro_export]
    macro_rules! response_pipe_fut {
        ($response:pat, $host:pat, $(move |$($move:ident:$ty:ty),+|)? $code:block) => {
            $crate::extension!($crate::extensions::ResponsePipeFutureCall, (), (mut), |$response: &'a mut $crate::application::ResponseBodyPipe: a1, $host: &'a $crate::prelude::Host: a2|, $(($((mut) $move:$ty),+))?, $code)
        };
    }
}

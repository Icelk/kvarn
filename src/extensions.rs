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

/// Used for the `server` header etc
pub const SERVER_NAME_VERSION: &str = "Kvarn/0.6.2";

/// A return type for a `dyn` [`Future`].
///
/// Used as the return type for all extensions,
/// so they can be stored.
#[cfg(feature = "uring")]
pub type RetFut<'a, T> = Pin<Box<(dyn Future<Output = T> + 'a)>>;
/// A return type for a `dyn` [`Future`].
///
/// Used as the return type for all extensions,
/// so they can be stored.
#[cfg(not(feature = "uring"))]
pub type RetFut<'a, T> = Pin<Box<(dyn Future<Output = T> + Send + 'a)>>;
/// Same as [`RetFut`] but also implementing [`Sync`].
///
/// Mostly used for extensions used across yield bounds.
#[cfg(feature = "uring")]
pub type RetSyncFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
/// Same as [`RetFut`] but also implementing [`Sync`].
///
/// Mostly used for extensions used across yield bounds.
#[cfg(not(feature = "uring"))]
pub type RetSyncFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;

#[cfg(feature = "uring")]
#[doc(hidden)]
pub trait KvarnSendSync {}
#[cfg(feature = "uring")]
impl<T> KvarnSendSync for T {}
#[cfg(not(feature = "uring"))]
#[doc(hidden)]
pub trait KvarnSendSync: Send + Sync {}
#[cfg(not(feature = "uring"))]
impl<T: Send + Sync> KvarnSendSync for T {}

/// A prime extension.
///
/// Can be created using the [`prime!`] macro.
///
/// Requires an object which implements the [`PrimeCall`] trait. See it for details on arguments.
///
/// See [module level documentation](extensions) and [kvarn.org](https://kvarn.org/extensions/) for more info.
pub type Prime = Box<dyn PrimeCall>;
/// Implement this to pass your extension to [`Extensions::add_prime`].
pub trait PrimeCall: KvarnSendSync {
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
pub trait PrepareCall: KvarnSendSync {
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
            + KvarnSendSync,
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
/// [`Extensions::add_present_internal`] or [`Extensions::add_present_fn`].
pub trait PresentCall: KvarnSendSync {
    /// # Arguments
    ///
    /// [`PresentData`] contains all the references to the data needed.
    fn call<'a>(&'a self, present_data: &'a mut PresentData<'a>) -> RetFut<'a, ()>;
}
impl<F: for<'a> Fn(&'a mut PresentData<'a>) -> RetFut<'a, ()> + KvarnSendSync> PresentCall for F {
    fn call<'a>(&'a self, present_data: &'a mut PresentData<'a>) -> RetFut<'a, ()> {
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
pub trait PackageCall: KvarnSendSync {
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
        addr: SocketAddr,
    ) -> RetFut<'a, ()>;
}
impl<
        F: for<'a> Fn(&'a mut Response<()>, &'a FatRequest, &'a Host, SocketAddr) -> RetFut<'a, ()>
            + KvarnSendSync,
    > PackageCall for F
{
    fn call<'a>(
        &'a self,
        response: &'a mut Response<()>,
        request: &'a FatRequest,
        host: &'a Host,
        addr: SocketAddr,
    ) -> RetFut<'a, ()> {
        self(response, request, host, addr)
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
pub trait PostCall: KvarnSendSync {
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
        response_pipe: &'a mut ResponseBodyPipe,
        identity_body: Bytes,
        addr: SocketAddr,
    ) -> RetFut<'a, ()>;
}
impl<
        F: for<'a> Fn(
                &'a FatRequest,
                &'a Host,
                &'a mut ResponseBodyPipe,
                Bytes,
                SocketAddr,
            ) -> RetFut<'a, ()>
            + KvarnSendSync,
    > PostCall for F
{
    fn call<'a>(
        &'a self,
        request: &'a FatRequest,
        host: &'a Host,
        response_pipe: &'a mut ResponseBodyPipe,
        identity_body: Bytes,
        addr: SocketAddr,
    ) -> RetFut<'a, ()> {
        self(request, host, response_pipe, identity_body, addr)
    }
}
/// Dynamic function to check if a extension should be ran.
///
/// Used with [`Prepare`] extensions
#[cfg(feature = "uring")]
pub type If = Box<(dyn Fn(&FatRequest, &Host) -> bool)>;
/// Dynamic function to check if a extension should be ran.
///
/// Used with [`Prepare`] extensions
#[cfg(not(feature = "uring"))]
pub type If = Box<(dyn Fn(&FatRequest, &Host) -> bool + Sync + Send)>;
/// A [`Future`] for writing to a [`ResponsePipe`] after the response is sent.
///
/// Used with [`Prepare`] extensions in their returned [`FatResponse`].
pub type ResponsePipeFuture = Box<dyn ResponsePipeFutureCall>;
/// Implement this to pass your future to [`FatResponse::with_future`].
pub trait ResponsePipeFutureCall: KvarnSendSync {
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
#[cfg(not(feature = "uring"))]
pub fn ready<'a, T: 'a + Send>(value: T) -> RetFut<'a, T> {
    Box::pin(core::future::ready(value))
}
/// Returns a future accepted by all the [`extensions`]
/// yielding immediately with `value`.
#[inline]
#[cfg(feature = "uring")]
pub fn ready<'a, T: 'a>(value: T) -> RetFut<'a, T> {
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
    prepare_single: HashMap<CompactString, Prepare>,
    prepare_fn: Vec<(Id, If, Prepare)>,
    present_internal: HashMap<CompactString, Present>,
    present_file: HashMap<CompactString, Present>,
    present_fn: Vec<(Id, If, Present)>,
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
            present_fn: Vec::new(),
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
    /// - The `server` header is set to `Kvarn/<version>`. See [`Self::with_server_header`] for
    ///   more info and customization.
    pub fn new() -> Self {
        let mut new = Self::empty();

        new.with_uri_redirect()
            .with_no_referrer()
            .with_disallow_cors()
            .with_csp(Csp::default().arc())
            .with_server_header(SERVER_NAME_VERSION, false, true);

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
            Id::new(-100, "Expand . and /"),
        );
        self
    }
    /// Adds a [`Package`] extension to set the `referrer-policy` to `no-referrer`
    /// for maximum privacy and security.
    /// If another `referrer-policy` is already present, nothing happens.
    /// This is added when calling [`Extensions::new`].
    pub fn with_no_referrer(&mut self) -> &mut Self {
        self.add_package(
            package!(response, _, _, _, {
                response
                    .headers_mut()
                    .entry("referrer-policy")
                    .or_insert(HeaderValue::from_static("no-referrer"));
            }),
            Id::new(10, "Set the referrer-policy header to no-referrer"),
        );
        self
    }

    /// Adds a [`Prepare`] and a [`Prime`] extension (with a priority of `86881`) which redirects requests using HTTP to HTTPS
    /// with a [`StatusCode::TEMPORARY_REDIRECT`].
    ///
    /// For more info about how it works, see the source of this function.
    #[cfg(feature = "https")]
    pub fn with_http_to_https_redirect(&mut self) -> &mut Self {
        self.add_prepare_fn(
            Box::new(|request, host| {
                request.uri().scheme_str() == Some("http") && request.uri().port().is_none() && {
                    host.certificate.read().unwrap().is_some()
                }
            }),
            prepare!(request, _, _, _, {
                // "/./ path" is special; it will not be accepted from outside; any path containing './' gets rejected.
                // Therefore, we can unwrap on values, making the assumption I implemented them correctly below.
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
                    HeaderValue::from_maybe_shared(bytes).unwrap()
                };

                let response = Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", uri);
                // Unwrap is ok; we know this is valid.
                FatResponse::cache(response.body(Bytes::new()).unwrap())
                    .with_server_cache(comprash::ServerCachePreference::None)
                    .with_compress(comprash::CompressPreference::None)
            }),
            extensions::Id::new(86881, "Redirecting to HTTPS"),
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
        use base64::Engine;
        use rand::Rng;

        const DEFAULT_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new().with_encode_padding(true),
        );

        self.add_present_internal(
            "nonce",
            present!(ext, {
                let data: [u8; 16] = rand::rng().random();
                let mut s = BytesMut::with_capacity(24);
                unsafe { s.set_len(24) };

                let wrote = DEFAULT_ENGINE
                    .encode_slice(data, &mut s)
                    .expect("base64 failed to encode");
                // the padding should do this
                assert_eq!(wrote, 24);

                let body = ext.response.body_mut();
                // let mut new_body = BytesMut::with_capacity(body.len() + 24 * 4);
                let mut replacement = Vec::with_capacity(28);
                let mut last_start = 0;

                while let Some(occurrence) =
                    memchr::memmem::find(&body[last_start + 1..], b"nonce=")
                {
                    let occurrence = occurrence + last_start + 1;
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
                    if let Some(end) = end {
                        let double = *first.unwrap() == b'"';
                        last_start = occurrence + end;

                        if double {
                            replacement.push(b'"');
                        } else {
                            replacement.push(b'\'');
                        }
                        replacement.extend_from_slice(&s);

                        if double {
                            replacement.push(b'"');
                        } else {
                            replacement.push(b'\'');
                        }
                    } else {
                        replacement.extend_from_slice(b"\"\"");
                        last_start = occurrence + 6 + 2;
                    }
                    body.replace(occurrence + 6..last_start, &replacement);
                    replacement.clear();
                }

                ext.response.headers_mut().insert(
                    "csp-nonce",
                    HeaderValue::from_maybe_shared(s.freeze())
                        .expect("base64 is valid for a header value"),
                );

                if *ext.server_cache_preference != comprash::ServerCachePreference::None {
                    error!(
                        "Enabled nonce on page with server caching enabled! \
                        This is critical for XSS resilience.\n\
                        nonces don't work with server caching."
                    );
                    *ext.server_cache_preference = comprash::ServerCachePreference::None;
                }
            }),
        );
        self
    }
    /// Set the `server` header to `server_name` (e.g. [`SERVER_NAME_VERSION`]).
    /// This is called by default when creating a new [`Extensions`] (except when calling
    /// [`Extensions::empty`]).
    ///
    /// If `add_platform` is true, append the platform the server is running
    /// on to the end of the server header.
    ///
    /// If `override_server_header` is true, remove any previous mentions of the server software.
    /// Set to false if you want reverse proxies to pass through the information (and therefore
    /// return two `server` headers to the user agent (maybe for debugging)).
    /// In most cases, it should be set to true.
    pub fn with_server_header(
        &mut self,
        server_name: impl AsRef<str>,
        add_platform: bool,
        override_server_header: bool,
    ) -> &mut Self {
        #[cfg(target_os = "windows")]
        const PLATFORM: &str = " (Windows)";
        #[cfg(target_os = "macos")]
        const PLATFORM: &str = " (macOS)";
        #[cfg(target_os = "linux")]
        const PLATFORM: &str = " (Linux)";
        #[cfg(target_os = "freebsd")]
        const PLATFORM: &str = " (FreeBSD)";
        #[cfg(target_os = "netbsd")]
        const PLATFORM: &str = " (NetBSD)";
        #[cfg(target_os = "openbsd")]
        const PLATFORM: &str = " (OpenBSD)";
        #[cfg(not(any(
            target_os = "windows",
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
        )))]
        const PLATFORM: &str = "";

        let server_name = server_name.as_ref();
        let bytes = build_bytes!(
            server_name.as_bytes(),
            if add_platform {
                PLATFORM.as_bytes()
            } else {
                &[]
            }
        );
        let header_value = HeaderValue::from_maybe_shared(bytes.freeze())
            .expect("`server` header contains invalid bytes");

        self.add_package(
            package!(
                resp,
                _,
                _,
                _,
                move |header_value: HeaderValue, override_server_header: bool| {
                    if *override_server_header {
                        resp.headers_mut().insert("server", header_value.clone());
                    } else {
                        resp.headers_mut().append("server", header_value.clone());
                    }
                }
            ),
            Id::new(-1327, "add `server` header"),
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
            .insert(path.as_ref().to_compact_string(), extension);
    }
    /// Removes the [`Prepare`] extension (if any) at `path`.
    pub fn remove_prepare_single(&mut self, path: impl AsRef<str>) {
        self.prepare_single.remove(path.as_ref());
    }
    /// Get a reference to the [`Prepare`] extensions bound to a path.
    #[must_use]
    pub fn get_prepare_single(&self) -> &HashMap<CompactString, Prepare> {
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
            .insert(name.as_ref().to_compact_string(), extension);
    }
    /// Removes the [`Present`] internal extension (if any) at `path`.
    pub fn remove_present_internal(&mut self, path: impl AsRef<str>) {
        self.present_internal.remove(path.as_ref());
    }
    /// Get a reference to the [`Present`] internal extensions bound to a path.
    #[must_use]
    pub fn get_present_internal(&self) -> &HashMap<CompactString, Present> {
        &self.present_internal
    }
    /// Adds a [`Present`] file extension, called with file extensions matching `name`.
    pub fn add_present_file(&mut self, name: impl AsRef<str>, extension: Present) {
        self.present_file
            .insert(name.as_ref().to_compact_string(), extension);
    }
    /// Removes the [`Present`] file extension (if any) at `path`.
    pub fn remove_present_file(&mut self, path: impl AsRef<str>) {
        self.present_file.remove(path.as_ref());
    }
    /// Get a reference to the [`Present`] file extensions bound to a path.
    #[must_use]
    pub fn get_present_file(&self) -> &HashMap<CompactString, Present> {
        &self.present_file
    }
    /// Adds a [`Present`] file extension, filtered by `predicate`
    pub fn add_present_fn(&mut self, predicate: If, extension: Present, id: Id) {
        add_sorted_list!(self.present_fn, id, predicate, extension,);
    }
    /// Removes the [`Present`] file extension (if any) with `id`.
    pub fn remove_present_fn(&mut self, id: Id) {
        remove_sorted_list!(self.present_fn, id);
    }
    /// Get a reference to the [`Present`] file extensions bound to a predicate.
    #[must_use]
    pub fn get_present_fn(&self) -> &HashMap<CompactString, Present> {
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
        path: &Option<CompactString>,
        address: SocketAddr,
    ) -> Option<FatResponse> {
        if let Some(extension) = self
            .prepare_single
            .get(overide_uri.unwrap_or_else(|| request.uri()).path())
        {
            Some(
                extension
                    .call(request, host, path.as_deref().map(Path::new), address)
                    .await,
            )
        } else {
            for (_, function, extension) in &self.prepare_fn {
                if function(request, host) {
                    return Some(
                        extension
                            .call(request, host, path.as_deref().map(Path::new), address)
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

        let extensions = PresentExtensions::new(Bytes::clone(response.body()));

        if let Some(extensions) = &extensions {
            *response.body_mut() = response.body_mut().split_off(extensions.data_start());
        }

        let (response_head, response_body) = utils::split_response(core::mem::take(response));
        let response_body = utils::BytesCow::Ref(response_body);
        let mut cow_response = response_head.map(|()| response_body);

        for (_, predicate, ext) in &self.present_fn {
            if (predicate)(request, host) {
                let mut data = PresentData {
                    address,
                    request,
                    body,
                    host,
                    path: path.map(Path::new),
                    server_cache_preference,
                    client_cache_preference,
                    response: &mut cow_response,
                    args: PresentArguments::empty(),
                };
                ext.call(&mut data).await;
            }
        }

        if let Some(extension) = path
            .map(Path::new)
            .and_then(Path::extension)
            .and_then(std::ffi::OsStr::to_str)
            .and_then(|s| self.present_file.get(s))
        {
            let mut data = PresentData {
                address,
                request,
                body,
                host,
                path: path.map(Path::new),
                server_cache_preference,
                client_cache_preference,
                response: &mut cow_response,
                args: PresentArguments::empty(),
            };
            extension.call(&mut data).await;
        }

        if let Some(extensions) = extensions {
            for extension_name_args in extensions {
                if let Some(extension) = self.present_internal.get(extension_name_args.name()) {
                    let mut data = PresentData {
                        address,
                        request,
                        body,
                        host,
                        path: path.map(Path::new),
                        server_cache_preference,
                        client_cache_preference,
                        response: &mut cow_response,
                        args: extension_name_args,
                    };
                    extension.call(&mut data).await;
                }
            }
        }

        *response = cow_response.map(utils::BytesCow::freeze);
    }
    pub(crate) async fn resolve_package(
        &self,
        response: &mut Response<()>,
        request: &FatRequest,
        host: &Host,
        addr: SocketAddr,
    ) {
        for (_, extension) in &self.package {
            extension.call(response, request, host, addr).await;
        }
    }
    pub(crate) async fn resolve_post(
        &self,
        request: &FatRequest,
        bytes: Bytes,
        response_pipe: &mut ResponseBodyPipe,
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
            (self.present_fn, map!(self.present_fn)),
            (self.package, map!(self.package)),
            (self.post, map!(self.post)),
        );
        s.finish()
    }
}

/// Add data pretending to present state in creating the response.
///
/// See [module level documentation](crate::extensions).
#[allow(missing_docs)]
#[derive(Debug)]
pub struct PresentData<'a> {
    // Regarding request
    pub address: SocketAddr,
    pub request: &'a FatRequest,
    pub body: &'a mut LazyRequestBody,
    pub host: &'a Host,
    pub path: Option<&'a Path>,
    // Regarding response
    pub server_cache_preference: &'a mut comprash::ServerCachePreference,
    pub client_cache_preference: &'a mut comprash::ClientCachePreference,
    pub response: &'a mut Response<utils::BytesCow>,
    // Regarding extension
    pub args: PresentArguments,
}

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
    /// `max_len` can be used to limit memory allocation. 16MB is often enough for every case.
    ///
    /// # Errors
    ///
    /// Returns any errors from reading the inner [`Body`].
    #[inline]
    pub async fn get(&mut self, max_len: usize) -> io::Result<&Bytes> {
        if let Some(ref result) = self.result {
            Ok(result)
        } else {
            let buffer = unsafe { &mut *self.body }.read_to_bytes(max_len).await?;
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
#[derive(Debug, Clone)]
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
    pub fn add(mut self, path: impl AsRef<str>, rule: impl Into<R>) -> Self {
        self.add_mut(path, rule);
        self
    }
    /// Same as [`Self::add`] but operating on a mutable reference.
    pub fn add_mut(&mut self, path: impl AsRef<str>, rule: impl Into<R>) -> &mut Self {
        let path = path.as_ref().to_owned();

        if let Ok(idx) = self.rules.binary_search_by(|probe| probe.0.cmp(&path)) {
            // not swap_remove, because ordering!
            self.rules.remove(idx);
        }
        self.rules.push((path, rule.into()));

        self.rules.sort_unstable_by(|a, b| {
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

/// Prepare extension to stream body instead of: reading it fully, caching, then responding.
/// **Use with care!**
///
/// Does not support present extensions, nor post extensions.
#[must_use]
#[allow(clippy::cast_possible_truncation, unused_mut)]
pub fn stream_body() -> Box<dyn PrepareCall> {
    prepare!(req, host, path, _addr, {
        debug!("Streaming body for {:?}", req.uri().path());
        let range = utils::parse::sanitize_request(req)
            .ok()
            .and_then(|data| data.get_range());
        let start = range.map_or(0, |range| range.0);
        if let Some(path) = path {
            let file = fs::File::open(path).await;
            let meta = if let Ok(_file) = &file {
                #[cfg(feature = "uring")]
                {
                    tokio_uring::fs::statx(path).await.ok()
                }
                #[cfg(not(feature = "uring"))]
                {
                    _file.metadata().await.ok()
                }
            } else {
                None
            };
            if let (Ok(mut file), Some(meta)) = (file, meta) {
                let mut response = Response::new(Bytes::new());
                response
                    .headers_mut()
                    .insert("vary", HeaderValue::from_static("range"));

                let first_bytes = {
                    let mut v = vec![0; 16];
                    #[cfg(feature = "uring")]
                    let (Ok(read), mut v) = file.read_at(v, 0).await
                    else {
                        return default_error_response(StatusCode::NOT_FOUND, host, None).await;
                    };
                    #[cfg(not(feature = "uring"))]
                    let Ok(read) = file.read(&mut v).await
                    else {
                        return default_error_response(StatusCode::NOT_FOUND, host, None).await;
                    };
                    v.truncate(read);
                    v
                };

                // Mime
                if !response.headers().contains_key("content-type") {
                    let mime = comprash::get_mime(
                        path.extension()
                            .and_then(std::ffi::OsStr::to_str)
                            .unwrap_or(""),
                        &first_bytes,
                    );
                    let mime = if comprash::is_text(&mime) {
                        let b = mime.to_string().into_bytes();
                        build_bytes!(&b, b"; charset=utf-8").freeze()
                    } else {
                        mime.to_string().into_bytes().into()
                    };

                    // Mime will only contains valid bytes.
                    let content_type = HeaderValue::from_maybe_shared::<Bytes>(mime).unwrap();
                    response.headers_mut().insert("content-type", content_type);
                }

                #[cfg(feature = "uring")]
                let file_len = meta.stx_size;
                #[cfg(not(feature = "uring"))]
                let file_len = meta.len();

                let end = if let Some((_, end)) = range {
                    end
                } else {
                    file_len
                };
                let len = end - start;

                #[cfg(not(feature = "uring"))]
                {
                    use tokio::io::AsyncSeekExt;
                    if file.seek(io::SeekFrom::Start(start)).await.is_err() {
                        return default_error_response(StatusCode::NOT_FOUND, host, None).await;
                    }
                }

                #[allow(clippy::uninit_vec)]
                let fut = response_pipe_fut!(response, _host, move |file: fs::File| {
                    let mut buf = Vec::with_capacity(1024 * 64);
                    let mut pos = start;
                    unsafe { buf.set_len(buf.capacity()) };
                    let mut i = 0u32;
                    loop {
                        // add 1 at the top to skip waiting for connection on first iter
                        i = i.wrapping_add(1);
                        #[cfg(feature = "uring")]
                        let r = {
                            let (r, b) = file.read_at(buf, pos).await;
                            buf = b;
                            r
                        };
                        #[cfg(not(feature = "uring"))]
                        let r = file.read(&mut buf).await;
                        match r {
                            Ok(read) => {
                                if read == 0 {
                                    break;
                                }
                                pos += read as u64;

                                // it what was just read into memory, safe to cast to usize
                                #[allow(clippy::cast_possible_truncation)]
                                let buf_end = if pos > end {
                                    read - (pos - end) as usize
                                } else {
                                    read
                                };
                                // one chunk is max 64kB (see buffer above)
                                // we want to check connection status every, say, 10MB, to not
                                // exhaust resources.
                                // 10MB/64kB = 160
                                let data = Bytes::copy_from_slice(&buf[..buf_end]);
                                let r = if i % 160 == 0 {
                                    response.send_with_wait(data, 10 * 1024 * 1024).await
                                } else {
                                    response.send(data).await
                                };
                                match r {
                                    Ok(()) => {}
                                    Err(_) => {
                                        break;
                                    }
                                }
                                if pos >= end {
                                    break;
                                }
                            }
                            Err(err) => {
                                warn!("Failed to stream body from file: {err}");
                                break;
                            }
                        }
                    }
                });

                FatResponse::new(response, comprash::ServerCachePreference::None)
                    .with_future_and_len(fut, len)
            } else {
                default_error_response(StatusCode::NOT_FOUND, host, None).await
            }
        } else {
            default_error_response(StatusCode::NOT_FOUND, host, None).await
        }
    })
}

#[doc(hidden)]
pub use macros::_UringSendSync;
mod macros {
    /// Create a pinned future, compatible with [`crate::RetFut`].
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
            Box::pin(async move { $code }) as $crate::extensions::RetFut<_>
        };
    }

    #[cfg(feature = "uring")]
    #[doc(hidden)]
    ///
    pub trait _UringSendSync {}
    #[cfg(feature = "uring")]
    impl<T> _UringSendSync for T {}
    #[cfg(not(feature = "uring"))]
    #[doc(hidden)]
    ///
    pub trait _UringSendSync: Send + Sync {}
    #[cfg(not(feature = "uring"))]
    impl<T: Send + Sync> _UringSendSync for T {}

    /// The ultimate extension-creation macro.
    ///
    /// This is used in the various other macros which expand to extensions; **use them instead**!
    ///
    /// # Stability
    ///
    /// This macro isn't considered stable and may change at any time.
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
    ///     | request: &'a mut FatRequest: &mut FatRequest: arg1,
    ///     host: &'a Host: &Host: arg2,
    ///     path: Option<&'a Path>: Option<&Path>: arg3,
    ///     addr: SocketAddr: SocketAddr: arg4 |, , {
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
        ($trait: ty, $ret: ty, $(($meta:tt) ,)? | $($param:tt: $param_type:ty: $param_type_no_lifetimes:ty :$name:ident ),* |, $(($($(($mut:tt))? $move:ident:$ty:ty),+))?, $code:block) => {{
            // we go through all this hassle of having a closure to capture dynamic environment.
            struct Ext<F: for<'a> Fn($($param_type,)* $($(&'a $($mut)? $ty,)+)?) -> $crate::extensions::RetFut<'a, $ret> + $crate::extensions::_UringSendSync> {
                function_private: F,
                $($($move:$ty,)+)?
            }

            impl<F: for<'a> Fn($($param_type,)* $($(&'a $($mut)? $ty,)+)?) -> $crate::extensions::RetFut<'a, $ret> + $crate::extensions::_UringSendSync> $trait for Ext<F> {
                fn call<'a>(
                    &'a $($meta)? self,
                    $($name: $param_type,)*
                ) -> $crate::extensions::RetFut<'a, $ret> {
                    let Self {
                        function_private,
                        $($($move,)+)?
                    } = self;
                    (function_private)($($name,)* $($($move,)+)?)
                }
            }
            Box::new(Ext {
                function_private: move |$($param: $param_type_no_lifetimes,)* $($($move: & $($mut)? $ty,)+)?| {
                    Box::pin(async move {
                        $code
                    })
                },
                $($($move,)+)?
            })
        }};
    }

    /// Construct a [`Prime`](super::Prime) extension like you write closures.
    ///
    /// See [`crate::prepare!`] for usage and useful examples.
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
            $crate::extension!(
                $crate::extensions::PrimeCall,
                Option<$crate::prelude::Uri>,
                |$request: &'a $crate::FatRequest: &$crate::FatRequest: a1,
                $host: &'a $crate::prelude::Host: &$crate::prelude::Host: a2,
                $addr: $crate::prelude::SocketAddr: $crate::prelude::SocketAddr: a3|,
                $(($($move:$ty),+))?,
                $code
            ) as $crate::extensions::Prime
        }
    }
    /// Construct a [`Prepare`](super::Prepare) extension like you write closures.
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
                $request: &'a mut $crate::FatRequest: &mut $crate::FatRequest: a1,
                $host: &'a $crate::prelude::Host: &$crate::prelude::Host: a2,
                $path: Option<&'a $crate::prelude::Path>: Option<&$crate::prelude::Path>: a3,
                $addr: $crate::prelude::SocketAddr: $crate::prelude::SocketAddr: a4 |,
                $(($($move:$ty),+))?,
                $code
            ) as $crate::extensions::Prepare
        }
    }
    /// Construct a [`Present`](super::Present) extension like you write closures.
    ///
    /// See [`crate::prepare!`] for usage and useful examples.
    /// See [`super::PresentCall`] for a list of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = present!(data, {
    ///     println!("Calling uri {}", data.request.uri());
    /// });
    /// ```
    #[macro_export]
    macro_rules! present {
        ($data:pat, $(move |$($move:ident:$ty:ty ),+|)? $code:block) => {
            $crate::extension!(
                $crate::extensions::PresentCall,
                (),
                |$data: &'a mut $crate::extensions::PresentData<'a>: &mut $crate::extensions::PresentData: a1|,
                $(($($move:$ty),+))?,
                $code
            ) as $crate::extensions::Present
        }
    }
    /// Construct a [`Package`](super::Package) extension like you write closures.
    ///
    /// See [`crate::prepare!`] for usage and useful examples.
    /// See [`super::PackageCall`] for a list of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = package!(response, _, _, _, {
    ///     response.headers_mut().insert("x-author", HeaderValue::from_static("Icelk"));
    ///     println!("Response headers {:#?}", response.headers());
    /// });
    /// ```
    #[macro_export]
    macro_rules! package {
        ($response:pat, $request:pat, $host:pat, $addr:pat, $(move |$($move:ident:$ty:ty ),+|)? $code:block) => {
            $crate::extension!(
                $crate::extensions::PackageCall,
                (),
                |$response: &'a mut $crate::prelude::Response<()>: &mut $crate::prelude::Response<()>: a1,
                $request: &'a $crate::FatRequest: &$crate::FatRequest: a2,
                $host: &'a $crate::prelude::Host: &$crate::prelude::Host: a3,
                $addr: $crate::prelude::SocketAddr: $crate::prelude::SocketAddr: a4 |,
                $(($($move:$ty),+))?,
                $code
            ) as $crate::extensions::Package
        }
    }
    /// Construct a [`Post`](super::Post) extension like you write closures.
    ///
    /// See [`crate::prepare!`] for usage and useful examples.
    /// See [`super::PostCall`] for a list of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// let extension = post!(_, _, response_pipe, _, _, {
    ///     match response_pipe {
    ///         application::ResponseBodyPipe::Http1(c) => println!("This is an HTTP/1 connection. {c:?}"),
    ///         application::ResponseBodyPipe::Http2(c, _) => println!("This is an HTTP/2 connection. {c:?}"),
    ///         application::ResponseBodyPipe::Http3(c) => println!("This is an HTTP/3 connection."),
    ///     }
    /// });
    /// ```
    #[macro_export]
    macro_rules! post {
        ($request:pat, $host:pat, $response_pipe:pat, $bytes:pat, $addr:pat, $(move |$($move:ident:$ty:ty ),+|)? $code:block) => {
            $crate::extension!(
                $crate::extensions::PostCall,
                (),
                |$request: &'a $crate::FatRequest: &$crate::FatRequest: a1,
                $host: &'a $crate::prelude::Host: &$crate::prelude::Host: a2,
                $response_pipe: &'a mut $crate::application::ResponseBodyPipe: &mut $crate::application::ResponseBodyPipe: a3,
                $bytes: $crate::prelude::Bytes: $crate::prelude::Bytes: a4,
                $addr: $crate::prelude::SocketAddr: $crate::prelude::SocketAddr: a5|,
                $(($($move:$ty),+))?,
                $code
            ) as $crate::extensions::Post
        }
    }
    /// Creates a [`super::ResponsePipeFuture`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kvarn::prelude::*;
    /// prepare!(_req, host, _, addr, {
    ///     let response = default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None).await;
    ///     response.with_future(response_pipe_fut!(response_pipe, host, move |addr: SocketAddr| {
    ///         response_pipe.send(Bytes::from_static(b"This will be appended to the body!")).await;
    ///     }))
    /// });
    /// ```
    #[macro_export]
    macro_rules! response_pipe_fut {
        ($response:pat, $host:pat, $(move |$($move:ident:$ty:ty),+|)? $code:block) => {
            $crate::extension!(
                $crate::extensions::ResponsePipeFutureCall,
                (),
                (mut),
                |$response: &'a mut $crate::application::ResponseBodyPipe: &mut $crate::application::ResponseBodyPipe: a1,
                $host: &'a $crate::prelude::Host: &$crate::prelude::Host: a2|,
                $(($((mut) $move:$ty),+))?, $code)
        };
    }
}

//! [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) implementation for Kvarn.
//!
//! See [`Cors`] for usage details.

use crate::prelude::*;
use extensions::RuleSet;

/// A [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) ruleset for Kvarn.
///
/// Use [`Extensions::with_cors`] to allow selected CORS requests.
///
/// By default, Kvarn uses a empty [`RuleSet`]; all CORS requests are rejected.
///
/// # Examples
///
/// ```
/// # use kvarn::prelude::*;
/// // Allow `https://icelk.dev` and `https://kvarn.org` to access all images.
/// // Also allow all requests from `http://example.org` access to the api.
/// let cors =
///     Cors::empty()
///         .add(
///             "/images/*",
///             CorsAllowList::new(time::Duration::from_secs(60*60*24*365))
///                 .add_origin("https://icelk.dev")
///                 .add_origin("https://kvarn.org")
///             )
///         .add(
///             "/api/*",
///             CorsAllowList::default()
///                 .add_origin("http://example.org")
///                 .add_method(Method::PUT)
///                 .add_method(Method::POST)
///         );
/// ```
pub type Cors = RuleSet<AllowList>;
impl Cors {
    /// Check if the (cross-origin) request's `origin` [`Uri`] is allowed by the CORS rules.
    ///
    /// See [`CorsAllowList::check`] for info about the return types.
    pub fn check_origin(
        &self,
        origin: &Uri,
        uri_path: &str,
    ) -> Option<(MethodAllowList, &[HeaderName], time::Duration)> {
        self.get(uri_path).and_then(|cal| cal.check(origin))
    }
    /// Check if the [`Request::headers`] and [`Request::uri`] is allowed with this ruleset.
    ///
    /// > This will not check for errors in `access-control-request-headers`.
    ///
    /// Use this over [`Self::check_origin`] because this checks for `same_origin` requests.
    ///
    /// See [`CorsAllowList::check`] for info about the return types.
    pub fn check_cors_request<T>(
        &self,
        request: &Request<T>,
    ) -> Option<(MethodAllowList, &[HeaderName], time::Duration)> {
        let same_origin_allowed_headers = (
            MethodAllowList::All,
            &[][..],
            time::Duration::from_secs(60 * 60 * 24 * 7),
        );
        match request.headers().get("origin") {
            None => Some(same_origin_allowed_headers),
            Some(origin)
                if origin.to_str().map_or(false, |origin| {
                    Cors::is_part_of_origin(origin, request.uri())
                }) =>
            {
                Some(same_origin_allowed_headers)
            }
            Some(origin) => match Uri::try_from(origin.as_bytes()) {
                Ok(origin) => match self.check_origin(&origin, request.uri().path()) {
                    Some(allowed) if allowed.0.allowed(request.method()) => Some(allowed),
                    _ => None,
                },
                Err(_) => None,
            },
        }
    }
    /// Checks if `uri` is the same origin as `origin`.
    fn is_part_of_origin(origin: &str, uri: &Uri) -> bool {
        let uri_parts = origin.split_once("://");

        let (origin_scheme, origin_authority) = match uri_parts {
            Some((s, o)) => (s, o),
            None => return origin == "localhost" || origin == "null",
        };
        if Some(origin_scheme) != uri.scheme_str() {
            return false;
        }
        uri.authority()
            .map(uri::Authority::as_str)
            .map_or(false, |authority| authority == origin_authority)
    }
}

/// A CORS allow list which allowes hosts, methods, and headers from a associated path.
/// This is a builder-like struct.
/// Use the `add_*` methods to add allowed origins, methods, and headers.
/// Multiple allow lists can be added to a [`Cors`] instance.
/// See the example at [`Cors`].
///
/// Use [`RuleSet::add`] to add a rule.
#[must_use]
#[derive(Debug)]
pub struct AllowList {
    allowed: Vec<Uri>,
    allow_all_origins: bool,
    methods: Option<Vec<Method>>,
    headers: Vec<HeaderName>,
    cache_for: time::Duration,
}
impl AllowList {
    /// Creates a empty CORS allow list with the client cache duration of `cache_for`.
    pub fn new(cache_for: time::Duration) -> Self {
        Self {
            allowed: Vec::new(),
            allow_all_origins: false,
            methods: Some(vec![Method::GET, Method::HEAD, Method::OPTIONS]),
            headers: Vec::new(),
            cache_for,
        }
    }
    /// Allows CORS request from `allowed_origin`.
    /// Note that the scheme (`https` / `http`) is sensitive.
    /// Use [`Self::add_origin_uri`] for a [`Uri`] input.
    ///
    /// # Panics
    ///
    /// Panics if `allowed_origin` is not a valid [`Uri`]
    /// or if it doesn't contain a host AND a scheme.
    pub fn add_origin(self, allowed_origin: impl AsRef<str>) -> Self {
        self.add_origin_uri(Uri::try_from(allowed_origin.as_ref()).unwrap())
    }
    /// Allows CORS request from `allowed_origin`.
    /// Note that the scheme (`https` / `http`) is sensitive.
    ///
    /// # Panics
    ///
    /// Panics if `allowed_origin` doesn't contain a host AND a scheme.
    pub fn add_origin_uri(mut self, allowed_origin: Uri) -> Self {
        assert!(allowed_origin.host().is_some());
        assert!(allowed_origin.scheme().is_some());
        self.allowed.push(allowed_origin);
        self
    }
    /// Enables the flag to allow all origins to use the set methods and headers in CORS requests.
    pub fn allow_all_origins(mut self) -> Self {
        self.allow_all_origins = true;
        self
    }
    /// Allows the listed origin(s) (added via [`Self::add_origin`])
    /// to request using `allowed_method`.
    pub fn add_method(mut self, allowed_method: Method) -> Self {
        let methods = self.methods.get_or_insert_with(Vec::new);
        if !methods.contains(&allowed_method) {
            methods.push(allowed_method);
        }
        self
    }
    /// Allows all methods.
    pub fn allow_all_methods(mut self) -> Self {
        self.methods = None;
        self
    }
    /// Allows the listed origin(s) (added via [`Self::add_origin`])
    /// to send the `allowed_header` in the request.
    pub fn add_header(mut self, allowed_header: HeaderName) -> Self {
        if !self.headers.contains(&allowed_header) {
            self.headers.push(allowed_header);
        }
        self
    }
    fn get_methods(&self) -> MethodAllowList {
        self.methods
            .as_deref()
            .map_or(MethodAllowList::All, MethodAllowList::Selected)
    }
    /// Checks if the `origin` is allowed according to the allow list.
    ///
    /// Returns [`Some`] if `origin` is allowed, with the [`Method`]s and [`HeaderName`]s
    /// allowed, with a cache max-age of [`time::Duration`].
    /// Returns [`None`] if `origin` isn't allowed.
    pub fn check(&self, origin: &Uri) -> Option<(MethodAllowList, &[HeaderName], time::Duration)> {
        if self.allow_all_origins {
            return Some((self.get_methods(), &self.headers, self.cache_for));
        }
        for allowed in &self.allowed {
            let scheme = allowed.scheme().map_or("https", uri::Scheme::as_str);
            // This is OK; we assert it has a host when we add it
            if Some(allowed.host().unwrap()) == origin.host()
                && allowed.port_u16() == origin.port_u16()
                && Some(scheme) == origin.scheme().map(uri::Scheme::as_str)
            {
                return Some((self.get_methods(), &self.headers, self.cache_for));
            }
        }
        None
    }
}
/// The default `cache_for` is 1 hour.
impl Default for AllowList {
    fn default() -> Self {
        Self::new(time::Duration::from_secs(60 * 60))
    }
}

/// The allowed methods.
#[derive(Debug)]
#[must_use]
pub enum MethodAllowList<'a> {
    /// All methods are allowed.
    All,
    /// Only the methods in the slice are allowed.
    Selected(&'a [Method]),
}
impl<'a> MethodAllowList<'a> {
    #[must_use]
    fn allowed(&self, method: &Method) -> bool {
        match self {
            Self::All => true,
            Self::Selected(list) => list.contains(method),
        }
    }
    fn to_bytes(&self) -> Bytes {
        match self {
            Self::All => Bytes::from_static(b"*"),
            Self::Selected(list) => list
                .iter()
                .enumerate()
                .fold(BytesMut::with_capacity(24), |mut acc, (pos, method)| {
                    acc.extend_from_slice(method.as_str().as_bytes());
                    if pos + 1 != list.len() {
                        acc.extend_from_slice(b", ");
                    }
                    acc
                })
                .freeze(),
        }
    }
}

impl Extensions {
    /// Adds extensions to disallow all CORS requests.
    /// This is added when calling [`Extensions::new`].
    pub fn with_disallow_cors(&mut self) -> &mut Self {
        self.add_prime(
            Box::new(|request, _, _| {
                box_fut!({
                    let request = unsafe { request.get_inner() };

                    let missmatch = request
                        .headers()
                        .get("origin")
                        .and_then(|origin| origin.to_str().ok())
                        .map_or(false, |origin| {
                            !Cors::is_part_of_origin(origin, request.uri())
                        });
                    if missmatch {
                        Some(Uri::from_static("/./cors_fail"))
                    } else {
                        None
                    }
                })
            }),
            Id::new(16_777_216, "Reroute all CORS requests to /./cors_fail"),
        );

        self.add_prepare_single(
            "/./cors_fail".to_owned(),
            Box::new(|_, _, _, _| {
                ready({
                    let response = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Bytes::from_static(b"CORS request denied"))
                        .expect("we know this is a good request.");
                    FatResponse::new(response, comprash::ServerCachePreference::Full)
                })
            }),
        );
        self.add_prime(
            Box::new(move |request, _, _| {
                let request = unsafe { request.get_inner() };
                ready(
                    if request.method() == Method::OPTIONS
                        && request.headers().get("origin").is_some()
                        && request
                            .headers()
                            .get("access-control-request-method")
                            .is_some()
                    {
                        Some(Uri::from_static("/./cors_fail"))
                    } else {
                        None
                    },
                )
            }),
            Id::new(16_777_215, "Provides CORS preflight request support"),
        );
        self
    }
    /// Overrides the default handling (deny all) of CORS requests to be `cors_settings`.
    ///
    /// See [`Cors`] for an example and more info.
    pub fn with_cors(&mut self, cors_settings: Arc<Cors>) -> &mut Self {
        self.with_disallow_cors();

        let options_cors_settings = Arc::clone(&cors_settings);
        let package_cors_settings = Arc::clone(&cors_settings);

        // This priority have to be higher than the one in the [`Self::add_disallow_cors`]'s prime
        // extension.
        self.add_prime(
            Box::new(move |request, _, _| {
                let request = unsafe { request.get_inner() };

                let allow = cors_settings.check_cors_request(request);
                ready(if allow.is_some() {
                    None
                } else {
                    Some(Uri::from_static("/./cors_fail"))
                })
            }),
            Id::new(
                16_777_216,
                "Reroute not allowed CORS request to /./cors_fail",
            ),
        );

        // Low priority so it runs last.
        self.add_package(
            Box::new(move |mut response, request, _| {
                let (response, request) = unsafe { (response.get_inner(), request.get_inner()) };

                if let Some(origin) = request.headers().get("origin") {
                    let allowed = package_cors_settings.check_cors_request(request).is_some();
                    if allowed {
                        utils::replace_header(
                            response.headers_mut(),
                            "access-control-allow-origin",
                            origin.clone(),
                        );
                    }
                }
                ready(())
            }),
            Id::new(
                -1024,
                "Adds access-control-allow-origin depending on if CORS request is allowed",
            ),
        );

        self.add_prepare_single(
            "/./cors_options".to_owned(),
            Box::new(move |mut request, _, _, _| {
                let request = unsafe { request.get_inner() };
                let allowed = options_cors_settings.check_cors_request(request);

                if allowed.is_none() {
                    return ready({
                        let response = Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Bytes::from_static(b"CORS request denied"))
                            .expect("we know this is a good request.");
                        FatResponse::new(response, comprash::ServerCachePreference::Full)
                    });
                }

                let mut builder = Response::builder().status(StatusCode::NO_CONTENT);

                if let Some((methods, headers, cache_for)) = allowed {
                    let methods = methods.to_bytes();
                    let headers = headers
                        .iter()
                        .enumerate()
                        .fold(BytesMut::with_capacity(24), |mut acc, (pos, header)| {
                            acc.extend_from_slice(header.as_str().as_bytes());
                            if pos + 1 != headers.len() {
                                acc.extend_from_slice(b", ");
                            }
                            acc
                        })
                        .freeze();

                    builder = builder
                        .header(
                            "access-control-allow-methods",
                            // We know all the characters from [`Method::as_str`] are valid.
                            HeaderValue::from_maybe_shared(methods).unwrap(),
                        )
                        .header(
                            "access-control-allow-headers",
                            // We know all the characters from [`HeaderName::as_str()`] are valid.
                            // See https://docs.rs/http/0.2.4/http/header/struct.HeaderValue.html#impl-From%3CHeaderName%3E
                            HeaderValue::from_maybe_shared(headers).unwrap(),
                        )
                        .header(
                            "access-control-max-age",
                            // We know a number is valid
                            HeaderValue::try_from(
                                (cache_for.as_secs() + u64::from(cache_for.subsec_nanos() > 0))
                                    .to_string(),
                            )
                            .unwrap(),
                        );
                }

                let response = builder.body(Bytes::new()).unwrap_or_else(|_| {
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(utils::hardcoded_error_body(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            None,
                        ))
                        .expect("this is a good response.")
                });
                ready(FatResponse::new(
                    response,
                    comprash::ServerCachePreference::None,
                ))
            }),
        );

        // This priority has to be above all the above, else it won't be able to get the options.
        self.add_prime(
            Box::new(move |request, _, _| {
                let request = unsafe { request.get_inner() };
                ready(
                    if request.method() == Method::OPTIONS
                        && request.headers().get("origin").is_some()
                        && request
                            .headers()
                            .get("access-control-request-method")
                            .is_some()
                    {
                        Some(Uri::from_static("/./cors_options"))
                    } else {
                        None
                    },
                )
            }),
            Id::new(16_777_215, "Provides CORS preflight request support"),
        );

        self
    }
}

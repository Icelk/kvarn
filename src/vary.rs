//! Vary header handling in Kvarn.
//!
//! You (as a user of Kvarn or extension author),
//! can add rules for headers which caches the response depending on their values.
//!
//! Indexed by request headers, which are modified by callbacks, specific to each header.
//!
//! See the example at [`Vary`] for an example implementation where
//! we have two pages, one in English and one in Swedish.
//! They are served depending on the user's preference.
//! All the responses are cached, so the [`Prepare`] extension will be called at most once.

use crate::prelude::*;
use comprash::CompressedResponse;
use utils::SuperUnsafePointer;

/// The transformation on a request header to get the
/// "key" header value to store in the cache (in the [`comprash::HeaderCollection`]).
// It's a `Arc` to enable cloning of `VaryRule`.
pub(crate) type Transformation = Pin<Arc<dyn Fn(&str) -> Cow<'static, str> + Send + Sync>>;

/// A rule for how to handle a single varied header.
///
/// Takes the name of the request header,
/// how to get the header to cache using,
/// and a default.
#[derive(Clone)]
pub(crate) struct Rule {
    name: &'static str,
    transformation: Transformation,
    default: &'static str,
}
impl Debug for Rule {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaryRule")
            .field("name", &self.name)
            .field("transformation", &"[ transformation Fn ]".as_clean())
            .field("default", &self.default)
            .finish()
    }
}
impl Rule {
    pub(crate) fn name(&self) -> &'static str {
        self.name
    }
    pub(crate) fn default(&self) -> &'static str {
        self.default
    }
    pub(crate) fn transformation(&self) -> &Transformation {
        &self.transformation
    }
}

/// The rules for handling and caching a request/response.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub(crate) rules: Vec<Rule>,
}
impl Settings {
    /// Returns an empty set of rules.
    /// Will not cache any variants, except compressed.
    #[must_use]
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }
    /// Add a custom rule.
    ///
    /// The `request_header` is used when outputting the `vary` header
    /// and for the internal cache.
    ///
    /// `transformation` takes `request_header` and (hopefully, for performance)
    /// narrows the variants down to a finite number.
    ///
    /// > Prefer to return a limited set of strings from the transformation to
    /// > minimize cache size. If you generate [`String`]s,
    /// > limit the amount of different strings.
    ///
    /// If you have a large set or infinitely many variants outputted by `transformation`,
    /// the cache will suffer. Consider disabling the cache for the files affected by this rule
    /// to improve performance.
    pub fn add_rule(
        mut self,
        request_header: &'static str,
        transformation: impl Fn(&str) -> Cow<'static, str> + Send + Sync + 'static,
        default: &'static str,
    ) -> Self {
        if self.rules.len() > 4 {
            warn!("More than 4 headers affect the caching of requests. This will exponentially increase memory usage.");
        }
        self.rules.push(Rule {
            name: request_header,
            transformation: Arc::pin(transformation),
            default,
        });
        self
    }
}
/// A set of rules for the `vary` header.
///
/// See [`Settings::add_rule`] on adding rules
/// and [`extensions::RuleSet::add`] for linking the [`Settings`] to paths.
///
/// # Examples
///
/// ```
/// use kvarn::prelude::*;
///
/// # #[tokio::test]
/// # async fn example() {
/// fn test_lang (header: &str) -> &'static str {
///     let mut langs = utils::list_header(header);
///     langs.sort_by(|l1, l2| {
///         l2.quality
///             .partial_cmp(&l1.quality)
///             .unwrap_or(cmp::Ordering::Equal)
///     });
///
///     for lang in &langs {
///         // We take the first language; the values are sorted by quality, so the highest will be
///         // chosen.
///         match lang.value {
///             "sv" => return "sv",
///             "en-GB" | "en" => return "en-GB",
///             _ => ()
///         }
///     }
///     "en-GB"
/// }
///
/// let host = Host::non_secure("localhost", PathBuf::from("web"), Extensions::default(), host::Options::default());
///
/// host.vary.add_mut(
///     "/test_lang",
///     vary::Settings::empty().add_rule(
///         "accept-language",
///         |header| Cow::Borrowed(test_lang(header)),
///         "en-GB",
///     ),
/// );
/// host.extensions.add_prepare_single(
///     "/test_lang",
///     prepare!(req, _host, _path, _addr {
///         let æ = req
///             .headers()
///             .get("accept-language")
///             .map(HeaderValue::to_str)
///             .and_then(Result::ok)
///             .map_or(false, |header| test_lang(header) == "sv");
///
///         let body = if æ {
///             "Hej!"
///         } else {
///             "Hello."
///         };
///
///         FatResponse::cache(Response::new(Bytes::from_static(body.as_bytes())))
///     }),
/// );
///
/// let data = Data::builder(host).build();
/// let port_descriptor = PortDescriptor::new(8080, data);
///
/// let shutdown_manager = run(run_config![port_descriptor]).await;
/// # }
/// ```
#[must_use]
pub type Vary = extensions::RuleSet<Settings>;
impl Vary {
    /// Gets the [`VarySettings`] from the ruleset using the path of `request`.
    pub fn rules_from_request<'a, T>(&'a self, request: &Request<T>) -> Cow<'a, Settings> {
        self.get(request.uri().path()).map_or_else(
            || Cow::Owned(Settings::default()),
            |rules| Cow::Borrowed(rules),
        )
    }
}

/// A header that is subject to the `vary` header.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub(crate) struct Header {
    name: &'static str,
    transformed: Cow<'static, str>,
}
/// A reference header to build [`VaryHeader`] against.
///
/// Contains the name of the header,
/// how to get the header value to store,
/// and a default if the header isn't available in the request.
#[derive(Debug, PartialEq, Eq, Clone)]
struct ReferenceHeader {
    name: &'static str,
    transformation: SuperUnsafePointer<Transformation>,
    default: &'static str,
}

/// A list of [`Header`]s.
///
/// Used as all the [`Header`]s that govern the caching of a single response.
type HeaderCollection = Vec<Header>;
/// The parameters needed to cache a response.
///
/// Can be obtained from [`VariedResponse::get_by_request`].
pub(crate) struct CacheParams {
    position: usize,
    headers: HeaderCollection,
}

#[derive(Debug)]
/// A collection of multiple responses depending on the headers the client sent,
/// according to the `vary` header.
///
/// The caching of multiple responses per path is controlled using [`Host::vary`].
pub struct VariedResponse {
    reference_headers: Vec<ReferenceHeader>,
    responses: Vec<(CompressedResponse, HeaderCollection)>,
}
impl VariedResponse {
    /// # Safety
    ///
    /// `settings` must not be dropped during the lifetime of this object.
    /// Keeping the [`host`] alive (which contains the cache) is enough.
    pub(crate) unsafe fn new<T>(
        response: CompressedResponse,
        request: &Request<T>,
        settings: &Settings,
    ) -> Self {
        let available_headers = settings
            .rules
            .iter()
            .map(|rule| {
                ReferenceHeader {
                    name: rule.name(),
                    // This is (mostly) safe because the type is `Pin` and `Host` is alive as long as the
                    // Kvarn server.
                    transformation: SuperUnsafePointer::new(rule.transformation()),
                    default: rule.default(),
                }
            })
            .collect();
        let mut me = Self {
            reference_headers: available_headers,
            responses: Vec::new(),
        };
        // Nothing is in the cache. We know this will be an error.
        let params = me.get_by_request(request).unwrap_err();
        me.push_response(response, params);

        me
    }
    pub(crate) fn push_response(
        &mut self,
        response: CompressedResponse,
        params: CacheParams,
    ) -> &(CompressedResponse, HeaderCollection) {
        debug_assert_eq!(self.reference_headers.len(), params.headers.len());
        let CacheParams { position, headers } = params;
        self.responses.insert(position, (response, headers));
        &self.responses[position]
    }
    fn get(&self, other: &[Header]) -> Result<usize, usize> {
        self.responses.binary_search_by_key(&other, |pair| &pair.1)
    }
    pub(crate) fn get_by_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<&(CompressedResponse, HeaderCollection), CacheParams> {
        let headers = {
            let mut headers = Vec::new();
            // Check every stored in here,
            // and if header isn't there, accept.
            for reference in &self.reference_headers {
                let name = reference.name;
                if let Some(header) = request
                    .headers()
                    .get(name)
                    .map(HeaderValue::to_str)
                    .and_then(Result::ok)
                {
                    // SAFETY: guaranteed by [`Self::new`]
                    let transformation = unsafe { reference.transformation.get() };
                    let header = transformation(header);
                    headers.push(Header {
                        name: reference.name,
                        transformed: header,
                    });
                } else {
                    headers.push(Header {
                        name: reference.name,
                        transformed: Cow::Borrowed(reference.default),
                    });
                }
            }
            headers
        };
        match self.get(&headers) {
            Ok(position) => Ok(&self.responses[position]),
            Err(sorted_position) => Err(CacheParams {
                position: sorted_position,
                headers,
            }),
        }
    }
    pub(crate) fn first(&self) -> &CompressedResponse {
        // We know there will be at least one; the [`Self::new`] method always inserts one
        // response.
        &self.responses.get(0).unwrap().0
    }
}

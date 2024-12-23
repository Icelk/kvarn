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

/// The transformation on a request header to get the
/// "key" header value to store in the cache (in the [`HeaderCollection`]).
// It's a `Arc` to enable cloning of `Rule`.
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
    // also update Debug implementation when adding fields
}
impl Debug for Rule {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct(utils::ident_str!(Rule));
        utils::fmt_fields!(
            s,
            (self.name),
            (self.transformation, &"[transformation fn]".as_clean()),
            (self.default)
        );
        s.finish()
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
#[must_use = "supply your vary settings to Kvarn"]
pub struct Settings {
    pub(crate) rules: Vec<Rule>,
}
impl Settings {
    /// Returns an empty set of rules.
    /// Will not cache any variants, except compressed.
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
    ///
    /// # Panics
    ///
    /// Will panic if the `request_header` contains invalid bytes.
    /// All of the bytes must satisfy `b >= 32 && b < 127 || b == b'\t'` where b is a byte.
    /// See [`utils::is_valid_header_value_byte`].
    pub fn add_rule(
        mut self,
        request_header: &'static str,
        transformation: impl Fn(&str) -> Cow<'static, str> + Send + Sync + 'static,
        default: &'static str,
    ) -> Self {
        if self.rules.len() > 4 {
            warn!("More than 4 headers affect the caching of requests. This will exponentially increase memory usage.");
        }
        for byte in request_header.as_bytes().iter().copied() {
            assert!(
                utils::is_valid_header_value_byte(byte),
                "A Vary request header contains invalid bytes."
            );
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
/// let host = Host::non_secure("localhost", "web", Extensions::default(), host::Options::default());
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
pub type Vary = extensions::RuleSet<Settings>;
impl Vary {
    /// Gets the [`Settings`] from the ruleset using the path of `request`.
    pub fn rules_from_request<'a, T>(&'a self, request: &Request<T>) -> Cow<'a, Settings> {
        self.get(request.uri().path())
            .map_or_else(|| Cow::Owned(Settings::default()), Cow::Borrowed)
    }
}
impl Default for Vary {
    fn default() -> Self {
        Self::empty()
    }
}

/// Creates a `vary` response header from the slice of [`Header`]s.
///
/// Consider using [`apply_header`] instead.
#[must_use]
fn get_header(headers: &[Header], no_range: bool) -> HeaderValue {
    use bytes::BufMut;

    let always_add = if no_range {
        &b"accept-encoding"[..]
    } else {
        &b"accept-encoding, range"[..]
    };

    let len = headers
        .iter()
        .fold(0, |acc, header| acc + header.name.len())
        + headers.len() * 2
        + always_add.len();

    let mut bytes = BytesMut::with_capacity(len);

    bytes.put(always_add);

    for header in headers {
        bytes.put(&b", "[..]);
        bytes.put(header.name.as_bytes());
    }

    // SAFETY: [`Header`] is guaranteed to only contain valid bytes, as stated in
    // [`Settings::add_rule`].
    unsafe { HeaderValue::from_maybe_shared_unchecked(bytes) }
}

/// Converts and applies the varied `headers` to the `response`.
pub(crate) fn apply_header(response: &mut Response<Bytes>, headers: &[Header], is_streaming: bool) {
    if !response.body().is_empty() {
        let header = get_header(
            headers,
            is_streaming
                && !response
                    .headers()
                    .get("vary")
                    .and_then(|h| h.to_str().ok())
                    .map_or(false, |h| h.contains("range")),
        );
        response.headers_mut().insert("vary", header);
    }
}

/// A header that is subject to the `vary` header.
///
/// The `name` must not contains chars [0..=32] | 127.
/// See [`utils::is_valid_header_value_byte`].
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub(crate) struct Header {
    name: &'static str,
    transformed: Cow<'static, str>,
}
/// A reference header to build [`Header`] against.
///
/// Contains the name of the header,
/// how to get the header value to store,
/// and a default if the header isn't available in the request.
#[derive(Clone)]
struct ReferenceHeader {
    name: &'static str,
    transformation: Transformation,
    default: &'static str,
}
impl Debug for ReferenceHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct(utils::ident_str!(ReferenceHeader));

        utils::fmt_fields!(
            s,
            (self.name),
            (self.transformation, &"[transformation]".as_clean()),
            (self.default)
        );

        s.finish()
    }
}

/// A list of [`Header`]s.
///
/// Used as all the [`Header`]s that govern the caching of a single response.
pub(crate) type HeaderCollection = Vec<Header>;
/// The parameters needed to cache a response.
///
/// Can be obtained from [`VariedResponse::get_by_request`].
pub(crate) struct CacheParams {
    position: usize,
    headers: HeaderCollection,
}

#[derive(Debug, Clone)]
/// A collection of multiple responses depending on the headers the client sent,
/// according to the `vary` header.
///
/// The caching of multiple responses per path is controlled using [`Host::vary`].
pub struct VariedResponse {
    reference_headers: Vec<ReferenceHeader>,
    responses: Vec<Arc<(CompressedResponse, HeaderCollection)>>,
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
                    transformation: rule.transformation().clone(),
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
    ) -> &Arc<(CompressedResponse, HeaderCollection)> {
        debug_assert_eq!(self.reference_headers.len(), params.headers.len());
        let CacheParams { position, headers } = params;
        self.responses
            .insert(position, Arc::new((response, headers)));
        &self.responses[position]
    }
    fn get(&self, other: &[Header]) -> Result<usize, usize> {
        self.responses.binary_search_by_key(&other, |pair| &pair.1)
    }
    fn get_headers_for_request<T>(&self, request: &Request<T>) -> HeaderCollection {
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
                let header = (reference.transformation)(header);
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
    }
    pub(crate) fn get_by_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<&Arc<(CompressedResponse, HeaderCollection)>, CacheParams> {
        let headers = self.get_headers_for_request(request);
        match self.get(&headers) {
            Ok(position) => Ok(&self.responses[position]),
            Err(sorted_position) => Err(CacheParams {
                position: sorted_position,
                headers,
            }),
        }
    }
    pub(crate) fn first(&self) -> &Arc<(CompressedResponse, HeaderCollection)> {
        // We know there will be at least one; the [`Self::new`] method always inserts one
        // response.
        self.responses.first().unwrap()
    }
}

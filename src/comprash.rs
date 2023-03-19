//! ***Compr***ess and c***ach***e.
//!
//! Provides the [`MokaCache`] for Kvarn.
//! When a response is made cacheable, several important headers are appended.
//! See [`FatResponse`] for more info.
//!
//! The main type in this module is [`CompressedResponse`], a dynamically compressed
//! response receiving correct headers and [`extensions`].
use crate::prelude::{chrono::*, *};
use std::{borrow::Borrow, hash::Hash};

/// The HTTP date time format in the [`time`] format.
pub static HTTP_DATE: &[time::format_description::FormatItem] = time::macros::format_description!("[weekday repr:short case_sensitive:true], [day padding:zero] [month repr:short case_sensitive:true] [year padding:zero repr:full base:calendar sign:automatic] [hour repr:24 padding:zero]:[minute padding:zero]:[second padding:zero] GMT");

/// A [`MokaCache`] with appropriate type parameters for a file cache.
pub type FileCache = MokaCache<CompactString, Bytes>;
/// A [`MokaCache`] with appropriate type parameters for a response cache.
pub type ResponseCache = MokaCache<UriKey, LifetimeCache<Arc<VariedResponse>>>;

/// A path an optional query used in [`UriKey`]
///
/// Represented as a [`String`] with a [`usize`] indicating the start of query.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[must_use]
pub struct PathQuery {
    string: CompactString,
    query_start: usize,
}
impl PathQuery {
    /// Get the path segment.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &str {
        &self.string[..self.query_start]
    }
    /// Get the optional query segment.
    /// `&str` will never be empty if the return value is [`None`].
    #[inline]
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        if self.query_start == self.string.len() {
            None
        } else {
            Some(&self.string[self.query_start..])
        }
    }
    /// Discards any [`Self::query()`].
    pub fn truncate_query(&mut self) {
        self.string.truncate(self.query_start);
    }
    /// Discards any [`Self::query()`] and returns the [`Self::path()`] as a [`String`]
    #[inline]
    #[must_use]
    pub fn into_path(mut self) -> CompactString {
        self.truncate_query();
        self.string
    }
}
/// Converts a [`Uri`] using one allocation.
impl From<&Uri> for PathQuery {
    fn from(uri: &Uri) -> Self {
        match uri.query() {
            Some(query) => {
                let mut string = CompactString::with_capacity(uri.path().len() + query.len());
                string.push_str(uri.path());
                string.push_str(query);
                Self {
                    string,
                    query_start: uri.path().len(),
                }
            }
            None => Self {
                string: uri.path().to_compact_string(),
                query_start: uri.path().len(),
            },
        }
    }
}

/// A key for an Uri used in [`ResponseCache`].
///
/// This is, for now, an opaque type in it's API.
/// Though, you can extract the path and query through matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UriKey {
    /// Uri with only a path component.
    ///
    /// Searching the cache with this should be avoided.
    /// See [`Self::call_all`].
    Path(CompactString),
    /// Uri with a path and optional query.
    ///
    /// See [`PathQuery`].
    PathQuery(PathQuery),
}
impl UriKey {
    /// Constructs a new [`UriKey`] from `uri`.
    ///
    /// This variant will math both [`Self::PathQuery`] and [`Self::Path`]
    /// if [`Self::call_all`] is called on it.
    #[inline]
    pub fn path_and_query(uri: &Uri) -> Self {
        Self::PathQuery(PathQuery::from(uri))
    }

    /// Tries to get type `T` from `callback` using current variant and other variants with fewer data.
    /// Returns `Self` which got a result from `callback` or, if none, truncated to `Self::Path`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kvarn::prelude::*;
    /// let key = UriKey::path_and_query(&Uri::from_static("https://icelk.dev/status?format=json"));
    ///
    /// // First gets called once with key as UriKey::PathQuery("/status?format=json")
    /// // then, the query gets truncated and we get a key as UriKey::Path("/status").
    /// let (_key, found) = key.call_all(|key| {
    ///     match key {
    ///         UriKey::Path(path) if *path == "/status" => Some(true),
    ///         _ => None
    ///     }
    /// });
    ///
    /// assert_eq!(found, Some(true));
    /// ```
    #[inline]
    pub fn call_all<T>(
        mut self,
        mut callback: impl FnMut(&Self) -> Option<T>,
    ) -> (Self, Option<T>) {
        match callback(&self) {
            Some(t) => (self, Some(t)),
            None => match self {
                Self::Path(_) => (self, None),
                Self::PathQuery(path_query) => {
                    self = Self::Path(path_query.into_path());
                    let result = callback(&self);
                    (self, result)
                }
            },
        }
    }
}

/// Checks `mime` if the content should be compressed;
/// heuristically checks for compressed formats.
pub fn do_compress(mime: &Mime, check_utf8: impl Fn() -> bool) -> bool {
    // IMAGE first, because it is the most likely
    mime.type_() != mime::IMAGE
        && mime.type_() != mime::FONT
        && mime.type_() != mime::VIDEO
        && mime.type_() != mime::AUDIO
        && mime.type_() != mime::STAR
        // compressed applications
        && mime != &mime::APPLICATION_PDF
        && mime.subtype() != "zip"
        && mime.subtype() != "zstd"
        // all applications which are not js, graphql, json, xml, or valid utf-8
        && (mime.type_() != mime::APPLICATION
            || (mime.subtype() == mime::JAVASCRIPT
                || mime.subtype() == "graphql"
                || mime.subtype() == mime::JSON
                || mime.subtype() == mime::XML
                || mime.subtype() == "wasm"
                || mime.subtype() == "octet-stream"
                || check_utf8()))
}

/// The preferred compression algorithm.
///
/// The default is chosen according to the [cargo features](https://kvarn.org/cargo-features.) in
/// the following order:
/// - Brotli
/// - Gzip
/// - None
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreferredCompression {
    /// Prefer the brotli algorithm.
    ///
    /// This is the default and is the best.
    #[cfg(feature = "br")]
    Brotli,
    /// Prefer the gzip algorithm.
    ///
    /// Uses a bit less memory than [`Self::Brotli`] at the expense of compression.
    #[cfg(feature = "gzip")]
    Gzip,
    /// Prefer no compression. This is the default if no compression features are enabled.
    None,
}
impl PreferredCompression {
    /// Return the name used in the `content-encoding` header.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "br")]
            Self::Brotli => "br",
            #[cfg(feature = "gzip")]
            Self::Gzip => "gzip",
            Self::None => "identity",
        }
    }
}
impl Default for PreferredCompression {
    fn default() -> Self {
        #[cfg(feature = "br")]
        {
            PreferredCompression::Brotli
        }
        #[cfg(all(not(feature = "br"), feature = "gzip"))]
        {
            PreferredCompression::Gzip
        }
        #[cfg(all(not(feature = "br"), not(feature = "gzip")))]
        {
            PreferredCompression::None
        }
    }
}
/// Some options for how to compress the response.
#[derive(Debug, Clone)]
pub struct CompressionOptions {
    /// The preferred compression algorithm.
    pub preferred: PreferredCompression,
    /// The level of brotli compression.
    ///
    /// See [some benchmarks](https://quixdb.github.io/squash-benchmark/#results) for more context.
    #[cfg(feature = "br")]
    pub brotli_level: u32,
    /// The level of gzip compression.
    ///
    /// See [some benchmarks](https://quixdb.github.io/squash-benchmark/#results) for more context.
    #[cfg(feature = "gzip")]
    pub gzip_level: u32,
}
#[allow(clippy::derivable_impls)] // if no features are enabled, we get a warning, since the only field is using it's default
impl Default for CompressionOptions {
    fn default() -> Self {
        Self {
            preferred: PreferredCompression::default(),
            #[cfg(feature = "br")]
            brotli_level: 3,
            #[cfg(feature = "gzip")]
            gzip_level: 1,
        }
    }
}

/// A response with a lazily compressed body.
///
/// The compressed body is cached.
/// It therefore uses `unsafe` to mutate the [`Option`]s containing the compressed data.
/// This should be fine; we only write once, if the value is [`None`].
#[derive(Debug)]
#[must_use]
pub struct CompressedResponse {
    identity: Response<Bytes>,
    #[cfg(feature = "gzip")]
    gzip: Option<Bytes>,
    #[cfg(feature = "br")]
    br: Option<Bytes>,

    compress: CompressPreference,
}
impl CompressedResponse {
    pub(crate) fn new(
        mut identity: Response<Bytes>,
        compress: CompressPreference,
        client_cache: ClientCachePreference,
        extension: &str,
        disable_client_cache: bool,
    ) -> Self {
        let headers = identity.headers_mut();
        Self::set_client_cache(headers, client_cache, disable_client_cache);
        Self::check_content_type(&mut identity, extension);
        Self {
            identity,
            #[cfg(feature = "gzip")]
            gzip: None,
            #[cfg(feature = "br")]
            br: None,

            compress,
        }
    }
    /// Gets the response with an uncompressed body.
    #[inline]
    pub fn get_identity(&self) -> &Response<Bytes> {
        &self.identity
    }

    /// Clones the preferred compression type based on
    /// `accept-encoding` header in `request`
    /// and already cached bodies.
    ///
    /// If an error occurs, you should respond with an [`StatusCode::NOT_ACCEPTABLE`].
    ///
    /// # Errors
    ///
    /// May return a &str to be used to inform the client what error occurred in content negotiation.
    pub fn clone_preferred<T>(
        &self,
        request: &Request<T>,
        options: &CompressionOptions,
    ) -> Result<Response<Bytes>, &'static str> {
        let values = match request
            .headers()
            .get("accept-encoding")
            .map(HeaderValue::to_str)
            .and_then(Result::ok)
        {
            Some(header) => utils::list_header(header),
            None => Vec::new(),
        };

        let disable_identity = values
            .iter()
            .any(|v| v.value == "identity" && v.quality == 0.0);

        let only_identity = values.len() == 1
            && values[0]
                == utils::ValueQualitySet {
                    value: "identity",
                    quality: 1.0,
                };

        // Only identity makes sure identity quality is `1.0`; identity encoding can't be disabled.
        if only_identity {
            return Ok(self.clone_identity_set_compression(
                Bytes::clone(self.get_identity().body()),
                HeaderValue::from_static("identity"),
            ));
        }

        #[cfg(any(feature = "gzip", feature = "br"))]
        let contains = |name| values.iter().any(|v| v.value == name && v.quality != 0.0);

        let mime = self
            .get_identity()
            .headers()
            .get("content-type")
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.parse().ok());
        debug!("Recognised mime {:?}", &mime);
        let (bytes, compression) = match &mime {
            Some(mime) => {
                if do_compress(mime, || str::from_utf8(self.get_identity().body()).is_ok()) {
                    match self.compress {
                        CompressPreference::None => (self.get_identity().body(), "identity"),
                        CompressPreference::Full => {
                            #[cfg(feature = "br")]
                            let contains_br = contains("br");
                            #[cfg(feature = "gzip")]
                            let contains_gzip = contains("gzip");

                            #[allow(unused_mut)]
                            let mut preferred = match options.preferred.as_str() {
                                #[cfg(feature = "br")]
                                "br" if contains_br => {
                                    Some((self.get_br(options.brotli_level), "br"))
                                }
                                #[cfg(feature = "gzip")]
                                "gzip" if contains_gzip => {
                                    Some((self.get_gzip(options.gzip_level), "gzip"))
                                }
                                _ => None,
                            };
                            #[cfg(feature = "br")]
                            if preferred.is_none() && contains_br {
                                preferred = Some((self.get_br(options.brotli_level), "br"));
                            }
                            #[cfg(feature = "gzip")]
                            if preferred.is_none() && contains_gzip {
                                preferred = Some((self.get_gzip(options.gzip_level), "gzip"));
                            }
                            preferred.unwrap_or_else(|| (self.get_identity().body(), "identity"))
                        }
                    }
                } else {
                    debug!("Not compressing; filtered out.");
                    (self.get_identity().body(), "identity")
                }
            }
            None => (self.get_identity().body(), "identity"),
        };
        if disable_identity && compression == "identity" {
            return Err(
                "identity compression is the only option, but the client refused to accept it",
            );
        }
        Ok(self.clone_identity_set_compression(
            Bytes::clone(bytes),
            HeaderValue::from_static(compression),
        ))
    }

    #[inline]
    fn set_client_cache(
        headers: &mut HeaderMap,
        preference: ClientCachePreference,
        disable_client_cache: bool,
    ) {
        let header = if disable_client_cache {
            Some(HeaderValue::from_static("no-store"))
        } else {
            preference.as_header()
        };
        if let Some(h) = header {
            headers.entry("cache-control").or_insert(h);
        }
    }
    fn check_content_type(response: &mut Response<Bytes>, extension: &str) {
        fn add_utf_8(headers: &mut HeaderMap, mime: &Mime) {
            let charset = if mime.get_param(mime::CHARSET) == Some(mime::UTF_8) {
                ""
            } else {
                "; charset=utf-8"
            };
            // We know the added bytes are safe for a http::HeaderValue
            // unwrap is ok.
            let mut header = mime.to_string();
            header.push_str(charset);
            let content_type =
                HeaderValue::from_maybe_shared::<Bytes>(header.into_bytes().into()).unwrap();
            headers.insert("content-type", content_type);
        }
        let utf_8 = response.body().len() < 16 * 1024 && str::from_utf8(response.body()).is_ok();

        match response.headers().get("content-type") {
            Some(content_type) => {
                if let Some(mime_type) = content_type
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse::<Mime>().ok())
                {
                    #[allow(clippy::match_same_arms)] // we have comments
                    match mime_type.get_param("charset") {
                        None if utf_8 => {
                            add_utf_8(response.headers_mut(), &mime_type);
                        }
                        // Has charset attribute or we shouldn't add a charset parameter
                        Some(_) | None => {}
                    }
                }
            }
            None if !response.body().is_empty() => {
                let mime = if utf_8 {
                    mime::TEXT_HTML_UTF_8
                } else {
                    mime::APPLICATION_OCTET_STREAM
                };
                let mime_type = mime_guess::from_ext(extension).first_or(mime);
                if utf_8 {
                    add_utf_8(response.headers_mut(), &mime_type);
                } else {
                    // Mime will only contains valid bytes.
                    let content_type = HeaderValue::from_maybe_shared::<Bytes>(
                        mime_type.to_string().into_bytes().into(),
                    )
                    .unwrap();
                    response.headers_mut().insert("content-type", content_type);
                }
            }
            None => {}
        }
    }

    fn clone_identity_set_compression(
        &self,
        new_data: Bytes,
        compression: HeaderValue,
    ) -> Response<Bytes> {
        let response = &self.identity;
        let mut builder = Response::builder()
            .version(response.version())
            .status(response.status());
        let mut map = response.headers().clone();
        if !new_data.is_empty() {
            let headers = &mut map;
            debug!(
                "Changing content-encoding from {:?}. Has content-type {:?}",
                headers.get("content-encoding"),
                headers.get("content-type"),
            );
            headers.insert("content-encoding", compression);
        }
        *builder.headers_mut().unwrap() = map;
        builder.body(new_data).unwrap()
    }

    /// Gets the gzip compressed version of [`CompressedResponse::get_identity()`]
    ///
    /// You should use [`Self::clone_preferred`] to get the preferred compression instead,
    /// as it is available with any set of features
    #[cfg(feature = "gzip")]
    pub fn get_gzip(&self, level: u32) -> &Bytes {
        if self.gzip.is_none() {
            let bytes = self.identity.body().as_ref();

            let mut buffer = utils::WriteableBytes::with_capacity(bytes.len() / 3 + 64);

            // 1-9, 1 is fast, 9 is slow. 4 is equal to brotli's 3
            let mut c = flate2::write::GzEncoder::new(&mut buffer, flate2::Compression::new(level));
            c.write_all(bytes).expect("Failed to compress using gzip!");
            c.finish().expect("Failed to compress using gzip!");

            let buffer = buffer.into_inner();
            let buffer = buffer.freeze();

            // Last check to make sure we don't override any value.
            if self.gzip.is_none() {
                // maybe shooting myself in the foot...
                // but should be OK, since we only set it once, otherwise it's None.
                unsafe { (*{ utils::ref_to_mut(&self.gzip) }).replace(buffer) };
            }
        }
        self.gzip.as_ref().unwrap()
    }
    /// Gets the Brotli compressed version of [`CompressedResponse::get_identity()`]
    ///
    /// You should use [`Self::clone_preferred`] to get the preferred compression instead,
    /// as it is available with any set of features
    #[cfg(feature = "br")]
    pub fn get_br(&self, level: u32) -> &Bytes {
        if self.br.is_none() {
            let bytes = self.identity.body().as_ref();

            let mut buffer = utils::WriteableBytes::with_capacity(bytes.len() / 3 + 64);

            // 1-10, 1 is fast, 10 is really slow
            let mut c = brotli::CompressorWriter::new(&mut buffer, 4096, level, 21);
            c.write_all(bytes)
                .expect("Failed to compress using Brotli!");
            c.flush().expect("Failed to compress using Brotli!");
            c.into_inner();

            let buffer = buffer.into_inner();
            let buffer = buffer.freeze();

            // Last check to make sure we don't override any value.
            if self.br.is_none() {
                // maybe shooting myself in the foot...
                // but should be OK, since we only set it once, otherwise it's None.
                unsafe { (*{ utils::ref_to_mut(&self.br) }).replace(buffer) };
            }
        }
        self.br.as_ref().unwrap()
    }
}

/// The preference of compression in [`CompressedResponse`].
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CompressPreference {
    /// Will not auto-compress response body
    None,
    /// Will automatically compress and send compressed versions of the response
    Full,
}

/// Error in parsing cache preference.
///
/// # Examples
///
/// ```
/// # use kvarn::prelude::{*, comprash::CachePreferenceError, comprash::ServerCachePreference,
/// comprash::ClientCachePreference};
/// assert_eq!(Err(CachePreferenceError::Empty), "".parse::<ServerCachePreference>());
/// assert_eq!(Err(CachePreferenceError::Invalid), "FULL".parse::<ClientCachePreference>());
/// assert_eq!(Ok(ServerCachePreference::QueryMatters), "query-matters".parse());
/// use std::convert::TryInto;
/// assert_eq!(Ok(ClientCachePreference::MaxAge(Duration::from_secs(42))), "42s".parse());
/// assert_eq!(Ok(ServerCachePreference::MaxAge(Duration::from_secs(3600))), "3600s".parse());
/// assert_eq!(Err(CachePreferenceError::ZeroDuration), "0s".parse::<ClientCachePreference>());
/// assert_eq!(Err(CachePreferenceError::ZeroDuration), "0s".parse::<ServerCachePreference>());
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CachePreferenceError {
    /// Input string is empty.
    Empty,
    /// Input string has an invalid syntax.
    Invalid,
    /// Duration is zero
    ZeroDuration,
}

/// The preference for caching the item on the server.
///
/// This can be overridden by the `cache-control` or `kvarn-cache-control` headers.
///
/// Note: It's only a preference. Disabling the cache in compile-time will
/// disable this behaviour. Some other factors also play a role, such as number of cached
/// `Vary` responses on a page.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ServerCachePreference {
    /// Will not cache response
    None,
    /// Will cache response with query
    QueryMatters,
    /// Query does not matter and will be discarded
    Full,
    /// Sets a max age for the content.
    /// Query will be discarded in cache, same as [`Self::Full`].
    MaxAge(Duration),
}
impl ServerCachePreference {
    /// If a response with `cache_action` (from [`host::CacheAction`]) should be cached.
    #[inline]
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn cache(self, cache_action: host::CacheAction, method: &Method) -> bool {
        let of_self = match self {
            Self::None => false,
            Self::QueryMatters | Self::Full | Self::MaxAge(_) => true,
        };
        #[allow(clippy::unnested_or_patterns)] // matches! macro
        let of_response =
            cache_action.into_cache() && matches!(method, &Method::GET | &Method::HEAD);
        of_self && of_response
    }
    /// If query matters in cache.
    ///
    /// Ultimately dictates which variant of [`UriKey`] should be cached.
    #[inline]
    #[must_use]
    pub fn query_matters(self) -> bool {
        match self {
            Self::None | Self::Full | Self::MaxAge(_) => false,
            Self::QueryMatters => true,
        }
    }
}
impl str::FromStr for ServerCachePreference {
    type Err = CachePreferenceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "full" => ServerCachePreference::Full,
            "query_matters" | "query-matters" | "QueryMatters" | "queryMatters" => {
                ServerCachePreference::QueryMatters
            }
            "none" => ServerCachePreference::None,
            "" => return Err(CachePreferenceError::Empty),
            _ => {
                if let Some(integer) = s.strip_suffix('s') {
                    if let Ok(integer) = integer.parse::<u64>() {
                        if integer == 0 {
                            return Err(CachePreferenceError::ZeroDuration);
                        }
                        return Ok(Self::MaxAge(integer.std_seconds()));
                    }
                }
                return Err(CachePreferenceError::Invalid);
            }
        })
    }
}
/// Automatically add `cache-control` header to response.
///
/// If a `cache-control` header is already present, it will be prioritized.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ClientCachePreference {
    /// Don't manage the `cache-control` header.
    Ignore,
    /// Will not cache on client
    None,
    /// A two-minute cache lifetime
    Changing,
    /// Will cache for 1 week
    Full,
    /// Sets a max age for the content.
    ///
    /// Note that this must be in seconds when sending a header.
    /// This will be rounded up.
    MaxAge(Duration),
}
impl ClientCachePreference {
    /// Gets the [`HeaderValue`] representation of the preference.
    #[inline]
    #[must_use]
    pub fn as_header(self) -> Option<HeaderValue> {
        Some(match self {
            Self::Ignore => return None,
            Self::None => HeaderValue::from_static("no-store"),
            Self::Changing => HeaderValue::from_static("max-age=120"),
            Self::Full => HeaderValue::from_static("public, max-age=604800, immutable"),
            Self::MaxAge(duration) => {
                let bytes = build_bytes!(
                    b"public, max-age=",
                    // if > second integer, add 1 second (ceil the duration).
                    // i64::from(bool) returns 1 if true.
                    (duration.as_secs() + u64::from(duration.subsec_nanos() > 0))
                        .to_string()
                        .as_bytes(),
                    b", immutable"
                );
                // We know these bytes are safe.
                HeaderValue::from_maybe_shared(bytes).unwrap()
            }
        })
    }
}
impl str::FromStr for ClientCachePreference {
    type Err = CachePreferenceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(integer) = s.strip_suffix('s') {
            if let Ok(integer) = integer.parse::<u64>() {
                if integer == 0 {
                    return Err(CachePreferenceError::ZeroDuration);
                }
                return Ok(Self::MaxAge(integer.std_seconds()));
            }
        }
        Ok(match s {
            "ignore" => ClientCachePreference::Ignore,
            "full" => ClientCachePreference::Full,
            "changing" => ClientCachePreference::Changing,
            "none" => ClientCachePreference::None,
            "" => return Err(CachePreferenceError::Empty),
            _ => return Err(CachePreferenceError::Invalid),
        })
    }
}

/// Output of cache operations.
///
/// [`CacheOut::None`] and [`CacheOut::Present`] reflects the [`HashMap`] API.
/// [`CacheOut::NotInserted`] is added to indicate the content to be cached
/// does not meet the requirements (e.g. it's too big)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum CacheOut<V> {
    /// No value.
    ///
    /// Returned when no item occupies the input key.
    None,
    /// Successful cache lookup.
    ///
    /// Returned when an item occupies the input key.
    Present(V),
    /// Error when value failed to get inserted. See [`CacheOut`].
    NotInserted(V),
}
impl<V> CacheOut<V> {
    /// Maps self to an [`Option`].
    ///
    /// Variants with a value are turned to [`Some`]
    /// and [`CacheOut::None`] to [`None`].
    #[inline]
    pub fn into_option(self) -> Option<V> {
        match self {
            Self::None => None,
            Self::Present(v) | Self::NotInserted(v) => Some(v),
        }
    }
    /// Applies a function to the inner value `V` of [`CacheOut`],
    /// if not [`CacheOut::None`] and returns a `CacheOut` with
    /// the transformed `K`.
    pub fn map<K>(self, f: impl FnOnce(V) -> K) -> CacheOut<K> {
        match self {
            Self::None => CacheOut::None,
            Self::NotInserted(v) => CacheOut::NotInserted(f(v)),
            Self::Present(v) => CacheOut::Present(f(v)),
        }
    }
}

/// Cache using [`moka`].
#[derive(Debug)]
pub struct MokaCache<K: Hash + Eq + Send + Sync + 'static, V: Clone + Send + Sync + 'static> {
    size_limit: usize,
    /// The inner cache, with direct access allowed.
    /// Please check the size of your item before inserting.
    pub cache: moka::future::Cache<K, V>,
}
impl<K: Hash + Eq + Send + Sync + 'static, V: Clone + Send + Sync + 'static> Default
    for MokaCache<K, V>
{
    fn default() -> Self {
        Self {
            size_limit: 4 * 1024 * 1024,
            cache: moka::future::Cache::new(1024),
        }
    }
}
impl<K: Hash + Eq + Send + Sync + 'static> MokaCache<K, LifetimeCache<Arc<VariedResponse>>> {
    pub(crate) async fn get_cache_item<Q: Hash + Eq>(
        &self,
        key: &Q,
    ) -> CacheOut<LifetimeCache<Arc<VariedResponse>>>
    where
        K: Borrow<Q>,
    {
        match self.cache.get(key) {
            Some(value_and_lifetime)
                if value_and_lifetime.1 .1.map_or(true, |lifetime| {
                    OffsetDateTime::now_utc() - value_and_lifetime.1 .0 <= lifetime
                }) =>
            {
                CacheOut::Present(value_and_lifetime)
            }
            Some(_) => {
                self.cache.invalidate(key).await;
                CacheOut::None
            }
            None => CacheOut::None,
        }
    }
    pub(crate) async fn insert(
        &self,
        len: usize,
        lifetime: Option<Duration>,
        key: K,
        response: VariedResponse,
    ) -> CacheOut<VariedResponse> {
        if len >= self.size_limit {
            return CacheOut::NotInserted(response);
        }

        self.cache
            .insert(
                key,
                (Arc::new(response), (OffsetDateTime::now_utc(), lifetime)),
            )
            .await;
        CacheOut::None
    }
    pub(crate) async fn insert_cache_item(
        &self,
        key: K,
        response: VariedResponse,
    ) -> CacheOut<VariedResponse> {
        let lifetime =
            parse::CacheControl::from_headers(response.first().0.get_identity().headers())
                .ok()
                .as_ref()
                .and_then(parse::CacheControl::as_freshness)
                .map(|s| u64::from(s).std_seconds());

        debug!("Inserted item to cache with lifetime {:?}", lifetime);

        self.insert(
            response.first().0.get_identity().body().len(),
            lifetime,
            key,
            response,
        )
        .await
    }
}

/// The item used in the cache.
/// `T` represents the cached data.
///
/// The other information is for lifetimes of the cache.
/// The [`OffsetDateTime`] is when the item was added and
/// the [`Duration`] how long the item can be kept.
/// A `Duration` value of `None` means the item will never expire.
///
/// Keep in mind that `Duration` is the std variant, while `Duration` is the time crate's
/// variant, which supports negative durations.
pub type LifetimeCache<T> = (T, (OffsetDateTime, Option<Duration>));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_query_empty_query_1() {
        let uri: Uri = "https://kvarn.org/index.html?".parse().unwrap();
        let path_query = PathQuery::from(&uri);

        assert_eq!(path_query.query(), None);
    }
    #[test]
    fn path_query_empty_query_2() {
        let uri: Uri = "https://kvarn.org/index.html?hi".parse().unwrap();
        let path_query = PathQuery::from(&uri);

        assert_eq!(path_query.query(), Some("hi"));
    }
    #[test]
    fn path_query_empty_query_3() {
        let uri: Uri = "https://kvarn.org/index.html??".parse().unwrap();
        let path_query = PathQuery::from(&uri);

        assert_eq!(path_query.query(), Some("?"));
    }
    #[test]
    fn path_query_empty_query_4() {
        let uri: Uri = "https://kvarn.org/".parse().unwrap();
        let path_query = PathQuery::from(&uri);

        assert_eq!(path_query.query(), None);
    }
}

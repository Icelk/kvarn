use crate::prelude::*;
use std::{borrow::Borrow, hash::Hash};

pub type FileCache = Mutex<Cache<PathBuf, Bytes>>;
pub type ResponseCache = Mutex<Cache<UriKey, CompressedResponse>>;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PathQuery {
    string: String,
    query_start: usize,
}
impl PathQuery {
    pub fn from_uri(uri: &Uri) -> Self {
        match uri.query() {
            Some(query) => {
                let mut string = String::with_capacity(uri.path().len() + query.len());
                string.push_str(uri.path());
                string.push_str(query);
                Self {
                    string,
                    query_start: uri.path().len(),
                }
            }
            None => Self {
                string: uri.path().to_string(),
                query_start: uri.path().len(),
            },
        }
    }
    #[inline]
    pub fn path(&self) -> &str {
        &self.string[..self.query_start]
    }
    #[inline]
    pub fn query(&self) -> Option<&str> {
        if self.query_start == self.string.len() {
            None
        } else {
            Some(&self.string[self.query_start..])
        }
    }
    #[inline]
    pub fn into_path(mut self) -> String {
        self.string.truncate(self.query_start);
        self.string
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UriKey {
    Path(String),
    PathQuery(PathQuery),
}
impl UriKey {
    #[inline]
    pub fn path_and_query(uri: &Uri) -> Self {
        Self::PathQuery(PathQuery::from_uri(uri))
    }

    /// Tries to get type `T` from `callback` using current variant and other variants with fewer data.
    /// Returns `Self` which got a result from `callback`, or if none, `Self::Path`.
    #[inline]
    pub fn call_all<T>(self, mut callback: impl FnMut(&Self) -> Option<T>) -> (Self, Option<T>) {
        match callback(&self) {
            Some(t) => (self, Some(t)),
            None => match self {
                Self::Path(_) => (self, None),
                Self::PathQuery(path_query) => {
                    let new = Self::Path(path_query.into_path());
                    let t = callback(&new);
                    (new, t)
                }
            },
        }
    }
}

pub fn do_compress<F: Fn() -> bool>(mime: Mime, check_utf8: F) -> bool {
    // IMAGE first, because it is the most likely
    mime.type_() != mime::IMAGE
        && mime.type_() != mime::FONT
        && mime.type_() != mime::VIDEO
        && mime.type_() != mime::AUDIO
        && mime.type_() != mime::STAR
        // compressed applications
        && mime != mime::APPLICATION_PDF
        && mime.subtype() != "zip"
        && mime.subtype() != "zstd"
        // all applications which are not js, graphql, json, xml, or valid utf-8
        && (mime.type_() != mime::APPLICATION
            || (mime.subtype() == mime::JAVASCRIPT
                || mime.subtype() == "graphql"
                || mime.subtype() == mime::JSON
                || mime.subtype() == mime::XML
                || check_utf8()))
}

// for when no compression is compiled in
#[allow(dead_code)]
#[derive(Debug)]
pub struct CompressedResponse {
    identity: Response<Bytes>,
    gzip: Option<Bytes>,
    br: Option<Bytes>,

    compress: CompressPreference,
}
impl CompressedResponse {
    pub(crate) fn new(
        mut identity: Response<Bytes>,
        compress: CompressPreference,
        client_cache: ClientCachePreference,
        extension: &str,
    ) -> Self {
        let headers = identity.headers_mut();
        Self::set_client_cache(headers, client_cache);
        Self::add_server_header(headers);
        Self::check_content_type(&mut identity, extension);
        Self {
            identity,
            gzip: None,
            br: None,

            compress,
        }
    }
    #[inline(always)]
    pub fn get_identity(&self) -> &Response<Bytes> {
        &self.identity
    }

    pub fn clone_preferred(&self, request: &FatRequest) -> Result<Response<Bytes>, StatusCode> {
        let values = match request
            .headers()
            .get("accept-encoding")
            .map(HeaderValue::to_str)
            .and_then(Result::ok)
        {
            Some(header) => parse::format_list_header(header),
            None => Vec::new(),
        };

        let disable_identity = values
            .iter()
            .position(|v| v.value == "identity" && v.quality == 0.0)
            .is_some();

        #[cfg(all(feature = "gzip", feature = "br"))]
        let prefer_br = values
            .iter()
            .find(|v| v.value == "gzip")
            .map(|v| v.quality)
            .unwrap_or(1.0)
            <= 0.5
            && values.iter().find(|v| v.value == "br").map(|v| v.quality) == Some(1.0);

        let only_identity = values.len() == 1
            && values[0]
                == parse::ValueQualitySet {
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
        let contains = |name| {
            values
                .iter()
                .position(|v| v.value == name && v.quality != 0.0)
                .is_some()
        };

        let mime = self
            .get_identity()
            .headers()
            .get("content-type")
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.parse().ok());
        debug!("Recognised mime {:?}", mime);
        let (bytes, compression) = match mime {
            Some(mime) => {
                match do_compress(mime, || str::from_utf8(self.get_identity().body()).is_ok()) {
                    true => match self.compress {
                        CompressPreference::None => (self.get_identity().body(), "identity"),
                        CompressPreference::Full => {
                            #[cfg(all(feature = "gzip", feature = "br"))]
                            match (self.br.is_some() && self.gzip.is_none()) || prefer_br {
                                true => (self.get_br(), "br"),
                                false if contains("gzip") => (self.get_gzip(), "gzip"),
                                false if contains("br") => (self.get_br(), "br"),
                                false => (self.get_identity().body(), "identity"),
                            }
                            #[cfg(all(feature = "gzip", not(feature = "br")))]
                            {
                                match contains("gzip") {
                                    true => (self.get_gzip(), "gzip"),
                                    false => (self.get_identity().body(), "identity"),
                                }
                            }
                            #[cfg(all(feature = "br", not(feature = "gzip")))]
                            {
                                match contains("br") {
                                    true => (self.get_br(), "br"),
                                    false => (self.get_identity().body(), "identity"),
                                }
                            }
                            #[cfg(not(any(feature = "gzip", feature = "br")))]
                            {
                                (self.get_identity().body(), "identity")
                            }
                        }
                    },
                    false => {
                        debug!("Not compressing; filtered out.");
                        (self.get_identity().body(), "identity")
                    }
                }
            }
            None => (self.get_identity().body(), "identity"),
        };
        if disable_identity && compression == "identity" {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(self.clone_identity_set_compression(
            Bytes::clone(bytes),
            HeaderValue::from_static(compression),
        ))
    }

    #[inline(always)]
    fn add_server_header(headers: &mut HeaderMap) {
        headers.insert("server", HeaderValue::from_static(SERVER));
    }

    #[inline(always)]
    fn set_client_cache(headers: &mut HeaderMap, preference: ClientCachePreference) {
        if let Some(header) = preference.as_header() {
            utility::replace_header(headers, "cache-control", header)
        };
    }
    fn check_content_type(response: &mut Response<Bytes>, extension: &str) {
        let utf_8 = response.body().len() < 16 * 1024 && str::from_utf8(&response.body()).is_ok();
        match response.headers().get("content-type") {
            Some(content_type) => match content_type
                .to_str()
                .ok()
                .and_then(|s| s.parse::<Mime>().ok())
            {
                Some(mime_type) => {
                    match mime_type.get_param("charset") {
                        // Has charset attribute.
                        Some(_) => {}
                        None if utf_8 => {
                            // Unsafe if ok; we know the added bytes are safe for a http::HeaderValue
                            // and unwrap is ok; we checked same thing  just above
                            let content_type = unsafe {
                                HeaderValue::from_maybe_shared_unchecked(
                                    format!("{}; charset=utf-8", content_type.to_str().unwrap())
                                        .into_bytes(),
                                )
                            };
                            utility::replace_header(
                                response.headers_mut(),
                                "content-type",
                                content_type,
                            );
                        }
                        // We should not add charset parameter
                        None => {}
                    }
                }
                // Mime type is not recognised, not touching.
                None => {}
            },
            None => {
                let mime = match utf_8 {
                    true => mime::TEXT_HTML_UTF_8,
                    false => mime::APPLICATION_OCTET_STREAM,
                };
                let mime_type = mime_guess::from_ext(extension).first_or(mime);
                // Is ok; Mime will only contain ok bytes.
                let content_type = unsafe {
                    HeaderValue::from_maybe_shared_unchecked(mime_type.to_string().into_bytes())
                };
                response.headers_mut().insert("content-type", content_type);
            }
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
        let headers = &mut map;
        debug!(
            "Changing content-encoding from {:?}. Has content-type {:?}",
            headers.get("content-encoding"),
            headers.get("content-type"),
        );
        utility::replace_header(headers, "content-encoding", compression);
        *builder.headers_mut().unwrap() = map;
        builder.body(new_data).unwrap()
    }

    #[cfg(feature = "gzip")]
    /// Gets the gzip compressed version of [`CompressedResponse::get_identity()`]
    pub fn get_gzip(&self) -> &Bytes {
        if self.gzip.is_none() {
            let bytes = self.identity.body().as_ref();

            let mut buffer =
                utility::WriteableBytes::new(bytes::BytesMut::with_capacity(bytes.len() / 2 + 64));

            let mut c = flate2::write::GzEncoder::new(&mut buffer, flate2::Compression::fast());
            c.write_all(bytes).expect("Failed to compress using gzip!");
            c.finish().expect("Failed to compress using gzip!");

            let buffer = buffer.into_inner();
            let buffer = buffer.freeze();

            if self.gzip.is_none() {
                // maybe shooting myself in the foot...
                // but should be OK, since we only set it once, otherwise it's None.
                unsafe { (&mut *{ &self.gzip as *const _ as *mut Option<Bytes> }).replace(buffer) };
            }
        }
        self.gzip.as_ref().unwrap()
    }
    #[cfg(feature = "br")]
    /// Gets the Brotli compressed version of [`CompressedResponse::get_identity()`]
    pub fn get_br(&self) -> &Bytes {
        if self.br.is_none() {
            let bytes = self.identity.body().as_ref();

            let mut buffer =
                utility::WriteableBytes::new(bytes::BytesMut::with_capacity(bytes.len() / 2 + 64));

            let mut c = brotli::CompressorWriter::new(&mut buffer, 4096, 8, 21);
            c.write_all(bytes)
                .expect("Failed to compress using Brotli!");
            c.flush().expect("Failed to compress using Brotli!");
            c.into_inner();

            let buffer = buffer.into_inner();
            let buffer = buffer.freeze();

            if self.br.is_none() {
                // maybe shooting myself in the foot...
                // but should be OK, since we only set it once, otherwise it's None.
                unsafe { (&mut *{ &self.br as *const _ as *mut Option<Bytes> }).replace(buffer) };
            }
        }
        self.br.as_ref().unwrap()
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CompressPreference {
    /// Will not auto-compress response body
    None,
    /// Will automatically compress and send compressed versions of the response
    Full,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ServerCachePreference {
    /// Will not cache response
    None,
    /// Will cache response with query
    QueryMatters,
    /// Query does not matter and will be discarded
    Full,
}
impl ServerCachePreference {
    #[inline]
    pub fn cache(&self) -> bool {
        #[cfg(not(feature = "no-response-cache"))]
        match self {
            Self::None => false,
            Self::QueryMatters | Self::Full => true,
        }
        #[cfg(feature = "no-response-cache")]
        false
    }
    #[inline]
    pub fn query_matters(&self) -> bool {
        match self {
            Self::None | Self::Full => false,
            Self::QueryMatters => true,
        }
    }
}
/// Automatically add `cache-control` header to response
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ClientCachePreference {
    /// Will not cache on client
    None,
    /// A two-minute cache lifetime
    Changing,
    /// Will cache for 1 year
    Full,
    /// Will not add or remove any header
    Undefined,
}
impl ClientCachePreference {
    #[inline]
    pub fn as_header(&self) -> Option<HeaderValue> {
        match self {
            Self::None => Some(HeaderValue::from_static(
                "public, max-age=604800, immutable",
            )),
            Self::Changing => Some(HeaderValue::from_static(
                "public, max-age=604800, immutable",
            )),
            Self::Full => Some(HeaderValue::from_static(
                "public, max-age=604800, immutable",
            )),
            Self::Undefined => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CombinedCachePreference(pub ServerCachePreference, pub ClientCachePreference);

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ParseCachedErr {
    StringEmpty,
    UndefinedKeyword,
    ContainsSpace,
    FailedToParse,
}
impl str::FromStr for CombinedCachePreference {
    type Err = ParseCachedErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(' ') {
            Err(Self::Err::ContainsSpace)
        } else {
            match s.to_ascii_lowercase().as_str() {
                "false" | "no-cache" | "dynamic" => Ok(Self(
                    ServerCachePreference::None,
                    ClientCachePreference::None,
                )),
                "changing" | "may-change" => Ok(Self(
                    ServerCachePreference::None,
                    ClientCachePreference::Changing,
                )),
                "per-query" | "query" => Ok(Self(
                    ServerCachePreference::QueryMatters,
                    ClientCachePreference::Full,
                )),
                "true" | "static" | "immutable" => Ok(Self(
                    ServerCachePreference::Full,
                    ClientCachePreference::Full,
                )),
                "" => Err(Self::Err::StringEmpty),
                _ => Err(Self::Err::UndefinedKeyword),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum CacheOut<V> {
    None,
    Present(V),
    NotInserted(V),
}
impl<V> CacheOut<V> {
    #[inline(always)]
    pub fn to_option(self) -> Option<V> {
        match self {
            Self::None => None,
            Self::Present(v) | Self::NotInserted(v) => Some(v),
        }
    }
}

#[derive(Debug)]
pub struct Cache<K, V> {
    map: HashMap<K, V>,
    max_items: usize,
    size_limit: usize,
    inserts: usize,
}
impl<K, V> Cache<K, V> {
    #[inline(always)]
    fn _new(max_items: usize, size_limit: usize) -> Self {
        Self {
            map: HashMap::new(),
            max_items,
            size_limit,
            inserts: 0,
        }
    }
    #[inline(always)]
    pub fn new() -> Self {
        Self::_new(1024, 4 * 1024 * 1024) // 4MiB
    }
    #[inline(always)]
    pub fn with_size_limit(size_limit: usize) -> Self {
        Self::_new(1024, size_limit)
    }
    #[inline(always)]
    pub fn clear(&mut self) {
        self.map.clear()
    }
}
impl<K: Eq + Hash, V> Cache<K, V> {
    pub fn get<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.map.get(key)
    }
    pub fn contains<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.map.contains_key(key)
    }
    pub fn remove<Q: ?Sized + Hash + Eq>(&mut self, key: &Q) -> CacheOut<V>
    where
        K: Borrow<Q>,
    {
        match self.map.remove(key) {
            Some(item) => CacheOut::Present(item),
            None => CacheOut::None,
        }
    }
}
impl<K: Eq + Hash, V> Cache<K, V> {
    pub fn discard_one(&mut self) {
        let pseudo_random = {
            use std::hash::Hasher;
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            hasher.write_usize(self.inserts);
            hasher.finish()
        };

        // I don't care about normalized distribution
        // also, it's safe to cast, modulo logic...
        let position = (pseudo_random % self.map.len() as u64) as usize;

        let mut current_position = 0;
        self.map.retain(|_, _| {
            let result = current_position != position;
            current_position += 1;
            result
        });
    }
}
impl<K: Eq + Hash> Cache<K, CompressedResponse> {
    pub fn cache(&mut self, key: K, response: CompressedResponse) -> CacheOut<CompressedResponse> {
        if response.identity.body().len() >= self.size_limit {
            return CacheOut::NotInserted(response);
        }
        self.inserts += 1;
        if self.map.len() >= self.max_items {
            self.discard_one();
        }
        match self.map.insert(key, response) {
            Some(item) => CacheOut::Present(item),
            None => CacheOut::None,
        }
    }
}
impl<K: Eq + Hash> Cache<K, Bytes> {
    pub fn cache(&mut self, key: K, contents: Bytes) -> CacheOut<Bytes> {
        if contents.len() >= self.size_limit {
            return CacheOut::NotInserted(contents);
        }
        self.inserts += 1;
        if self.map.len() >= self.max_items {
            self.discard_one();
        }
        match self.map.insert(key, contents) {
            Some(item) => CacheOut::Present(item),
            None => CacheOut::None,
        }
    }
}

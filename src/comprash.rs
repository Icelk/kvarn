use crate::prelude::*;
use bytes::{BufMut, Bytes};
use http::Response;
use std::{borrow::Borrow, hash::Hash, rc::Rc, sync::Arc};
use tokio::sync::Mutex;

pub type CachedResponse = Arc<Response<CachedCompression>>;
pub type FileCache = Mutex<Cache<PathBuf, Vec<u8>>>;
pub type ResponseCache = Mutex<Cache<UriKey<'static>, CachedCompression>>;

#[derive(Debug, PartialOrd, Ord, Clone)]
pub enum UriKey<'a> {
    PathBorrow(&'a str),
    PathOwned(String),
    PathQueryBorrow((&'a str, Option<&'a str>)),
    PathQueryOwned((String, Option<String>)),
}
impl PartialEq for UriKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        macro_rules! cmp_path {
            ( $e:expr ) => {
                match other {
                    Self::PathBorrow(p2) => $e == p2,
                    Self::PathOwned(p2) => $e == p2,
                    _ => false,
                }
            };
        }
        match self {
            Self::PathBorrow(p1) => cmp_path!(p1),
            Self::PathOwned(p1) => cmp_path!(p1),
            Self::PathQueryBorrow((p1, p2)) => match other {
                Self::PathQueryBorrow((p3, p4)) => p1 == p3 && p2 == p4,
                Self::PathQueryOwned((p3, p4)) => {
                    p1 == p3 && p2 == &p4.as_ref().map(|s| s.as_str())
                }
                _ => false,
            },
            Self::PathQueryOwned((p1, p2)) => match other {
                Self::PathQueryBorrow((p3, p4)) => {
                    p1 == p3 && &p2.as_ref().map(|s| s.as_str()) == p4
                }
                Self::PathQueryOwned((p3, p4)) => p1 == p3 && p2 == p4,
                _ => false,
            },
        }
    }
}
impl Eq for UriKey<'_> {}
impl Hash for UriKey<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::PathBorrow(p1) => p1.hash(state),
            Self::PathOwned(p1) => p1.as_str().hash(state),
            Self::PathQueryBorrow((p1, p2)) => {
                p1.hash(state);
                p2.map(|p| p.hash(state));
            }
            Self::PathQueryOwned((p1, p2)) => {
                p1.as_str().hash(state);
                p2.as_ref().map(|p| p.as_str().hash(state));
            }
        }
    }
}
impl<'a> From<&'a http::Uri> for UriKey<'a> {
    fn from(uri: &'a http::Uri) -> Self {
        match uri.query() {
            Some(query) => Self::PathQueryBorrow((uri.path(), Some(query))),
            None => Self::PathBorrow(uri.path()),
        }
    }
}
// impl From<http::Uri> for UriKey<'static> {
//     fn from(uri: http::Uri) -> Self {
//         match uri.query() {
//             Some(query) => Self::PathQueryBorrow((uri.path(), Some(query))),
//             None => Self::PathBorrow(uri.path()),
//         }
//     }
// }
// for when no compression is compiled in
#[allow(dead_code)]
#[derive(Debug)]
pub struct CachedCompression {
    identity: http::Response<Bytes>,
    gzip: Option<http::Response<Bytes>>,
    br: Option<http::Response<Bytes>>,

    compress: CompressPreference,
    client_cache: ClientCachePreference,
}
impl CachedCompression {
    pub(crate) fn new(
        identity: http::Response<Bytes>,
        compress: CompressPreference,
        client_cache: ClientCachePreference,
    ) -> Self {
        Self {
            identity,
            gzip: None,
            br: None,

            compress,
            client_cache,
        }
    }
    pub fn get_identity(&self) -> &http::Response<Bytes> {
        &self.identity
    }

    pub fn get_preferred(&self) -> &http::Response<Bytes> {
        match self.compress {
            CompressPreference::None => &self.identity,
            CompressPreference::Full => {
                #[cfg(all(feature = "gzip", feature = "br"))]
                match self.br.is_some() && self.gzip.is_none() {
                    true => return self.br.as_ref().unwrap(),
                    false => self.get_gzip(),
                }
                #[cfg(all(feature = "gzip", not(feature = "br")))]
                {
                    self.get_gzip()
                }
                #[cfg(all(feature = "br", not(feature = "gzip")))]
                {
                    self.get_br()
                }
                #[cfg(not(any(feature = "gzip", feature = "br")))]
                {
                    &self.identity
                }
            }
        }
    }

    #[allow(dead_code)]
    fn clone_response_set_compression(
        response: &http::Response<Bytes>,
        new_data: Bytes,
        compression: http::HeaderValue,
    ) -> http::Response<Bytes> {
        let mut builder = http::Response::builder()
            .version(response.version())
            .status(response.status());
        let mut map = response.headers().clone();
        utility::replace_header(&mut map, "content-encoding", compression);
        utility::replace_header(
            &mut map,
            "content-length",
            // unwrap is ok, we know the formatted bytes from a number are (0-9) or `.`
            http::HeaderValue::from_str(new_data.len().to_string().as_str()).unwrap(),
        );
        *builder.headers_mut().unwrap() = map;
        builder.body(new_data).unwrap()
    }

    #[cfg(feature = "gzip")]
    /// Gets the gzip compressed version of [`CachedCompression::get_identity()`]
    pub fn get_gzip(&self) -> &http::Response<Bytes> {
        if self.gzip.is_none() {
            use std::io::Write;
            let bytes = self.identity.body().as_ref();

            let mut buffer = bytes::BytesMut::with_capacity(bytes.len() / 2 + 64).writer();
            // unsafe { buffer.set_len(buffer.capacity()) };

            let mut c = flate2::write::GzEncoder::new(&mut buffer, flate2::Compression::fast());
            c.write(bytes).expect("Failed to compress using gzip!");
            c.finish().expect("Failed to compress using gzip!");

            let buffer = buffer.into_inner();
            let buffer = buffer.freeze();

            let response = Self::clone_response_set_compression(
                self.get_identity(),
                buffer,
                http::HeaderValue::from_static("gzip"),
            );

            if self.gzip.is_none() {
                // maybe shooting myself in the foot...
                // but should be OK, since we only set it once, otherwise it's None.
                unsafe {
                    (&mut *{ &self.gzip as *const _ as *mut Option<http::Response<Bytes>> })
                        .replace(response)
                };
            }
        }
        self.gzip.as_ref().unwrap()
    }
    #[cfg(feature = "br")]
    /// Gets the Brotli compressed version of [`CachedCompression::get_identity()`]
    pub fn get_br(&self) -> &http::Response<Bytes> {
        if self.br.is_none() {
            use std::io::Write;
            let bytes = self.identity.body().as_ref();

            let mut buffer = bytes::BytesMut::with_capacity(bytes.len() / 2 + 64).writer();

            let mut c = brotli::CompressorWriter::new(&mut buffer, 4096, 8, 21);
            c.write(bytes).expect("Failed to compress using Brotli!");
            c.flush().expect("Failed to compress using Brotli!");
            c.into_inner();

            let buffer = buffer.into_inner();
            let buffer = buffer.freeze();

            let response = Self::clone_response_set_compression(
                self.get_identity(),
                buffer,
                http::HeaderValue::from_static("br"),
            );

            if self.br.is_none() {
                // maybe shooting myself in the foot...
                // but should be OK, since we only set it once, otherwise it's None.
                unsafe {
                    (&mut *{ &self.br as *const _ as *mut Option<http::Response<Bytes>> })
                        .replace(response)
                };
            }
        }
        self.br.as_ref().unwrap()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum CompressPreference {
    /// Will not auto-compress response body
    None,
    /// Will automatically compress and send compressed versions of the response
    Full,
}
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum ServerCachePreference {
    /// Will not cache response
    None,
    /// Will cache response with query
    QueryMatters,
    /// Query does not matter and will be discarded
    Full,
}
impl ServerCachePreference {
    pub fn cache(&self) -> bool {
        match self {
            Self::None => false,
            Self::QueryMatters | Self::Full => true,
        }
    }
    pub fn query_matters(&self) -> bool {
        match self {
            Self::None | Self::Full => false,
            Self::QueryMatters => true,
        }
    }
}
/// Automatically add `cache-control` header to response
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum ClientCachePreference {
    /// Will not cache on client
    None,
    /// A two-minute cache lifetime
    Changing,
    /// Will cache for 1 year
    Full,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum CacheOut<V> {
    None,
    Present(V),
    NotInserted(V),
}

#[derive(Debug)]
pub struct Cache<K, V> {
    map: HashMap<K, V>,
    max_items: usize,
    size_limit: usize,
    inserts: usize,
}
impl<K, V> Cache<K, V> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            max_items: 1024,
            size_limit: 4 * 1024 * 1024, // 4MiB
            inserts: 0,
        }
    }
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
impl<K: Eq + Hash + Clone, V> Cache<K, V> {
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
        // unwrap ok; position is within bounds, did a modulo
        let key = self.map.keys().nth(position).unwrap();
        self.map.remove(key);
    }
}
impl<K: Eq + Hash + Clone> Cache<K, CachedCompression> {
    pub fn cache(
        &mut self,
        key: K,
        identity: http::Response<Bytes>,
        compress: CompressPreference,
        client_cache: ClientCachePreference,
    ) -> CacheOut<CachedCompression> {
        let item = CachedCompression::new(identity, compress, client_cache);

        if identity.body().len() >= self.size_limit {
            return CacheOut::NotInserted(item);
        }
        self.inserts += 1;
        if self.map.len() >= self.max_items {
            self.discard_one();
        }
        match self.map.insert(key, item) {
            Some(item) => CacheOut::Present(item),
            None => CacheOut::None,
        }
    }
}
impl<K: Eq + Hash + Clone> Cache<K, Vec<u8>> {
    pub fn cache(&mut self, key: K, contents: Vec<u8>) -> CacheOut<Vec<u8>> {
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

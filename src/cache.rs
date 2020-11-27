use crate::prelude::{fs::*, threading::*, *};
use std::mem;
use std::{borrow::Borrow, hash::Hash};

/// A response in byte form to query head or only body. Can be used when a if a buffer contains HTTP headers is unknown.
///
/// Variants `Body` and `BorrowedBody` doesn't contain a head, a head in `Merged` is optional.
pub enum ByteResponse {
    Merged(Vec<u8>, usize, bool),
    Both(Vec<u8>, Vec<u8>, bool),
    Body(Vec<u8>),
    BorrowedBody(Arc<Vec<u8>>),
}
impl ByteResponse {
    #[inline]
    pub fn with_header(bytes: Vec<u8>) -> Self {
        let start = Self::get_start(&bytes[..]);
        Self::Merged(bytes, start, false)
    }
    #[inline]
    pub fn with_partial_header(bytes: Vec<u8>) -> Self {
        let start = Self::get_start(&bytes[..]);
        Self::Merged(bytes, start, true)
    }
    #[inline]
    pub fn without_header(body: Vec<u8>) -> Self {
        Self::Body(body)
    }
    #[inline]
    pub fn without_header_shared(shared_body: Arc<Vec<u8>>) -> Self {
        Self::BorrowedBody(shared_body)
    }

    fn get_start(bytes: &[u8]) -> usize {
        let mut newlines_in_row = 0;
        for (position, byte) in bytes.iter().enumerate() {
            match *byte {
                LF | CR => newlines_in_row += 1,
                _ => newlines_in_row = 0,
            }
            if newlines_in_row == 4 {
                return position + 1;
            }
        }
        0
    }
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Merged(vec, _, _) => vec.len(),
            Self::Both(head, body, _) => head.len() + body.len(),
            Self::Body(body) => body.len(),
            Self::BorrowedBody(borrow) => borrow.len(),
        }
    }

    #[inline]
    pub fn write_all(&self, writer: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Merged(vec, _, _) => writer.write_all(&vec[..]),
            Self::Both(head, body, _) => {
                writer.write_all(&head[..])?;
                writer.write_all(&body[..])
            }
            Self::Body(body) => writer.write_all(&body[..]),
            Self::BorrowedBody(borrow) => writer.write_all(&borrow[..]),
        }
    }
    pub fn write_as_method(&self, writer: &mut dyn Write, method: &http::Method) -> io::Result<()> {
        match method {
            &http::Method::HEAD => {
                if let Some(head) = self.get_head() {
                    writer.write_all(head)
                } else {
                    Ok(())
                }
            }
            _ => match self {
                Self::Merged(vec, _, _) => writer.write_all(&vec[..]),
                Self::Both(head, body, _) => {
                    writer.write_all(&head[..])?;
                    writer.write_all(&body[..])
                }
                Self::Body(body) => writer.write_all(&body[..]),
                Self::BorrowedBody(borrow) => writer.write_all(&borrow[..]),
            },
        }
    }

    #[inline]
    pub fn get_head(&self) -> Option<&[u8]> {
        match self {
            Self::Merged(vec, start, _) if *start > 0 => Some(&vec[..*start]),
            Self::Both(head, _, _) => Some(&head[..]),
            _ => None,
        }
    }
    #[inline]
    pub fn into_head(self) -> Vec<u8> {
        match self {
            Self::Merged(mut vec, start, _) if start > 0 => {
                vec.truncate(start);
                vec
            }
            Self::Both(head, _, _) => head,
            _ => Vec::new(),
        }
    }
    #[inline]
    pub fn get_body(&self) -> &[u8] {
        match self {
            Self::Merged(vec, start, _) => &vec[*start..],
            Self::Both(_, body, _) => &body[..],
            Self::Body(body) => &body[..],
            Self::BorrowedBody(borrow) => &borrow[..],
        }
    }
    #[inline]
    pub fn into_body(self) -> Vec<u8> {
        match self {
            Self::Merged(vec, start, _) => utility::into_last(vec, start),
            Self::Both(_, body, _) => body,
            Self::Body(body) => body,
            Self::BorrowedBody(borrowed) => (*borrowed).clone(),
        }
    }
    #[inline]
    pub fn get_first_vec(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Merged(vec, _, _) => vec,
            Self::Both(head, _, _) => head,
            Self::Body(body) => body,
            Self::BorrowedBody(borrowed) => {
                *self = Self::Body((**borrowed).clone());
                match self {
                    Self::Body(vec) => vec,
                    _ => unreachable!(),
                }
            }
        }
    }
    #[inline]
    pub fn body_from(&self, from: usize) -> &[u8] {
        &self.get_body()[from..]
    }
    #[inline]
    pub fn body_to(&self, to: usize) -> &[u8] {
        &self.get_body()[..to]
    }
}
impl fmt::Debug for ByteResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Merged(_, starts_at, _) => {
                write!(f, "ByteResponse::Merged, starts at {}", starts_at)
            }
            Self::Both(_, _, _) => write!(f, "ByteResponse::Both"),
            Self::Body(_) => write!(f, "ByteResponse::Body"),
            Self::BorrowedBody(_) => write!(f, "ByteResponse::BorrowedBody"),
        }
    }
}

#[derive(Debug)]
pub enum ParseCachedErr {
    StringEmpty,
    UndefinedKeyword,
    ContainsSpace,
    FailedToParse,
}
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Cached {
    Dynamic,
    Changing,
    PerQuery,
    Static,
}
impl Cached {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        str::from_utf8(bytes).ok().and_then(|s| s.parse().ok())
    }

    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Cached::Dynamic => b"Cache-Control: no-store\r\n",
            Cached::Changing => b"Cache-Control: max-age=120\r\n",
            Cached::Static | Cached::PerQuery => {
                b"Cache-Control: public, max-age=604800, immutable\r\n"
            }
        }
    }

    pub fn do_internal_cache(&self) -> bool {
        match self {
            Self::Dynamic | Self::Changing => false,
            Self::Static | Self::PerQuery => true,
        }
    }
    pub fn query_matters(&self) -> bool {
        match self {
            Self::Dynamic | Self::PerQuery => true,
            Self::Static | Self::Changing => false,
        }
    }
    pub fn cached_without_query(&self) -> bool {
        match self {
            Self::Dynamic | Self::PerQuery | Self::Changing => false,
            Self::Static => true,
        }
    }
}
impl str::FromStr for Cached {
    type Err = ParseCachedErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(' ') {
            Err(Self::Err::ContainsSpace)
        } else {
            match s.to_ascii_lowercase().as_str() {
                "false" | "no-cache" | "dynamic" => Ok(Self::Dynamic),
                "changing" | "may-change" => Ok(Self::Changing),
                "per-query" | "query" => Ok(Self::PerQuery),
                "true" | "static" | "immutable" => Ok(Self::Static),
                "" => Err(Self::Err::StringEmpty),
                _ => Err(Self::Err::UndefinedKeyword),
            }
        }
    }
}

#[derive(Debug)]
pub struct VaryMaster {
    vary_headers: Vec<&'static str>,
    data: Mutex<Vec<(Vec<http::HeaderValue>, Arc<ByteResponse>)>>,
}

/// A enum to contain data about the cached data. Can either be `Data`, when no `Vary:` header is present, or `Vary` if it must contain several values.
#[derive(Debug)]
pub enum CacheType {
    Data(Arc<ByteResponse>),
    Vary(VaryMaster),
}
impl CacheType {
    pub fn with_data(data: ByteResponse) -> Self {
        Self::Data(Arc::new(data))
    }
    pub fn vary(headers: Vec<&'static str>) -> Self {
        Self::Vary(VaryMaster {
            vary_headers: headers,
            data: Mutex::new(Vec::with_capacity(8)),
        })
    }
    pub fn vary_with_data(
        structure: Vec<&'static str>,
        data: Arc<ByteResponse>,
        headers: Vec<http::HeaderValue>,
    ) -> Self {
        Self::Vary(VaryMaster {
            vary_headers: structure,
            data: Mutex::new(vec![(headers, data)]),
        })
    }

    pub fn resolve(&self, headers: &http::HeaderMap) -> Option<Arc<ByteResponse>> {
        match self {
            Self::Data(data) => Some(Arc::clone(data)),
            Self::Vary(vary) => {
                let mut results = Vec::with_capacity(8);
                let mut iter = vary.vary_headers.iter().enumerate();

                let all_data = vary.data.lock().unwrap();
                {
                    let (position, name) = iter.next().unwrap();

                    let required_data = {
                        let mut data = headers
                            .get(*name)
                            .and_then(|header| header.to_str().ok())
                            .map(|header| parse::format_list_header(header))
                            .unwrap_or(Vec::new());

                        // Push additional option to data if they should be available!
                        if name.to_ascii_lowercase() == "accept-encoding" {
                            if data.iter().find(|data| data.value == "identity").is_none() {
                                data.push(parse::ValueQualitySet {
                                    value: "identity",
                                    quality: 0.5,
                                });
                            }
                        }
                        data
                    };

                    // Match with all cached data!
                    for data in all_data.iter() {
                        // If nothing required
                        if required_data.is_empty() {
                            // Push!
                            results.push(data);
                        } else {
                            'match_supported: for supported_header in required_data.iter() {
                                // If any header contains star or matches required!
                                if data.0.get(position).unwrap() == supported_header.value
                                    || supported_header.value.starts_with('*')
                                {
                                    results.push(data);
                                    break 'match_supported;
                                }
                            }
                        }
                    }
                }
                for (position, header_to_compare) in iter {
                    results.retain(|&current| {
                        let required_data = {
                            headers.get(*header_to_compare);
                            Vec::<&str>::new()
                        };

                        if required_data.is_empty() {
                            // Keep!
                            return true;
                        } else {
                            for supported_header in required_data.iter() {
                                // If any header contains star or matches required!
                                if current.0.get(position).unwrap() == supported_header
                                    || supported_header.starts_with('*')
                                {
                                    return true;
                                }
                            }
                        }
                        false
                    })
                }

                results.get(0).map(|result| Arc::clone(&result.1))
            }
        }
    }

    pub fn add_variant(
        &self,
        response: Arc<ByteResponse>,
        headers: Vec<http::HeaderValue>,
        structure: &[&'static str],
    ) -> Result<(), Arc<ByteResponse>> {
        match self {
            // So data (header) structure is identical
            Self::Vary(vary) if structure == vary.vary_headers => {
                let mut data = vary.data.lock().unwrap();
                data.push((headers, response));
                Ok(())
            }
            _ => Err(response),
        }
    }
}
impl<K: Clone + Hash + Eq> Cache<K, CacheType> {
    pub fn resolve<Q: ?Sized + Hash + Eq>(
        &self,
        key: &Q,
        headers: &http::HeaderMap,
    ) -> Option<Arc<ByteResponse>>
    where
        K: Borrow<Q>,
    {
        let data = self.get(key)?;
        data.resolve(headers)
    }
    pub fn add_variant(
        &mut self,
        key: K,
        response: ByteResponse,
        headers: Vec<http::HeaderValue>,
        structure: &[&'static str],
    ) -> Result<(), ()> {
        match self.get(&key) {
            Some(varied) => {
                if response.size() > self.size_limit {
                    return Err(());
                }
                varied
                    .add_variant(Arc::new(response), headers, structure)
                    .or(Err(()))
            }
            None => self
                .cache(
                    key,
                    Arc::new(CacheType::vary_with_data(
                        structure.to_vec(),
                        Arc::new(response),
                        headers,
                    )),
                )
                .or(Err(())),
        }
    }
}

pub mod types {
    use super::*;

    pub type FsCacheInner = Cache<PathBuf, Vec<u8>>;
    pub type FsCache = Arc<Mutex<FsCacheInner>>;
    pub type ResponseCacheInner = Cache<http::Uri, CacheType>;
    pub type ResponseCache = Arc<Mutex<ResponseCacheInner>>;
    pub type TemplateCacheInner = Cache<String, HashMap<Arc<String>, Arc<Vec<u8>>>>;
    pub type TemplateCache = Arc<Mutex<TemplateCacheInner>>;
    pub type Bindings = Arc<bindings::FunctionBindings>;
}

pub trait Size {
    fn size(&self) -> usize;
}
impl<T> Size for Vec<T> {
    fn size(&self) -> usize {
        self.len() * mem::size_of::<T>()
    }
}
impl<T> Size for dyn Borrow<Vec<T>> {
    fn size(&self) -> usize {
        self.borrow().len() * mem::size_of::<T>()
    }
}
impl<K, V> Size for HashMap<K, V> {
    fn size(&self) -> usize {
        self.len() * mem::size_of::<V>()
    }
}
impl<K, V> Size for dyn Borrow<HashMap<K, V>> {
    fn size(&self) -> usize {
        self.borrow().len() * mem::size_of::<V>()
    }
}
impl Size for ByteResponse {
    fn size(&self) -> usize {
        self.len()
    }
}
impl Size for CacheType {
    fn size(&self) -> usize {
        match self {
            Self::Vary(vary) => {
                // for data in  {}
                vary.data
                    .lock()
                    .unwrap()
                    .iter()
                    .fold(0, |acc, data| acc + data.1.size())
            }
            Self::Data(data) => data.size(),
        }
    }
}

pub struct Cache<K, V> {
    map: HashMap<K, Arc<V>>,
    max_items: usize,
    size_limit: usize,
}
impl<K: Eq + Hash + Clone, V: Size> Cache<K, V> {
    #[inline]
    pub fn cache(&mut self, key: K, value: Arc<V>) -> Result<(), Arc<V>> {
        if value.size() > self.size_limit {
            return Err(value);
        }
        if self.map.len() >= self.max_items {
            // Reduce number of items!
            if let Some(last) = self.map.iter().next().map(|value| value.0.clone()) {
                self.map.remove(&last);
            }
        }
        self.map.insert(key, value);
        Ok(())
    }
}
impl<K: Eq + Hash + Clone, V> Cache<K, V> {
    pub fn new() -> Self {
        Cache {
            map: HashMap::with_capacity(64),
            max_items: 1024,
            size_limit: 4194304, // 4MiB
        }
    }
    pub fn with_max(max_items: usize) -> Self {
        assert!(max_items > 1);
        Cache {
            map: HashMap::with_capacity(max_items / 16 + 1),
            max_items,
            size_limit: 4194304, // 4MiB
        }
    }
    pub fn with_max_size(max_size: usize) -> Self {
        assert!(max_size > 1024);
        Cache {
            map: HashMap::with_capacity(64),
            max_items: 1024,
            size_limit: max_size,
        }
    }
    pub fn with_max_and_size(max_items: usize, size_limit: usize) -> Self {
        assert!(max_items > 1);
        assert!(size_limit >= 1024);

        Cache {
            map: HashMap::with_capacity(max_items / 16 + 1),
            max_items,
            size_limit,
        }
    }
    pub fn get<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> Option<Arc<V>>
    where
        K: Borrow<Q>,
    {
        self.map.get(key).map(|value| Arc::clone(value))
    }
    #[inline]
    pub fn cached(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }
    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<Arc<V>> {
        self.map.remove(key)
    }
    #[inline]
    pub fn clear(&mut self) {
        self.map.clear()
    }
}
impl<K: fmt::Debug, V> fmt::Debug for Cache<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cache {{ map: ")?;
        f.debug_map()
            .entries(self.map.iter().map(|(key, _)| (key, "bytes")))
            .finish()?;
        write!(
            f,
            ", max_items: {}, size_limit: {} }}",
            self.max_items, self.size_limit
        )
    }
}

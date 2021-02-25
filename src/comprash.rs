use crate::prelude::*;
use bytes::Bytes;
use http::Response;
use std::{borrow::Borrow, hash::Hash};
use tokio::sync::{Mutex, MutexGuard};

pub type CachedResponse = Arc<Response<CachedCompression>>;

pub struct Guard<'a, T> {
    guard: MutexGuard<'a, Option<T>>,
}
impl<'a, T> Guard<'a, T> {
    /// Will panic in runtime if the input `guard`s option is not `Some`
    // If no compression features are used.
    #[allow(dead_code)]
    fn new(guard: MutexGuard<'a, Option<T>>) -> Self {
        Self { guard }
    }
}
impl<T> std::ops::Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().unwrap()
    }
}

impl<T> std::ops::DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.as_mut().unwrap()
    }
}

// #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct CachedCompression {
    identity: http::Response<Bytes>,
    gzip: Mutex<Option<http::Response<Bytes>>>,
    br: Mutex<Option<http::Response<Bytes>>>,
}
impl CachedCompression {
    pub(crate) fn new(identity: http::Response<Bytes>) -> Self {
        Self {
            identity,
            gzip: Mutex::new(None),
            br: Mutex::new(None),
        }
    }
    pub fn get_identity(&self) -> &http::Response<Bytes> {
        &self.identity
    }

    fn clone_response_set_compression(
        response: &http::Response<Bytes>,
        new_data: Bytes,
        compression: http::HeaderValue,
    ) -> http::Response<Bytes> {
        let mut builder = http::Response::builder()
            .version(response.version())
            .status(response.status());
        let mut map = response.headers().clone();
        // http::header::OccupiedEntry::remove_entry_mult(self)
        // http::header::Entry::
        match map.entry("content-encoding") {
            http::header::Entry::Vacant(slot) => {
                slot.insert(compression);
            }
            http::header::Entry::Occupied(slot) => {
                slot.remove_entry_mult();
                slot.insert(compression);
            }
        }

        *builder.headers_mut().unwrap() = map;
        builder.body(new_data).unwrap()
    }

    #[cfg(features = "gzip")]
    /// Gets the gzip compressed version of [`CachedCompression::get_identity()`]
    pub async fn get_gzip(&mut self) -> Guard<'_, http::Response<Bytes>> {
        let mut lock = self.gzip.lock().await;
        if lock.is_none() {
            use std::io::Write;
            let bytes = self.identity.body().as_ref();

            let mut buffer = bytes::BytesMut::with_capacity(bytes.len() / 2 + 64);

            let mut c = flate2::write::GzEncoder::new(buffer.as_mut(), flate2::Compression::fast());
            c.write(bytes).expect("Failed to compress using gzip!");
            c.finish().expect("Failed to compress using gzip!");
            let buffer = buffer.freeze();

            let response = Self::clone_response_set_compression(
                self.get_identity(),
                buffer,
                http::HeaderValue::from_static("gzip"),
            );

            *lock = Some(response);
        }
        Guard::new(lock)
    }
    #[cfg(features = "br")]
    /// Gets the Brotli compressed version of [`CachedCompression::get_identity()`]
    pub async fn get_br(&mut self) -> Guard<'_, http::Response<Bytes>> {
        let mut lock = self.gzip.lock().await;
        if lock.is_none() {
            use std::io::Write;
            let bytes = self.identity.body().as_ref();

            let mut buffer = bytes::BytesMut::with_capacity(bytes.len() / 2 + 64);

            let mut c = brotli::CompressorWriter::new(buffer.as_mut(), 4096, 8, 21);
            c.write(bytes).expect("Failed to compress using Brotli!");
            c.flush().expect("Failed to compress using Brotli!");
            c.into_inner();
            let buffer = buffer.freeze();

            let response = Self::clone_response_set_compression(
                self.get_identity(),
                buffer,
                http::HeaderValue::from_static("gzip"),
            );

            *lock = Some(response);
        }
        Guard::new(lock)
    }
}
impl Debug for CachedCompression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn get_status(mutex: &Mutex<Option<Bytes>>) -> &'static str {
            match mutex.try_lock() {
                Err(_) => "[Busy]",
                Ok(o) => match o.as_ref() {
                    Some(_) => "Some",
                    None => "None",
                },
            }
        }

        const RESPONSE: &str = "http::Response<Bytes>";
        write!(
            f,
            "CachedCompression {{ identity: {}, gzip: {}({}), br: {}({})",
            RESPONSE,
            get_status(&self.gzip),
            RESPONSE,
            get_status(&self.br),
            RESPONSE
        )
    }
}

#[derive(Debug)]
pub struct Cache<K> {
    map: HashMap<K, CachedCompression>,
}
impl<K> Cache<K> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    pub fn clear(&mut self) {
        self.map.clear()
    }
}
impl<K: Eq + Hash> Cache<K> {
    pub fn get<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> Option<&CachedCompression>
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
    pub fn remove<Q: ?Sized + Hash + Eq>(&mut self, key: &Q) -> Option<CachedCompression>
    where
        K: Borrow<Q>,
    {
        self.map.remove(key)
    }
    pub fn cache(&mut self, key: K, value: http::Response<Bytes>) -> Option<CachedCompression> {
        self.map.insert(key, CachedCompression::new(value))
    }
}

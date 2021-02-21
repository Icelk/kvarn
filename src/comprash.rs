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

pub struct CachedCompression {
    identity: Bytes,
    gzip: Mutex<Option<Bytes>>,
    br: Mutex<Option<Bytes>>,
}
impl CachedCompression {
    pub(crate) fn new(identity: Bytes) -> Self {
        Self {
            identity,
            gzip: Mutex::new(None),
            br: Mutex::new(None),
        }
    }
    pub fn get_identity(&self) -> &Bytes {
        &self.identity
    }
    #[cfg(features = "gzip")]
    /// Gets the gzip compressed version of [`CachedCompression::get_identity()`]
    pub async fn get_gzip(&mut self) -> Guard<'_, Bytes> {
        let mut lock = self.gzip.lock().await;
        if lock.is_none() {
            use std::io::Write;
            let bytes = self.identity.as_ref();

            let mut buffer = bytes::BytesMut::with_capacity(bytes.len() / 2 + 64);

            let mut c = flate2::write::GzEncoder::new(buffer.as_mut(), flate2::Compression::fast());
            c.write(bytes).expect("Failed to compress using gzip!");
            c.finish().expect("Failed to compress using gzip!");
            let buffer = buffer.freeze();
            *lock = Some(buffer);
        }
        Guard::new(lock)
    }
    #[cfg(features = "br")]
    /// Gets the Brotli compressed version of [`CachedCompression::get_identity()`]
    pub async fn get_br(&mut self) -> Guard<'_, Bytes> {
        let mut lock = self.gzip.lock().await;
        if lock.is_none() {
            use std::io::Write;
            let bytes = self.identity.as_ref();

            let mut buffer = bytes::BytesMut::with_capacity(bytes.len() / 2 + 64);

            let mut c = brotli::CompressorWriter::new(buffer.as_mut(), 4096, 8, 21);
            c.write(bytes).expect("Failed to compress using Brotli!");
            c.flush().expect("Failed to compress using Brotli!");
            c.into_inner();
            let buffer = buffer.freeze();
            *lock = Some(buffer);
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
    pub fn get<Q: ?Sized + Hash + Eq>(&mut self, key: &Q) -> Option<&mut CachedCompression>
    where
        K: Borrow<Q>,
    {
        self.map.get_mut(key)
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

    pub fn cache(&mut self, key: K, value: Bytes) -> Option<CachedCompression> {
        self.map.insert(key, CachedCompression::new(value))
    }
}

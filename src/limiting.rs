//! Limits traffic from a ip address to partially mitigate attacks.
//!
//! Kvarn's limiting is smart; when a client first makes to many requests,
//! a hardcoded `429 Too Many Requests` is sent back (taking virtually null resources).
//! It the spam continues, the current connection and all future streams are blocked.
//!
//! The thresholds are configurable and have sensible defaults.
//!
//! After `reset_time` is elapsed, all stored request counts are cleared.
//! Longer `reset_time`s and higher `max_requests` can be less forgiving for clients,
//! but safer for the server, and vise versa.

use crate::prelude::*;
#[cfg(feature = "limiting")]
use threading::atomic;

/// Get a `429 Too Many Requests` response.
#[cfg(feature = "limiting")]
#[inline]
#[must_use]
pub fn get_too_many_requests() -> Response<Bytes> {
    let body = Bytes::from_static("<html>\
    <head>\
        <title>429 Too Many Requests</title>\
    </head>\
    <body>\
        <center>\
            <h1>429 Too Many Requests</h1>\
            <hr>\
            <p>You have requested resources from this server too many times. <i>Please Enhance Your Calm.</i></p>\
            <p>Try to access this page again in a minute. If this error persists, please contact the website administrator.</p>\
        </center>\
    </body>\
</html>".as_bytes());

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(
            "content-type",
            HeaderValue::from_static("text/html; charset=utf-8"),
        )
        .header("content-length", body.len().to_string())
        .header("content-encoding", "identity")
        .body(body)
        .unwrap()
}

/// The strength of limiting.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum LimitStrength {
    /// Request should continue as normal.
    Passed,
    /// Send a [`get_too_many_requests`] response.
    Send,
    /// Drop the connection immediately.
    Drop,
}

/// Data used to limit requests.
///
/// One instance of this is used per `Listener`.
/// It counts using a [`atomic::AtomicUsize`] and keeps the count of requests per
/// [`IpAddr`] in a [`Mutex`], for fast access times and cheap cloning.
#[cfg(feature = "limiting")]
#[derive(Debug, Clone)]
#[must_use]
pub struct LimitManager {
    connection_map_and_time: Arc<Mutex<(HashMap<IpAddr, usize>, std::time::Instant)>>,
    max_requests: usize,
    check_every: usize,
    reset_seconds: u64,

    iteration: Arc<atomic::AtomicUsize>,
}
#[cfg(feature = "limiting")]
impl LimitManager {
    /// Creates a new manager.
    ///
    /// Use [`LimitManager::default`] for sane defaults.
    ///
    /// The number of allowed requests per reset is `max_requests * check_every`.
    /// After `reset_seconds`, all data is cleared.
    pub fn new(max_requests: usize, check_every: usize, reset_seconds: u64) -> Self {
        Self {
            connection_map_and_time: Arc::new(Mutex::new((HashMap::new(), std::time::Instant::now()))),
            max_requests,
            check_every,
            reset_seconds,

            iteration: Arc::new(atomic::AtomicUsize::new(0)),
        }
    }
    /// Registers a request from `addr`.
    ///
    /// This is called twice, once when a new connection is established, and once when a new request is made.
    ///
    /// Does not always lock the mutex, only once per `check_every`.
    /// It only [`atomic::AtomicUsize::fetch_add`] else, with [`atomic::Ordering::Relaxed`].
    /// This is less reliable, but faster. We do not require this to be to be exact.
    pub async fn register(&mut self, addr: IpAddr) -> LimitStrength {
        if self.iteration.fetch_add(1, atomic::Ordering::Relaxed) + 1 < self.check_every {
            LimitStrength::Passed
        } else {
            self.iteration.store(0, atomic::Ordering::Release);
            let mut lock = self.connection_map_and_time.lock().await;
            let (map, time) = &mut *lock;
            if time.elapsed().as_secs() >= self.reset_seconds {
                *time = std::time::Instant::now();
                map.clear();
                LimitStrength::Passed
            } else {
                let requests = *map.entry(addr).and_modify(|count| *count += 1).or_insert(1);
                if requests <= self.max_requests {
                    LimitStrength::Passed
                } else if requests <= self.max_requests * 10 {
                    LimitStrength::Send
                } else {
                    LimitStrength::Drop
                }
            }
        }
    }
}
#[cfg(feature = "limiting")]
impl Default for LimitManager {
    #[inline]
    fn default() -> Self {
        Self::new(10, 10, 10)
    }
}

/// A wrapper for [`LimitManager`].
///
/// This is here to prove a common interface for when the feature `limiting` is disabled.
#[derive(Debug, Clone)]
#[must_use]
pub struct LimitWrapper {
    #[cfg(feature = "limiting")]
    limiter: LimitManager,
}
impl LimitWrapper {
    /// Creates a new [`LimitWrapper`].
    ///
    /// See it for more information.
    #[cfg(feature = "limiting")]
    #[inline]
    pub fn new(max_requests: usize, check_every: usize, reset_seconds: u64) -> Self {
        Self {
            limiter: LimitManager::new(max_requests, check_every, reset_seconds),
        }
    }
    /// Creates a new, empty, [`LimitWrapper`].
    #[cfg(not(feature = "limiting"))]
    #[inline]
    pub fn new(_: usize, _: usize, _: usize) -> Self {
        Self {}
    }
    /// Registers a request from `addr`.
    ///
    /// Always returns [`LimitStrength::Passed`] if the feature `limiting` is disabled.
    #[allow(unused_variables)]
    #[inline]
    pub async fn register(&mut self, addr: IpAddr) -> LimitStrength {
        #[cfg(feature = "limiting")]
        {
            self.limiter.register(addr).await
        }
        #[cfg(not(feature = "limiting"))]
        {
            LimitStrength::Passed
        }
    }
}
impl Default for LimitWrapper {
    #[inline]
    fn default() -> Self {
        Self {
            #[cfg(feature = "limiting")]
            limiter: LimitManager::default(),
        }
    }
}

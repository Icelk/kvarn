//! Limits traffic from a IP address to partially mitigate attacks.
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
use threading::atomic;

/// Get a `429 Too Many Requests` response.
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
pub enum Action {
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
#[derive(Debug, Clone)]
#[must_use]
pub struct Manager {
    connection_map_and_time: Arc<Mutex<(HashMap<IpAddr, usize>, std::time::Instant)>>,
    max_requests: usize,
    check_every: usize,
    reset_seconds: u64,

    iteration: Arc<atomic::AtomicUsize>,
}
impl LimitManager {
    /// Creates a new manager.
    ///
    /// Use [`LimitManager::default`] for sane defaults.
    ///
    /// The number of allowed requests per reset is `max_requests * check_every`.
    /// After `reset_seconds`, all data is cleared.
    ///
    /// As the math implies, increasing `max_requests` and lowering `reset_seconds`
    /// does nothing to the amount of accepted requests.
    /// Though, if you have large `reset_seconds`, it'll take longer
    /// for the limits to clear after the user has reached `max_requests`.
    pub fn new(max_requests: usize, check_every: usize, reset_seconds: u64) -> Self {
        Self {
            connection_map_and_time: Arc::new(Mutex::new((
                HashMap::new(),
                std::time::Instant::now(),
            ))),
            max_requests,
            check_every,
            reset_seconds,

            iteration: Arc::new(atomic::AtomicUsize::new(0)),
        }
    }

    /// Disables limiting of this manager.
    pub fn disable(&mut self) -> &mut Self {
        self.set_check_every(usize::MAX)
    }
    /// Sets the number of calls in between checking the request.
    ///
    /// This is here to not have to check every request.
    pub fn set_check_every(&mut self, check_every: usize) -> &mut Self {
        self.check_every = check_every;
        self
    }
    /// Sets the max requests in the current cycle
    /// (which resets after [`Self::set_reset_seconds`]).
    /// If the amount of requests from a IP address exceeds
    /// `max_requests` in the cycle, the request is denied.
    pub fn set_max_requests(&mut self, max_requests: usize) -> &mut Self {
        self.max_requests = max_requests;
        self
    }
    /// Sets the interval to clear all limits.
    ///
    /// See [`Self::new`] for considerations when making this value large.
    pub fn set_reset_seconds(&mut self, reset_seconds: u64) -> &mut Self {
        self.reset_seconds = reset_seconds;
        self
    }

    /// Registers a request from `addr`.
    ///
    /// This is called twice, once when a new connection is established, and once when a new request is made.
    ///
    /// Does not always lock the [`Mutex`], only once per `check_every`.
    /// It only [`atomic::AtomicUsize::fetch_add`] else, with [`atomic::Ordering::Relaxed`].
    /// This is less reliable, but faster. We do not require this to be to be exact.
    pub async fn register(&self, addr: IpAddr) -> Action {
        if self.check_every == usize::MAX
            || self.iteration.fetch_add(1, atomic::Ordering::Relaxed) + 1 < self.check_every
        {
            Action::Passed
        } else {
            self.iteration.store(0, atomic::Ordering::Release);
            let mut lock = self.connection_map_and_time.lock().await;
            let (map, time) = &mut *lock;
            if time.elapsed().as_secs() >= self.reset_seconds {
                *time = std::time::Instant::now();
                map.clear();
                Action::Passed
            } else {
                let requests = *map.entry(addr).and_modify(|count| *count += 1).or_insert(1);
                if requests <= self.max_requests {
                    Action::Passed
                } else if requests <= self.max_requests * 10 {
                    Action::Send
                } else {
                    Action::Drop
                }
            }
        }
    }
}
impl Default for LimitManager {
    #[inline]
    fn default() -> Self {
        Self::new(10, 10, 10)
    }
}

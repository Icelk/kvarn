use crate::prelude::*;
#[cfg(feature = "limiting")]
use threading::atomic;

#[cfg(feature = "limiting")]
#[inline]
#[must_use]
pub fn get_too_many_requests() -> Response<Bytes> {
    let body = Bytes::from_static(b"<html>\
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
</html>");

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

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum LimitStrength {
    Passed,
    Send,
    Drop,
}

#[cfg(feature = "limiting")]
#[derive(Debug, Clone)]
#[must_use]
pub struct LimitManager {
    connection_map_and_time: Arc<Mutex<(HashMap<IpAddr, usize>, time::Instant)>>,
    max_requests: usize,
    check_every: usize,
    reset_seconds: u64,

    iteration: Arc<atomic::AtomicUsize>,
}
#[cfg(feature = "limiting")]
impl LimitManager {
    pub fn new(max_requests: usize, check_every: usize, reset_seconds: u64) -> Self {
        Self {
            connection_map_and_time: Arc::new(Mutex::new((HashMap::new(), time::Instant::now()))),
            max_requests,
            check_every,
            reset_seconds,

            iteration: Arc::new(atomic::AtomicUsize::new(0)),
        }
    }
    pub async fn register(&mut self, addr: SocketAddr) -> LimitStrength {
        if self.iteration.fetch_add(1, atomic::Ordering::Relaxed) + 1 < self.check_every {
            LimitStrength::Passed
        } else {
            self.iteration.store(0, atomic::Ordering::Release);
            let mut lock = self.connection_map_and_time.lock().await;
            let (map, time) = &mut *lock;
            if time.elapsed().as_secs() >= self.reset_seconds {
                *time = time::Instant::now();
                map.clear();
                LimitStrength::Passed
            } else {
                let requests = *map
                    .entry(addr.ip())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
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

#[derive(Debug, Clone)]
#[must_use]
pub struct LimitWrapper {
    #[cfg(feature = "limiting")]
    pub limiter: LimitManager,
}
impl LimitWrapper {
    #[cfg(feature = "limiting")]
    #[inline]
    pub fn new(max_requests: usize, check_every: usize, reset_seconds: u64) -> Self {
        Self {
            limiter: LimitManager::new(max_requests, check_every, reset_seconds),
        }
    }
    #[cfg(not(feature = "limiting"))]
    #[inline]
    pub fn new() -> Self {
        Self {}
    }
    #[allow(unused_variables)]
    #[inline(always)]
    pub async fn register(&mut self, addr: SocketAddr) -> LimitStrength {
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

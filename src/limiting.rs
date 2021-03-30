use crate::prelude::{networking::*, threading::*, *};

#[cfg(features = "limiting")]
pub const TOO_MANY_REQUESTS: &'static [u8] = b"\
HTTP/1.1 429 Too Many Requests\r\n\
Content-Type: text/html\r\n\
Connection: keep-alive\r\n\
Content-Encoding: identity\r\n\
Content-Length: 342\r\n\
\r\n\
<html>\
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
</html>\
";

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum LimitStrength {
    Passed,
    Send,
    Drop,
}

#[cfg(features = "limiting")]
#[derive(Debug, Clone)]
pub struct LimitManager {
    connection_map_and_time: Arc<Mutex<(HashMap<IpAddr, usize>, time::Instant)>>,
    max_requests: usize,
    check_every: usize,
    reset_seconds: u64,

    iteration: Arc<atomic::AtomicUsize>,
}
#[cfg(features = "limiting")]
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
    pub fn register(&mut self, addr: SocketAddr) -> LimitStrength {
        if self.iteration.fetch_add(1, atomic::Ordering::AcqRel) + 1 < self.check_every {
            LimitStrength::Passed
        } else {
            self.iteration.store(0, atomic::Ordering::Release);
            match self.connection_map_and_time.try_lock() {
                Err(err) => match err {
                    // Do nothing! You are allowed inside
                    TryLockError::WouldBlock => LimitStrength::Passed,
                    TryLockError::Poisoned(_) => panic!("Connection Map lock poisoned!"),
                },
                Ok(mut lock) => {
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
                        } else {
                            if requests <= self.max_requests * 10 {
                                LimitStrength::Send
                            } else {
                                LimitStrength::Drop
                            }
                        }
                    }
                }
            }
        }
    }
}
#[cfg(features = "limiting")]
impl Default for LimitManager {
    fn default() -> Self {
        Self::new(10, 10, 10)
    }
}

#[derive(Debug, Clone)]
pub struct LimitWrapper {
    #[cfg(features = "limiting")]
    pub limiter: LimitManager,
}
impl LimitWrapper {
    #[cfg(features = "limiting")]
    pub fn new(max_requests: usize, check_every: usize, reset_seconds: u64) -> Self {
        Self {
            limiter: LimitManager::new(max_requests, check_every, reset_seconds),
        }
    }
    #[cfg(not(features = "limiting"))]
    pub fn new() -> Self {
        Self {}
    }
    pub fn register(&mut self, addr: SocketAddr) -> LimitStrength {
        #[cfg(features = "limiting")]
        {
            self.limiter.register(addr)
        }
        #[cfg(not(features = "limiting"))]
        {
            LimitStrength::Passed
        }
    }
}
impl Default for LimitWrapper {
    fn default() -> Self {
        Self {
            #[cfg(features = "limiting")]
            limiter: LimitManager::default(),
        }
    }
}

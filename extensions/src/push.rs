use std::collections::HashSet;

use crate::*;

/// Mounts a push extension with priority `-32`, overriding any other [`Post`] extension with that
/// priority.
///
/// This only pushes new content to each connection every 2 minutes, not every time.
pub fn mount(extensions: &mut Extensions) -> &mut Extensions {
    let manager = Mutex::new(SmartPush::default());
    extensions.add_post(
        Box::new(move |request, host, response_pipe, bytes, addr| {
            let manager = unsafe { utils::SuperUnsafePointer::new(&manager) };
            push(request, host, response_pipe, bytes, addr, Some(manager))
        }),
        Id::new(-32, "HTTP/2 push"),
    );
    extensions
}

pub fn always(
    request: RequestWrapper,
    host: HostWrapper,
    response_pipe: ResponsePipeWrapperMut,
    bytes: Bytes,
    addr: SocketAddr,
) -> RetFut<()> {
    push(request, host, response_pipe, bytes, addr, None)
}

struct SmartPush {
    db: HashSet<SocketAddr>,
    last_clear: time::Instant,
    clear_interval: time::Duration,
    check_every_request: u32,
    iteration: u32,
}
impl SmartPush {
    fn new(clear_interval: time::Duration, check_every_request: u32) -> Self {
        Self {
            db: HashSet::new(),
            last_clear: time::Instant::now(),
            clear_interval,
            check_every_request,
            iteration: 0,
        }
    }
    fn accept(&mut self, remote: SocketAddr) -> bool {
        if self.iteration >= self.check_every_request {
            let now = time::Instant::now();
            let elapsed = now - self.last_clear;
            if elapsed > self.clear_interval {
                self.last_clear = now;
                self.db.clear();
            }
        }
        self.iteration += 1;

        !self.db.contains(&remote)
    }
    fn register(&mut self, remote: SocketAddr) {
        self.db.insert(remote);
    }
}
impl Default for SmartPush {
    fn default() -> Self {
        Self::new(time::Duration::from_secs(60 * 2), 8)
    }
}

fn push(
    request: RequestWrapper,
    host: HostWrapper,
    mut response_pipe: ResponsePipeWrapperMut,
    bytes: Bytes,
    addr: SocketAddr,
    manager: Option<utils::SuperUnsafePointer<Mutex<SmartPush>>>,
) -> RetFut<()> {
    use internals::*;
    Box::pin(async move {
        // If it is not HTTP/1
        #[allow(irrefutable_let_patterns)]
        if let ResponsePipe::Http1(_) = unsafe { &response_pipe.get_inner() } {
            return;
        }

        if let Some(manager) = manager.as_ref() {
            let manager = unsafe { manager.get() };
            let mut lock = manager.lock().await;
            if !lock.accept(addr) {
                return;
            }
        }

        // If user agent is Firefox, return.
        // This implementations of push doesn not work with Firefox!
        // I do not know why. Any help is appreciated.
        // Kvarn follows the HTTP/2 spec completely, according to h2spec.
        if unsafe { request.get_inner() }
            .headers()
            .get("user-agent")
            .and_then(|user_agent| user_agent.to_str().ok())
            .map_or(false, |user_agent| user_agent.contains("Firefox/"))
        {
            return;
        }

        const HTML_START: &str = "<!doctype html>";

        match str::from_utf8(&bytes) {
            // If it is HTML
            Ok(string)
                if string
                    .get(..HTML_START.len())
                    .map_or(false, |s| s.eq_ignore_ascii_case(HTML_START)) =>
            {
                let mut urls = url_crawl::get_urls(string);
                let host = unsafe { host.get_inner() };

                urls.retain(|url| {
                    let correct_host = {
                        // only push https://; it's eight bytes long
                        url.get(8..).map_or(false, |url| url.starts_with(host.name))
                    };
                    url.starts_with('/') || correct_host
                });

                info!("Pushing urls {:?}", urls);

                for url in urls {
                    let request = unsafe { request.get_inner() };
                    let response_pipe = unsafe { response_pipe.get_inner() };

                    let mut uri = request.uri().clone().into_parts();
                    if let Some(uri) =
                        uri::PathAndQuery::from_maybe_shared::<Bytes>(url.into_bytes().into())
                            .ok()
                            .and_then(|path| {
                                uri.path_and_query = Some(path);
                                Uri::from_parts(uri).ok()
                            })
                    {
                        let mut push_request = Request::builder().uri(uri);
                        macro_rules! copy_header {
                            ($builder: expr, $headers: expr, $name: expr) => {
                                if let Some(header) = $headers.get($name) {
                                    $builder = $builder.header($name, header);
                                }
                            };
                        }
                        let headers = request.headers();

                        copy_header!(push_request, headers, "accept-encoding");

                        let push_request = push_request.body(()).expect(
                            "failed to construct a request only from another valid request.",
                        );

                        let empty_request = utils::empty_clone_request(&push_request);

                        let mut response_pipe = match response_pipe.push_request(empty_request) {
                            Ok(pipe) => pipe,
                            Err(_) => return,
                        };

                        let mut push_request = push_request
                            .map(|_| kvarn::application::Body::Bytes(Bytes::new().into()));

                        let response = kvarn::handle_cache(&mut push_request, addr, host).await;

                        if let Err(err) = kvarn::SendKind::Push(&mut response_pipe)
                            .send(response, request, host, addr)
                            .await
                        {
                            error!("Error occurred when pushing request. {:?}", err);
                        }
                    }
                }
            }
            // Else, do nothing
            _ => {}
        }
        if let Some(manager) = manager.as_ref() {
            let manager = unsafe { manager.get() };
            let mut lock = manager.lock().await;
            lock.register(addr);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn run() {
        let mut extensions = Extensions::new();
        mount(&mut extensions);
        let _server = kvarn_testing::ServerBuilder::from(extensions).run().await;
    }
    #[test]
    fn exclusive() {
        let mut extensions = new();
        extensions.add_post(Box::new(always), Id::new(-32, "HTTP/2 push"));

        let debug = format!("{:?}", extensions);
        assert_eq!(debug.match_indices("push").count(), 1);
        mount(&mut extensions);
        assert_eq!(debug.match_indices("push").count(), 1);
    }
}

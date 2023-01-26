use std::collections::HashSet;

use crate::*;

/// Mounts a push extension with priority `-32`, overriding any other [`Post`] extension with that
/// priority.
///
/// This only pushes new content to each connection every 2 minutes (if you use
/// [`SmartPush::default`]), not every time.
pub fn mount(extensions: &mut Extensions, manager: SmartPush) -> &mut Extensions {
    let manager = Mutex::new(manager);

    extensions.add_post(
        post!(
            request,
            host,
            response_pipe,
            identity_body,
            addr,
            move |manager: Mutex<SmartPush>| {
                push(
                    request,
                    host,
                    response_pipe,
                    identity_body,
                    addr,
                    Some(manager),
                )
                .await
            }
        ),
        Id::new(-32, "HTTP/2 push"),
    );
    extensions
}

/// Always push all links on page.
///
/// # Examples
///
/// ```rust
/// # use kvarn::prelude::*;
/// # let mut extensions = Extensions::new();
/// use kvarn_extensions::push::always;
/// extensions.add_post(
///     Box::new(always),
///     Id::new(-32, "HTTP/2 push"),
/// );
/// ```
pub fn always<'a>(
    request: &'a FatRequest,
    host: &'a Host,
    response_pipe: &'a mut application::ResponsePipe,
    bytes: Bytes,
    addr: SocketAddr,
) -> RetFut<'a, ()> {
    push(request, host, response_pipe, bytes, addr, None)
}

pub struct SmartPush {
    db: HashSet<SocketAddr>,
    last_clear: Instant,
    clear_interval: Duration,
    check_every_request: u32,
    iteration: u32,
}
impl SmartPush {
    /// `clear_interval` is the duration between clearing the log of who's been pushed content.
    ///
    /// `check_every_request` is the number of requests between checks if the duration has
    /// expired.
    pub fn new(clear_interval: Duration, check_every_request: u32) -> Self {
        Self {
            db: HashSet::new(),
            last_clear: Instant::now(),
            clear_interval,
            check_every_request,
            iteration: 0,
        }
    }
    fn accept(&mut self, remote: SocketAddr) -> bool {
        if self.iteration >= self.check_every_request {
            let now = Instant::now();
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
        Self::new(Duration::from_secs(60 * 2), 8)
    }
}

fn push<'a>(
    request: &'a FatRequest,
    host: &'a Host,
    response_pipe: &'a mut application::ResponsePipe,
    bytes: Bytes,
    addr: SocketAddr,
    manager: Option<&'a Mutex<SmartPush>>,
) -> RetFut<'a, ()> {
    use internals::*;
    Box::pin(async move {
        // let request = unsafe { request.get_inner() };
        // let response_pipe = unsafe { response_pipe.get_inner() };

        // If it is not HTTP/1
        #[allow(irrefutable_let_patterns)]
        if let ResponsePipe::Http1(_) = &response_pipe {
            return;
        }

        if let Some(manager) = manager {
            // let manager = unsafe { manager.get() };
            let mut lock = manager.lock().await;
            if !lock.accept(addr) {
                return;
            }
        }

        // If user agent is Firefox, return.
        // This implementations of push doesn not work with Firefox!
        // I do not know why. Any help is appreciated.
        // Kvarn follows the HTTP/2 spec completely, according to h2spec.
        if request
            .headers()
            .get("user-agent")
            .and_then(|user_agent| user_agent.to_str().ok())
            .map_or(false, |user_agent| user_agent.contains("Firefox/"))
        {
            return;
        }

        const HTML_START: &str = "<!DOCTYPE html>";

        match str::from_utf8(&bytes) {
            // If it is HTML
            Ok(string)
                if string
                    .get(..HTML_START.len())
                    .map_or(false, |s| s.eq_ignore_ascii_case(HTML_START)) =>
            {
                let mut urls = url_crawl::get_urls(string);
                // let host = unsafe { host.get_inner() };

                urls.retain(|url| {
                    let uri: Option<Uri> = url.parse().ok();
                    if let Some(uri) = uri {
                        if uri.scheme().is_none() {
                            return true;
                        }
                        uri.host().map_or(true, |uri_host| uri_host == host.name)
                    } else {
                        false
                    }
                });
                for url in &mut urls {
                    if !url.starts_with('/') && !url.contains(':') {
                        let path = request.uri().path();
                        let mut last_slash = 0;
                        for (pos, c) in path.chars().enumerate() {
                            if c == '/' {
                                last_slash = pos;
                            }
                        }
                        url.insert_str(0, &path[..=last_slash]);
                    }
                }

                info!("Pushing urls {:?}", urls);

                urls.sort_unstable();
                urls.dedup();

                for url in urls {
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
                                for header in $headers.get_all($name) {
                                    $builder = $builder.header($name, header);
                                }
                            };
                        }
                        let headers = request.headers();

                        copy_header!(push_request, headers, "accept-encoding");
                        copy_header!(push_request, headers, "accept-language");
                        copy_header!(push_request, headers, "user-agent");
                        copy_header!(push_request, headers, "host");
                        copy_header!(push_request, headers, "origin");
                        copy_header!(push_request, headers, "cookies");

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

                info!("Push done.");
            }
            // Else, do nothing
            _ => {}
        }
        if let Some(manager) = manager {
            // let manager = unsafe { manager.get() };
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
        mount(&mut extensions, SmartPush::default());
        let _server = kvarn_testing::ServerBuilder::from(extensions).run().await;
    }
    #[test]
    fn exclusive() {
        let mut extensions = new();
        extensions.add_post(Box::new(always), Id::new(-32, "HTTP/2 push"));

        let debug = format!("{extensions:?}");
        assert_eq!(debug.match_indices("push").count(), 1);
        mount(&mut extensions, SmartPush::default());
        assert_eq!(debug.match_indices("push").count(), 1);
    }
}

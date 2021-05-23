use crate::*;

pub fn push(
    request: RequestWrapper,
    bytes: Bytes,
    mut response_pipe: ResponsePipeWrapperMut,
    addr: SocketAddr,
    host: HostWrapper,
) -> RetFut<()> {
    use internals::*;
    Box::pin(async move {
        // If it is not HTTP/1
        #[allow(irrefutable_let_patterns)]
        if let ResponsePipe::Http1(_) = unsafe { &response_pipe.get_inner() } {
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
                        url.get(8..)
                            .map(|url| url.starts_with(host.name))
                            .unwrap_or(false)
                    };
                    url.starts_with('/') || correct_host
                });

                info!("Pushing urls {:?}", urls);

                for url in urls {
                    unsafe {
                        let mut uri = request.get_inner().uri().clone().into_parts();
                        if let Some(url) = uri::PathAndQuery::from_maybe_shared(url.into_bytes())
                            .ok()
                            .and_then(|path| {
                                uri.path_and_query = Some(path);
                                Uri::from_parts(uri).ok()
                            })
                        {
                            let mut request = utility::empty_clone_request(request.get_inner());
                            *request.uri_mut() = url;

                            let empty_request = utility::empty_clone_request(&request);

                            let response = response_pipe.get_inner();
                            let mut response_pipe = match response.push_request(empty_request) {
                                Ok(pipe) => pipe,
                                Err(_) => return,
                            };

                            let request = request.map(|_| kvarn::application::Body::Empty);

                            if let Err(err) = kvarn::handle_cache(
                                request,
                                addr,
                                kvarn::SendKind::Push(&mut response_pipe),
                                host,
                            )
                            .await
                            {
                                error!("Error occurred when pushing request. {:?}", err);
                            };
                        }
                    }
                }
            }
            // Else, do nothing
            _ => {}
        }
    })
}

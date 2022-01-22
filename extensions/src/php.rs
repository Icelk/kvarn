use crate::*;

/// Redirects all requests where the [`Uri::path`] ends in `.php` to `connection`.
///
/// Priority is `-8`.
///
/// `capture_fn` can be used to pass other pages to PHP. Keep in mind the `Fn` is ran for every request, so to check if it matches several pages,
/// create a hash map and try it there.
///
/// > Setting that to `Some(|req, _host| req.uri().path() == "/sitemap.xml")` can be useful if
/// > you're running WordPress.
pub fn mount_php(
    extensions: &mut Extensions,
    connection: Connection,
    capture_fn: Option<impl Fn(&Request<application::Body>, &Host) -> bool + Send + Sync + 'static>,
) {
    extensions.add_prepare_fn(
        Box::new(move |req, host| {
            (!host.options.disable_fs && req.uri().path().ends_with(".php"))
                || (capture_fn.as_ref().map_or(false, |f| f(req, host)))
        }),
        Box::new(move |req, host, path, addr| php(req, host, path, addr, connection)),
        extensions::Id::new(-8, "PHP"),
    );
}
fn php(
    mut req: RequestWrapperMut,
    host: HostWrapper,
    path: PathOptionWrapper,
    address: SocketAddr,
    connection: Connection,
) -> RetFut<FatResponse> {
    Box::pin(async move {
        let req = unsafe { req.get_inner() };
        let host = unsafe { host.get_inner() };
        let path = unsafe { path.get_inner() };

        // This will be `Some`.
        // The only reason a path isn't `Some` is if the `disable_fs` flag is set in `host::Options`,
        // which we check for in the `If` predicate above.
        if let Some(path) = path {
            if !path.exists() {
                return default_error_response(StatusCode::NOT_FOUND, host, None).await;
            }

            let body = match req.body_mut().read_to_bytes().await {
                Ok(body) => body,
                Err(_) => {
                    return FatResponse::cache(
                        default_error(
                            StatusCode::BAD_REQUEST,
                            Some(host),
                            Some("failed to read body".as_bytes()),
                        )
                        .await,
                    )
                }
            };
            let output = match fastcgi::from_prepare(req, &body, path, address, connection).await {
                Ok(vec) => vec,
                Err(err) => {
                    error!("FastCGI failed. {}", err);
                    return default_error_response(StatusCode::INTERNAL_SERVER_ERROR, host, None)
                        .await;
                }
            };
            let output = Bytes::copy_from_slice(&output);
            match async_bits::read::response_php(&output) {
                Ok(response) => FatResponse::cache(response),
                Err(err) => {
                    error!("failed to parse response; {}", err.as_str());
                    default_error_response(StatusCode::NOT_FOUND, host, None).await
                }
            }
        } else {
            error!("Path is none. This is a internal guarantee error.");
            default_error_response(StatusCode::INTERNAL_SERVER_ERROR, host, None).await
        }
    })
}

#[cfg(test)]
mod tests {
    use kvarn_testing::prelude::*;

    #[tokio::test]
    async fn no_fs() {
        let server = ServerBuilder::from(crate::new())
            .with_options(|options| {
                options.disable_fs();
            })
            .run()
            .await;

        let response = server.get("index.php").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

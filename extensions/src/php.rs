use crate::*;

/// Redirects all requests where `capture_fn` returns true to `connection`.
///
/// Consider using [`mount_php_with_working_directory`] for a simpler install. It allows you to
/// easily add PHP for a path on your server, pointing to an arbitrary working directory.
///
/// Priority is `-8`.
///
/// A good `capture_fn` is `|req, _host| req.uri().path().ends_with(".php")`.
///
/// > Setting `capture_fn` to `|req, _host| req.uri().path() == "/sitemap.xml" || req.uri().path().ends_with(".php")` can be useful if
/// > you're running WordPress.
///
/// If you set `path_rewrite`, keep in mind that the path given to you is percent decoded (%20 -> ' '), so if
/// you're taking the path from the **request** URI, make sure to percent decode the path again.
pub fn mount_php(
    extensions: &mut Extensions,
    connection: Connection,
    capture_fn: impl Fn(&FatRequest, &Host) -> bool + Send + Sync + 'static,
    path_rewrite: Option<
        impl Fn(&str, &FatRequest, &Host) -> CompactString + Send + Sync + 'static,
    >,
) {
    type DynPathRewrite =
        Option<Box<dyn Fn(&str, &FatRequest, &Host) -> CompactString + Send + Sync + 'static>>;
    let path_rewrite: DynPathRewrite = match path_rewrite {
        Some(x) => Some(Box::new(x)),
        None => None,
    };
    extensions.add_prepare_fn(
        Box::new(move |req, host| !host.options.disable_fs && capture_fn(req, host)),
        prepare!(
            req,
            host,
            path,
            addr,
            move |connection: Connection, path_rewrite: DynPathRewrite| {
                let rewriteen_path = path
                    .and_then(Path::to_str)
                    .into_iter()
                    .zip(path_rewrite.iter())
                    .map(|(path, path_rewrite)| path_rewrite(path, req, host))
                    .next();
                let path = rewriteen_path
                    .or_else(|| path.and_then(Path::to_str).map(|s| s.to_compact_string()));
                php(req, host, path.as_deref(), addr, connection.clone()).await
            }
        ),
        extensions::Id::new(-8, "PHP").no_override(),
    );
}
/// Redirects all requests that start with `capture` to `connection`, and sets the current
/// directory for PHP to `working_directory`.
///
/// A request to `/cgi-bin/script.php` with `capture` set to `/cgi-bin/` and `working_directory`
/// set to `/opt/cgi-bin/icelk/` executes `/opt/cgi-bin/icelk/script.php`.
///
/// # Errors
///
/// Returns an error if `working_directory` isn't found on the FS.
pub async fn mount_php_with_working_directory(
    extensions: &mut Extensions,
    connection: Connection,
    capture: impl Into<String>,
    working_directory: impl Into<PathBuf>,
) -> Result<(), io::Error> {
    let working_directory = tokio::fs::canonicalize(working_directory.into()).await?;
    let working_directory = working_directory.to_string_lossy().to_compact_string();
    let capture = capture.into();
    let rewrite_capture = capture.clone();
    let file_capture = capture.clone();
    let file_rewrite_capture = capture.clone();
    let file_working_directory = working_directory.clone();
    // add binding to just read file if it's not a .php file!
    mount_php(
        extensions,
        connection,
        move |req, _host| {
            req.uri().path().starts_with(&capture) && req.uri().path().ends_with(".php")
        },
        Some(move |_path: &str, request: &FatRequest, _host: &Host| {
            let path = format!(
                "/{}",
                request
                    .uri()
                    .path()
                    .strip_prefix(&rewrite_capture)
                    .expect("failed to strip a prefix we guaranteed the URI path starts with")
            );
            let decoded = percent_encoding::percent_decode_str(&path)
                .decode_utf8()
                .expect("percent decoding was successful earlier in Kvarn");
            let p = utils::make_path(
                &working_directory,
                "",
                // Ok, since Uri's have to start with a `/` (https://github.com/hyperium/http/issues/465).
                // We also are OK with all Uris, since we did a check on the
                // incoming and presume all internal extension changes are good.
                utils::parse::uri(&decoded).unwrap(),
                None,
            );
            p
        }),
    );
    extensions.add_prepare_fn(
        Box::new(move |req, host| {
            !host.options.disable_fs
                && req.uri().path().starts_with(&file_capture)
                && !req.uri().path().ends_with(".php")
        }),
        prepare!(
            req,
            host,
            _path,
            _addr,
            move |file_rewrite_capture: String, file_working_directory: CompactString| {
                if req.method() != Method::GET && req.method() != Method::HEAD {
                    return default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None)
                        .await;
                }
                let path = format!(
                    "/{}",
                    req.uri()
                        .path()
                        .strip_prefix(file_rewrite_capture)
                        .expect("failed to strip a prefix we guaranteed the URI path starts with")
                );
                let decoded = percent_encoding::percent_decode_str(&path)
                    .decode_utf8()
                    .expect("percent decoding was successful earlier in Kvarn");
                let p = utils::make_path(
                    file_working_directory,
                    "",
                    // Ok, since Uri's have to start with a `/` (https://github.com/hyperium/http/issues/465).
                    // We also are OK with all Uris, since we did a check on the
                    // incoming and presume all internal extension changes are good.
                    utils::parse::uri(&decoded).unwrap(),
                    None,
                );
                let file = read_file_cached(&p, host.file_cache.as_ref()).await;
                if let Some(file) = file {
                    FatResponse::new(Response::new(file), comprash::ServerCachePreference::Full)
                } else {
                    default_error_response(StatusCode::NOT_FOUND, host, None).await
                }
            }
        ),
        extensions::Id::new(-9, "PHP file server").no_override(),
    );
    Ok(())
}
fn php<'a>(
    req: &'a mut FatRequest,
    host: &'a Host,
    path: Option<&'a str>,
    address: SocketAddr,
    connection: Connection,
) -> RetFut<'a, FatResponse> {
    box_fut!({
        // This will be `Some`.
        // The only reason a path isn't `Some` is if the `disable_fs` flag is set in `host::Options`,
        // which we check for in the `If` predicate above.
        if let Some(path) = path {
            if tokio::fs::metadata(&path).await.is_err() {
                return default_error_response(StatusCode::NOT_FOUND, host, None).await;
            }

            let body = match req.body_mut().read_to_bytes(1024 * 1024 * 16).await {
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
            let output =
                match fastcgi::from_prepare(req, &body, Path::new(path), address, connection).await
                {
                    Ok(vec) => vec,
                    Err(err) => {
                        error!("FastCGI failed: {err}");
                        return default_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            host,
                            None,
                        )
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
            error!("Path is none. This is a internal contract error.");
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
        assert_eq!(response.status().as_str(), StatusCode::NOT_FOUND.as_str());
    }
}

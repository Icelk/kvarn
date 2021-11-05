use kvarn::prelude::*;
use kvarn_testing::ServerBuilder;

#[tokio::test]
async fn prime_redirect() {
    let extensions = get_extensions();

    let server = ServerBuilder::new(extensions, host::Options::default())
        .run()
        .await;

    let response = server.get("/").send().await.unwrap();
    assert!(response.text().await.unwrap().contains("404 Not Found"));

    let response = server
        .get("/")
        .header("user-agent", "curl")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "::1");

    let response = server
        .get("/")
        .header(
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/78.0",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "<!DOCTYPE html>\n<html>\n<head>\n<title>Your IP address </title>\n</head>\n<body><h2>Your IP address is ::1</h2></body>\n</html>");

    let response = server.get("/ip").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "::1");
}

#[tokio::test]
async fn package_and_post() {
    let run_validation = Arc::new(threading::atomic::AtomicBool::new(false));
    let cloned_run_validation = run_validation.clone();

    let mut extensions = get_extensions();
    extensions.add_post(
        post!(
            _req,
            _host,
            _response,
            _body,
            _addr,
            move |run_validation| {
                run_validation.store(true, threading::Ordering::Release);
            }
        ),
        extensions::Id::new(-42, "post test"),
    );

    let server = ServerBuilder::new(extensions, host::Options::default())
        .run()
        .await;

    let response = server.get("/").send().await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|header| header.to_str().ok()),
        Some("default-src 'self'; style-src 'unsafe-inline' 'self'")
    );

    assert!(cloned_run_validation.load(threading::Ordering::Acquire));
}

#[tokio::test]
async fn body() {
    let length = 1024 * 16 + 7;

    let server = ServerBuilder::default()
        .with_extensions(|extensions| {
            extensions.add_prepare_single(
                "/api-1".to_string(),
                prepare!(req, _host, path, _addr {
                    let body = req.body_mut().read_to_bytes().await.unwrap();
                    let body = str::from_utf8(&body).unwrap();

                    assert_eq!(body, "This is the full body.");
                    assert_eq!(path.as_deref(), Some(Path::new("tests/public/api-1")));

                    FatResponse::no_cache(Response::new(Bytes::from_static(b"OK")))
                }),
            );
            extensions.add_prepare_single(
                "/api-2".to_string(),
                prepare!(req, _host, _path, _addr {
                    let body = req.body_mut().read_to_bytes().await.unwrap();

                    println!("Body len: {}", body.len());
                    let expected = vec![chars::SPACE; length];

                    assert_eq!(&body, &expected);

                    FatResponse::no_cache(Response::new(Bytes::from_static(b"OK")))
                }),
            );
            extensions.add_prepare_single(
                "/api-3".to_string(),
                prepare!(req, _host, _path, _addr {
                    let body = req.body_mut().read_to_bytes().await.unwrap();
                    let body = str::from_utf8(&body).unwrap();

                    assert_eq!(body, "");

                    FatResponse::no_cache(Response::new(Bytes::from_static(b"OK")))
                }),
            );
        })
        .run()
        .await;
    server
        .post("/api-1")
        .header("content-type", "text/plain; encoding=utf-8")
        .body("This is the full body.")
        .send()
        .await
        .unwrap();

    let body = vec![chars::SPACE; length];
    server
        .post("/api-2")
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .unwrap();
    server
        .get("/api-3")
        .header("content-type", "text/plain; encoding=utf-8")
        .body("This is the full body.")
        .send()
        .await
        .unwrap();
}

fn get_extensions() -> Extensions {
    let mut extensions = Extensions::empty();

    extensions.add_prime(prime!(request, host, addr {
        assert_eq!(host.name, "localhost");
        assert_eq!(addr.ip(), net::Ipv6Addr::LOCALHOST);

        if request.uri().path() == "/" {
            // This maps the Option<HeaderValue> to Option<Result<&str, _>> which the
            // `.and_then(Result::ok)` makes Option<&str>, returning `Some` if the value is both `Ok` and `Some`.
            // Could also be written as
            // `.get("user-agent").and_then(|header| header.to_str().ok())`.
            if let Some(ua) = request.headers().get("user-agent").map(HeaderValue::to_str).and_then(Result::ok) {
                if ua.contains("curl") {
                    Some(Uri::from_static("/ip"))
                } else {
                    Some(Uri::from_static("/index.html"))
                }
            } else {
                None
            }
        } else {
            None
        }
    }), extensions::Id::new(16, "Redirect `/`"));

    extensions.add_prepare_single(
        "/ip".to_string(),
        prepare!(_request, _host, _path, addr {
            let ip = addr.ip().to_string();
            let response = Response::new(Bytes::copy_from_slice(ip.as_bytes()));
            FatResponse::no_cache(response)
        }),
    );
    extensions.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_request, _host, _path, addr {
            let content = format!(
                "!> simple-head Your IP address\n\
                <h2>Your IP address is {}</h2>",
                addr.ip()
            );
            let response = Response::new(Bytes::copy_from_slice(content.as_bytes()));
            FatResponse::new(response, comprash::ServerCachePreference::None)
        }),
    );

    extensions.add_present_internal(
        "simple-head".to_string(),
        present!(present_data {
            let content = present_data.response().body();

            let start = "\
<!DOCTYPE html>
<html>
<head>
<title>";
            let middle = "\
</title>
</head>
<body>";
            let end = "\
</body>
</html>";
            let title = present_data.args().iter().fold(String::new(), |mut acc, arg| {
                acc.push_str(arg);
                acc.push(' ');
                acc
            });

            let bytes = build_bytes!(start.as_bytes(), title.as_bytes(), middle.as_bytes(), content, end.as_bytes());
            *present_data.response_mut().body_mut() = bytes;
        }),
    );
    extensions.add_package(
        package!(response, _request, _host {
            response.headers_mut().insert("fun-header", HeaderValue::from_static("why not?"));
            utils::replace_header_static(response.headers_mut(), "content-security-policy", "default-src 'self'; style-src 'unsafe-inline' 'self'");
        }),
        extensions::Id::new(-1024, "add headers"),
    );

    extensions.add_post(
        post!(_request, host, _response_pipe, body, addr {
            if let Ok(mut body) = str::from_utf8(&body) {
                body = body.get(0..512).unwrap_or(body);
                println!("Sent {:?} to {} from {}", body, addr, host.name);
            }
        }),
        extensions::Id::new(0, "Print sent data"),
    );

    extensions
}

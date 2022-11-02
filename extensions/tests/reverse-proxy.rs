#[cfg(feature = "reverse-proxy")]
use kvarn_testing::prelude::*;

#[tokio::test]
#[cfg(feature = "reverse-proxy")]
async fn basic() {
    let servers_dir = "/port/";
    let path = Arc::new(servers_dir.to_owned());

    let get_port = |req: &Request<_>, path: &str| {
        let req_path = req.uri().path();
        req_path
            .strip_prefix(path)
            .map(|path| {
                let mut i = path.split('/');
                (i.next(), i.next())
            })
            .and_then(|(first, second)| {
                second?;
                first
            })
            .and_then(|port| port.parse::<u16>().ok())
    };

    let when_path = Arc::clone(&path);
    let when =
        Box::new(move |request: &FatRequest, _host: &Host| get_port(request, &when_path).is_some());

    let con_path = Arc::clone(&path);
    let connection: kvarn_extensions::reverse_proxy::GetConnectionFn =
        Arc::new(move |request, _bytes| {
            get_port(request, &con_path)
                .map(kvarn_extensions::localhost)
                .map(kvarn_extensions::Connection::Tcp)
        });

    let modify: kvarn_extensions::reverse_proxy::ModifyRequestFn =
        Arc::new(move |request, _, _| {
            let path = Arc::clone(&path);

            request
                .headers_mut()
                .insert("proxy", HeaderValue::from_static("Kvarn"));

            // We know this is a good path and query; we've just removed the first x bytes.
            let stripped_path = request.uri().path().get(path.as_str().len()..);
            if let Some(stripped_path) = stripped_path {
                let pos = stripped_path.find('/').map(|pos| pos + path.len());
                if let Some(pos) = pos {
                    let mut parts = request.uri().clone().into_parts();

                    if let Some(short_path) = request.uri().path().get(pos..) {
                        let short = uri::PathAndQuery::from_maybe_shared(Bytes::copy_from_slice(
                            short_path.as_bytes(),
                        ))
                        .unwrap();
                        parts.path_and_query = Some(short);
                        parts.scheme = Some(uri::Scheme::HTTP);
                        // For unwrap, see ↑
                        let uri = Uri::from_parts(parts).unwrap();
                        *request.uri_mut() = uri;
                    }
                }
            }
        });
    let manager = kvarn_extensions::ReverseProxy::new(
        when,
        connection,
        modify,
        std::time::Duration::from_secs(5),
    );
    let mut proxy_extensions = Extensions::new();
    manager.mount(&mut proxy_extensions);

    let proxy = ServerBuilder::from(proxy_extensions).run().await;

    let backend = ServerBuilder::default()
        .http()
        .with_extensions(|ext| {
            ext.add_prepare_single(
                "/api",
                kvarn::prepare!(req, _host, _path, addr, {
                    let bytes = kvarn::prelude::build_bytes!(
                        b"The SocketAddr of the proxy's request is ",
                        addr.to_string().as_bytes(),
                        b".\nThe `proxy` header is `",
                        format!("{:?}", req.headers().get("proxy")).as_bytes(),
                        b"`."
                    );
                    let response = Response::new(bytes);
                    FatResponse::no_cache(response)
                }),
            )
        })
        .run()
        .await;

    let response = proxy
        .get(format!("/port/{}/api", backend.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let text = response.text().await.unwrap();
    assert!(text.contains("127.0.0.1"), "Text: {:?}", text);
}

#[tokio::test]
#[cfg(feature = "reverse-proxy")]
async fn base() {
    let backend = ServerBuilder::default()
        .http()
        .with_extensions(|ext| {
            ext.add_prepare_single(
                "/user-agent",
                kvarn::prepare!(req, _host, _path, _addr, {
                    let bytes = Bytes::copy_from_slice(
                        format!("{:?}", req.headers().get("user-agent")).as_bytes(),
                    );
                    let response = Response::new(bytes);
                    FatResponse::no_cache(response)
                }),
            )
        })
        .run()
        .await;
    let mut extensions = Extensions::new();
    kvarn_extensions::ReverseProxy::base(
        "/api",
        kvarn_extensions::static_connection(kvarn_extensions::Connection::Tcp(
            kvarn_extensions::localhost(backend.port()),
        )),
        std::time::Duration::from_secs(5),
    )
    .mount(&mut extensions);
    let proxy = ServerBuilder::from(extensions).run().await;

    let ua = "Kvarn testing!";
    let response = proxy
        .get("/api/user-agent")
        .header("user-agent", ua)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), format!("Some({:?})", ua));
}

#[tokio::test]
#[cfg(feature = "reverse-proxy")]
async fn chunked_encoding() {
    let backend = ServerBuilder::default()
        .http()
        .with_extensions(|ext| {
            ext.add_prepare_single(
                "/chunked",
                kvarn::prepare!(_req, _host, _path, _addr, {
                    let bytes = Bytes::from_static(b"5\r\nhello\r\n7\r\n world!\r\n0\r\n\r\n");
                    let response = Response::builder()
                        .header("transfer-encoding", "chunked")
                        .body(bytes)
                        .unwrap();
                    FatResponse::no_cache(response)
                }),
            )
        })
        .run()
        .await;
    let mut extensions = Extensions::new();
    kvarn_extensions::ReverseProxy::base(
        "/api",
        kvarn_extensions::static_connection(kvarn_extensions::Connection::Tcp(
            kvarn_extensions::localhost(backend.port()),
        )),
        std::time::Duration::from_secs(5),
    )
    .mount(&mut extensions);
    let proxy = ServerBuilder::from(extensions).run().await;

    let response = proxy.get("/api/chunked").send().await.unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "hello world!");
}

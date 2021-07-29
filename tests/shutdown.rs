use kvarn::prelude::*;
use kvarn_testing::prelude::*;

#[tokio::test]
async fn basic() {
    let server = ServerBuilder::default()
        .with_extensions(|ext| {
            ext.add_prepare_single(
                "/slow-response".to_string(),
                prepare!(_req, _host, _path, _addr {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    FatResponse::no_cache(Response::new(Bytes::from_static(b"Finally here!")))
                }),
            )
        })
        .run()
        .await;

    internals::timeout(std::time::Duration::from_millis(200), async move {
        let shutdown = server.get_shutdown_manager();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            shutdown.shutdown();
        });

        let response = server.get("/slow-response").send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "Finally here!");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn handover() {
    let socket_path = "handover_test.sock";
    let server = ServerBuilder::default()
        .http()
        .enable_handover(socket_path)
        .run()
        .await;

    let url = server.url("/");
    let cert = server.cert().map(Clone::clone);

    let running = Arc::new(threading::atomic::AtomicBool::new(true));
    let running_send = Arc::clone(&running);
    // spam with requests
    tokio::spawn(async move {
        loop {
            let mut client = reqwest::Client::builder();
            if let Some(cert) = &cert {
                let cert = reqwest::Certificate::from_der(&cert.0).unwrap();
                client = client.add_root_certificate(cert);
            };
            let client = client.build().unwrap();
            let request = client.request(reqwest::Method::GET, url.clone());
            tokio::spawn(async move {
                request.send().await.unwrap().text().await.unwrap();
            });
            // Stop when not running!
            if !running_send.load(threading::Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_micros(100)).await;
        }
    });
    // Let's get some requests!
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // Now handover.
    let server = ServerBuilder::default()
        .http()
        .handover_from(&server)
        .run()
        .await;
    // Let this accept some requests
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // The tell them to stop.
    running.store(false, threading::Ordering::Relaxed);
    // Shortly after, drop server, so it shuts down, removing the socket
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    drop(server);
    // Wait for the shutdown messages to be passed
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    assert!(!Path::new(socket_path).exists());
}

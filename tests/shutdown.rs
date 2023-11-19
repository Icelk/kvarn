use kvarn::prelude::*;
use kvarn_testing::prelude::*;

#[tokio::test]
async fn basic() {
    let server = ServerBuilder::default()
        .with_extensions(|ext| {
            ext.add_prepare_single(
                "/slow-response",
                prepare!(_, _, _, _, {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    FatResponse::no_cache(Response::new(Bytes::from_static(b"Finally here!")))
                }),
            )
        })
        .run()
        .await;

    internals::timeout(Duration::from_millis(1000), async move {
        let shutdown = server.get_shutdown_manager();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
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
    let failed = Arc::new(threading::atomic::AtomicBool::new(false));

    let running = Arc::new(threading::atomic::AtomicBool::new(true));
    let running_send = Arc::clone(&running);
    // spam with requests
    let f = failed.clone();
    tokio::spawn(async move {
        loop {
            if !running_send.load(threading::Ordering::Acquire) {
                break;
            }
            let mut client = reqwest::Client::builder();
            if let Some(cert) = &cert {
                let cert = reqwest::Certificate::from_der(&cert.0).unwrap();
                client = client.add_root_certificate(cert);
            };
            let client = client.build().unwrap();
            let request = client.request(reqwest::Method::GET, url.clone());
            let failed = f.clone();
            tokio::spawn(async move {
                let response = match request.send().await {
                    Err(err) => {
                        let error_text = format!("{err:?}");
                        if error_text.contains("ConnectionReset") {
                            // there is an edge-case whenere some clients are rejected (in reality
                            // only when not running --release)
                            // which occurs when a new connection has been accepted by the kernel,
                            // but the task has not yet been notified. Instead, it is notified by a
                            // shutdown. Dropping the listener, the connection gets reset.
                            return;
                        }
                        failed.store(true, threading::Ordering::SeqCst);
                        println!("{:?}", std::time::SystemTime::now());
                        panic!("{err}");
                    }
                    Ok(r) => r,
                };
                if let Err(err) = response.text().await {
                    failed.store(true, threading::Ordering::SeqCst);
                    println!("{:?}", std::time::SystemTime::now());
                    panic!("{err}");
                }
            });
            // Stop when not running!
            if !running_send.load(threading::Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    });
    // Let's get some requests!
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Now handover.
    let server = ServerBuilder::default()
        .http()
        .handover_from(&server)
        .run()
        .await;
    // Let this accept some requests
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The tell them to stop.
    running.store(false, threading::Ordering::Relaxed);
    // Shortly after, drop server, so it shuts down, removing the socket
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(server);
    // Wait for the shutdown messages to be passed
    tokio::time::sleep(Duration::from_millis(10)).await;

    if failed.load(threading::Ordering::SeqCst) {
        panic!("Requests were rejected!");
    }

    assert!(!Path::new(socket_path).exists());
}

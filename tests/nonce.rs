use kvarn::prelude::*;
use kvarn_testing::prelude::*;

const DATA: &str = r#"!> nonce
<!DOCTYPE html>
<html>
<head>
<script nonce="this will be removed">alert("hi!");</script>
</head>

<body>
The body.
</body>
</html>
"#;

fn get_server() -> ServerBuilder {
    ServerBuilder::default().with_extensions(|ext| {
        assert!(ext.get_present_internal().contains_key("nonce"));
        ext.add_prepare_single(
            "/index.html",
            prepare!(_, _, _, _, {
                let bytes = Bytes::from_static(DATA.as_bytes());
                FatResponse::cache(Response::new(bytes))
            }),
        );
    })
}

#[tokio::test]
async fn header_match() {
    let server = get_server().run().await;

    let response = server.get("/").send().await.unwrap();

    let csp = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    println!("CSP: {csp:?}");
    let start = csp.find("'nonce-").unwrap();
    let end = csp[start + 7..].find('\'').unwrap();
    let nonce = &csp[start + 7..start + 7 + end];

    assert_eq!(nonce.len(), 24);

    assert_eq!(csp.matches(nonce).count(), 4);

    let needle = format!("nonce=\"{nonce}\"");
    let body = response.text().await.unwrap();
    assert!(body.contains(&needle));
    assert!(!body.contains("this will be removed"));
}

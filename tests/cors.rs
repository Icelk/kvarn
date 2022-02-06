use kvarn::prelude::*;
use kvarn_testing::prelude::*;

#[tokio::test]
async fn default_deny() {
    let server = ServerBuilder::default().run().await;
    let response = server
        .get("/")
        .header("origin", "https://kvarn.org")
        .send()
        .await
        .unwrap();

    test_cors_response(response, false, line!()).await;
}
#[tokio::test]
async fn default_options() {
    let server = ServerBuilder::default().run().await;
    test_cors_options(
        &server,
        "/",
        "https://doc.kvarn.org",
        &[Method::POST],
        &[],
        false,
        false,
        line!(),
    )
    .await;
}

fn get_extensions() -> Extensions {
    let mut extensions = Extensions::new();
    let cors = Cors::empty()
        .add("/logo.svg", CorsAllowList::default().allow_all_origins())
        .add(
            "/api/*",
            CorsAllowList::default()
                .add_origin("https://icelk.dev")
                .add_origin("http://kvarn.org")
                .add_origin("https://kvarn.org")
                .add_method(Method::PUT)
                .add_method(Method::DELETE),
        )
        .add(
            "/images/*",
            CorsAllowList::new(Duration::from_secs(60 * 60 * 24 * 365))
                .add_origin("https://example.org")
                .add_origin("https://foo.bar"),
        )
        .arc();

    extensions.with_cors(cors);
    extensions
}
async fn test_cors_response(response: reqwest::Response, valid_expected: bool, line: u32) {
    if valid_expected {
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NO_CONTENT,
            "On line {} Response: {:#?}",
            line,
            response
        );
    } else {
        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "On line {} Response: {:#?}",
            line,
            response
        );
        assert_eq!(
            response.text().await.unwrap(),
            "CORS request denied",
            "On line {}",
            line
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn test_cors_options(
    server: &Server,
    path: impl AsRef<str>,
    origin: impl AsRef<str>,
    methods: &[Method],
    headers: &[&str],
    valid_expected: bool,
    test_methods_and_headers: bool,
    line: u32,
) {
    let mut request = server
        .options(path.as_ref())
        .header("origin", origin.as_ref());
    if !methods.is_empty() {
        let mut methods =
            methods
                .iter()
                .map(Method::as_str)
                .fold(String::new(), |mut s, method| {
                    s.push_str(method);
                    s.push_str(", ");
                    s
                });
        methods.pop();
        methods.pop();
        request = request.header("access-control-request-method", methods);
    }
    if !headers.is_empty() {
        let mut headers = headers.iter().fold(String::new(), |mut s, header| {
            s.push_str(header);
            s.push_str(", ");
            s
        });
        headers.pop();
        headers.pop();
        request = request.header("access-control-request-headers", headers);
    }

    let response = request.send().await.unwrap();

    if test_methods_and_headers {
        let mut all_all_here = true;
        if let Some(accepted_methods) = response
            .headers()
            .get("access-control-allow-methods")
            .and_then(|h| h.to_str().ok())
        {
            let mut all_here = true;
            for expected_method in methods {
                if !accepted_methods.contains(expected_method.as_str()) {
                    println!("NOT HERE!");
                    all_here = false;
                    break;
                }
            }
            if !all_here {
                all_all_here = false;
            }
        }
        if let Some(accepted_headers) = response
            .headers()
            .get("access-control-allow-headers")
            .and_then(|h| h.to_str().ok())
        {
            let mut all_here = true;
            for expected_header in headers {
                if !accepted_headers.contains(expected_header) {
                    all_here = false;
                    break;
                }
            }
            println!("All headers here");
            if !all_here {
                all_all_here = false;
            }
        }
        assert_eq!(all_all_here, valid_expected, "On line {}", line);
    } else {
        test_cors_response(response, valid_expected, line).await;
    }
}
#[tokio::test]
async fn options() {
    let server = ServerBuilder::from(get_extensions()).run().await;

    test_cors_options(
        &server,
        "/logo.svg",
        "ftp://foo.bar",
        &[Method::GET],
        &[],
        true,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/api/test",
        "ftp://foo.bar",
        &[Method::PUT],
        &[],
        false,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/api/test",
        "http://icelk.dev",
        &[],
        &[],
        false,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/api/test",
        "https://icelk.dev",
        &[Method::GET, Method::PUT, Method::DELETE],
        &[],
        true,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/api/test",
        "https://icelk.dev",
        &[Method::GET, Method::PUT, Method::DELETE, Method::POST],
        &[],
        false,
        true,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/api/test",
        "https://icelk.dev",
        &[Method::GET, Method::PUT, Method::DELETE],
        &["content-type"],
        false,
        true,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/",
        "https://icelk.dev",
        &[Method::GET],
        &[],
        false,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/images",
        "https://example.org",
        &[Method::GET],
        &[],
        false,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/images/",
        "https://example.org",
        &[Method::GET],
        &[],
        true,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/images/my-funny-cat-pic.png",
        "https://example.org",
        &[Method::GET],
        &[],
        true,
        false,
        line!(),
    )
    .await;
    test_cors_options(
        &server,
        "/images/my-funny-cat-pic.png",
        "https://kvarn.org",
        &[Method::GET],
        &[],
        false,
        false,
        line!(),
    )
    .await;

    let max_age_response = server
        .options("/images/my-funny-cat-pic.png")
        .header("origin", "https://example.org")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(
        max_age_response
            .headers()
            .get("access-control-max-age")
            .unwrap()
            .to_str()
            .unwrap(),
        (60 * 60 * 24 * 365).to_string()
    );
}

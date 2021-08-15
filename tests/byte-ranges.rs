use bytes::BufMut;
use kvarn::prelude::*;
use kvarn_testing::prelude::*;

const DATA: &str = "This is a small document with a length of 50 bytes";

fn get_server() -> ServerBuilder {
    ServerBuilder::default().with_extensions(|ext| {
        ext.add_prepare_single(
            "/index.html".to_string(),
            prepare!(_request, _host, _path, _addr {
                let bytes = Bytes::from_static(DATA.as_bytes());
                FatResponse::cache(Response::new(bytes))
            }),
        );
    })
}

#[tokio::test]
async fn byte_ranges() {
    let server = get_server().run().await;

    let mut received_data = BytesMut::new();

    let response1 = server
        .get("/")
        .header("range", "bytes=0-15")
        .send()
        .await
        .unwrap();
    let content_range = response1
        .headers()
        .get("content-range")
        .unwrap()
        .to_str()
        .unwrap();
    let content_length: usize = content_range.split('/').last().unwrap().parse().unwrap();
    received_data.put(response1.text().await.unwrap().as_bytes());

    let response2 = server
        .get("/")
        .header("range", format!("bytes=16-{}", content_length - 1))
        .send()
        .await
        .unwrap();
    assert_eq!(response2.status(), reqwest::StatusCode::PARTIAL_CONTENT);
    received_data.put(response2.text().await.unwrap().as_bytes());

    assert_eq!(received_data, DATA.as_bytes());
}

#[tokio::test]
async fn out_of_bounds() {
    let server = get_server().run().await;

    let response = server
        .get("/")
        .header("range", "bytes=50-100")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::RANGE_NOT_SATISFIABLE
    );
    assert_eq!(
        response.headers().get("reason").unwrap().to_str().unwrap(),
        "Range start after end of body"
    )
}
#[tokio::test]
async fn end_before_start() {
    let server = get_server().run().await;

    let response = server
        .get("/")
        .header("range", "bytes=30-20")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::RANGE_NOT_SATISFIABLE
    );
}

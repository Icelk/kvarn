#[cfg(feature = "templates")]
use kvarn_testing::prelude::*;

#[cfg(feature = "templates")]
#[tokio::test]
async fn basic() {
    let file = "\
!> tmpl 1.txt\n\
[1]\
";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "1");
}

#[cfg(feature = "templates")]
#[tokio::test]
async fn non_existent() {
    let file = "\
!> tmpl 1.txt\n\
[2]\
Nothing here!\
";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "Nothing here!");
}

#[cfg(feature = "templates")]
#[tokio::test]
async fn several_files() {
    let file = "\
!> tmpl 1.txt 2.txt\n\
[
2
]
[1!]
";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "\\2\\2[2]\n111\n");
}

#[cfg(feature = "templates")]
#[tokio::test]
async fn non_closing() {
    let file = "\
!> tmpl 2.txt\n\
[2!]\
";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "");
}

#[cfg(feature = "templates")]
#[tokio::test]
async fn escaping() {
    let file = "\
!> tmpl 2.txt\n\
\\[2]
[\n2\n]";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "[2]\n\\2\\2[2]");
}

#[cfg(feature = "templates")]
#[tokio::test]
async fn spaces_before_template() {
    let file = r"!> tmpl 3.txt
   [spaces]";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "   this contains spaces!");
}

#[cfg(feature = "templates")]
#[tokio::test]
async fn complex_data() {
    let file = "\
!> tmpl 3.txt
this is complex
[complex]
data";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(
        response.text().await.unwrap(),
        "this is complex\noh <b>so</b> complex\ndata"
    );
}

#[cfg(feature = "templates")]
#[tokio::test]
async fn tmpl_ignore() {
    let file = "\
!> tmpl 1.txt
<---! tmpl-ignore -->
[1!]
data";
    let mut ext = kvarn_extensions::new();
    ext.add_prepare_single(
        "/index.html".to_string(),
        prepare!(_req, _host, _path, _addr {
            FatResponse::no_cache(Response::new(Bytes::copy_from_slice(file.as_bytes())))
        }),
    );
    let server = ServerBuilder::from(ext).path("./").run().await;
    let response = server.get("/").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "111\ndata");
}

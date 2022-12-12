#![allow(clippy::doc_markdown)] // WebSocket is the name of the protocol
#![cfg(feature = "websocket")]
//! Easy and fast WebSockets for Kvarn.
//!
//! See [`response()`] for an example.
use crate::prelude::*;
use sha1::Digest;

pub use futures_util::{Sink, SinkExt, Stream, StreamExt};
pub use tokio_tungstenite;
pub use tokio_tungstenite::tungstenite;

static SEC_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Form a response to a request on a WebSocket route.
///
/// Checks the HTTP version, `Connection` and `Upgrade` headers, handles the `Sec-WebSocket-Accept`
/// header, and makes sure this isn't an unallowed cross origin request.
///
/// # Examples
/// ```
/// use kvarn::prelude::*;
/// use kvarn::websocket::{SinkExt, StreamExt};
///
/// let mut extensions = Extensions::new();
///
/// extensions.add_prepare_single(
///     "/ws-ping",
///     prepare!(req, host, _path, _addr, {
///         kvarn::websocket::response(
///             req,
///             host,
///             response_pipe_fut!(response_pipe, _host, {
///                 let mut ws = kvarn::websocket::wrap(response_pipe).await;
///                 while let Some(Ok(message)) = ws.next().await {
///                     let _ = ws.send(message).await;
///                 }
///             }),
///         ).await
///     }),
/// );
/// ```
pub async fn response(req: &FatRequest, host: &Host, future: ResponsePipeFuture) -> FatResponse {
    if req.headers().get("connection").map_or(true, |conn| {
        conn.to_str().map_or(true, |s| {
            !s.split(',')
                .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))
        })
    }) || req
        .headers()
        .get("upgrade")
        .map_or(true, |upg| upg != "websocket")
    {
        let mut response = default_error(StatusCode::UPGRADE_REQUIRED, Some(host), None).await;
        response
            .headers_mut()
            .insert("connection", HeaderValue::from_static("upgrade"));
        response
            .headers_mut()
            .insert("upgrade", HeaderValue::from_static("websocket"));
        return FatResponse::cache(response)
            .with_server_cache(comprash::ServerCachePreference::None);
    }
    if let Body::Http1(_) = req.body() {
        // allowed
    } else {
        return default_error_response(
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            host,
            Some("You must use HTTP/1.1 for WebSocket requests"),
        )
        .await;
    }
    let key = if let Some(k) = req.headers().get("sec-websocket-key") {
        k
    } else {
        return default_error_response(
            StatusCode::BAD_REQUEST,
            host,
            Some("No Sec-WebSocket-Key header was sent"),
        )
        .await;
    };
    let mut hasher = sha1::Sha1::new();
    hasher.update(key);
    hasher.update(SEC_MAGIC_STRING);
    let hash = hasher.finalize();
    let mut bytes = BytesMut::with_capacity(28);
    // I have dug into the code and verified that the call to base64::encode_config_slice will fill
    // all 28 bytes.
    unsafe { bytes.set_len(28) };
    base64::encode_engine_slice(hash, &mut bytes, &base64::engine::DEFAULT_ENGINE);
    let response = Response::builder()
        .header(
            "sec-websocket-accept",
            HeaderValue::from_maybe_shared(bytes.freeze()).expect(
                "the base64 encoded sec-websocket-accept \
                response contains illegal header value bytes",
            ),
        )
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(Bytes::new())
        .expect("building the WebSocket response body failed");
    FatResponse::new(response, comprash::ServerCachePreference::None)
        .with_compress(comprash::CompressPreference::None)
        .with_future(future)
}

/// Get a [`tokio_tungstenite::WebSocketStream`] from the `pipe` given by [`response_pipe_fut!`].
///
/// # Examples
///
/// See [`response()`].
pub async fn wrap(
    pipe: &mut ResponseBodyPipe,
) -> tokio_tungstenite::WebSocketStream<&mut ResponseBodyPipe> {
    tokio_tungstenite::WebSocketStream::from_raw_socket(
        pipe,
        tungstenite::protocol::Role::Server,
        None,
    )
    .await
}

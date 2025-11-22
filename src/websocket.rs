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
///                 let mut ws = kvarn::websocket::wrap(response_pipe).await.unwrap();
///                 while let Some(Ok(message)) = ws.next().await {
///                     let _ = ws.send(message).await;
///                 }
///             }),
///         ).await
///     }),
/// );
/// ```
pub async fn response(req: &FatRequest, host: &Host, future: ResponsePipeFuture) -> FatResponse {
    use base64::Engine;
    const DEFAULT_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_encode_padding(false),
    );

    if req.headers().get("connection").is_none_or(|conn| {
        conn.to_str().map_or(true, |s| {
            !s.split(',')
                .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))
        })
    }) || req
        .headers()
        .get("upgrade")
        .is_none_or(|upg| upg != "websocket")
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
    let Some(key) = req.headers().get("sec-websocket-key") else {
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
    DEFAULT_ENGINE
        .encode_slice(hash, &mut bytes)
        .expect("base64 encoding failed");
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

/// Error from WebSocket operations
#[derive(Debug)]
pub enum Error {
    /// WebSocket currently isn't supported for HTTP/3 nor HTTP/2.
    WebSocketUnsupported,
}
/// Variants of WebSocket streams.
#[derive(Debug)]
pub enum WSStream<'a> {
    /// HTTP/1 version
    /// WebTransport was introduced in HTTP/3 and WebSocket support is sketch in HTTP/2,
    /// so this is unlikely to get more versions
    Http1(&'a Arc<Mutex<Encryption>>),
}
impl AsyncRead for WSStream<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http1(s) => match s.try_lock() {
                Err(_) => Poll::Pending,
                Ok(mut s) => Pin::new(&mut *s).poll_read(cx, buf),
            },
        }
    }
}
impl AsyncWrite for WSStream<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Http1(s) => match s.try_lock() {
                Err(_) => Poll::Pending,
                Ok(mut s) => Pin::new(&mut *s).poll_write(cx, buf),
            },
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Http1(s) => {
                if let Ok(mut s) = s.try_lock() {
                    Pin::new(&mut *s).poll_flush(cx)
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

/// Get a [`tokio_tungstenite::WebSocketStream`] from the `pipe` given by [`response_pipe_fut!`].
///
/// # Examples
///
/// See [`response()`].
///
/// # Errors
///
/// Errors if `pipe` is [unsupported](Error::WebSocketUnsupported).
pub async fn wrap(
    pipe: &mut ResponseBodyPipe,
) -> Result<tokio_tungstenite::WebSocketStream<WSStream<'_>>, Error> {
    match pipe {
        ResponseBodyPipe::Http1(s) => Ok(tokio_tungstenite::WebSocketStream::from_raw_socket(
            WSStream::Http1(s),
            tungstenite::protocol::Role::Server,
            None,
        )
        .await),
        #[cfg(feature = "http2")]
        ResponseBodyPipe::Http2(_, _) => Err(Error::WebSocketUnsupported),
        #[cfg(feature = "http3")]
        ResponseBodyPipe::Http3(_) => Err(Error::WebSocketUnsupported),
    }
}

//! Utility functions to provide solid solutions for common problems.
//!
//! This includes
//! - [`WriteableBytes`] for when you want to use [`Bytes`]
//!   as a [`Vec`], with tailored allocations
//! - [`CleanDebug`] to get the [`Display`] implementation when
//!   implementing [`Debug`] for a struct (see the Debug implementation for [`Host`])
//! - Async cached access to the file system
//! - Default errors which can be customised in `<host_dir>/errors/<status_code>.html`
//! - And several [`http`] helper functions.

use crate::prelude::*;

/// Turns a [`SanitizeError`] into a [`FatResponse`]
/// with `host`.
pub async fn sanitize_error_into_response(error: SanitizeError, host: &Host) -> FatResponse {
    default_response(
        match error {
            SanitizeError::UnsafePath => StatusCode::BAD_REQUEST,
            SanitizeError::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
        },
        host,
        match error {
            SanitizeError::UnsafePath => Some("path contains illegal segments (e.g. `./`)"),
            SanitizeError::RangeNotSatisfiable => None,
        },
    )
    .await
}

/// Default HTTP error used in Kvarn.
///
/// Gets the default error based on `code` from the file system
/// through a cache.
#[inline]
pub async fn default(
    code: StatusCode,
    host: Option<&Host>,
    message: Option<&[u8]>,
) -> Response<Bytes> {
    // Error files will be used several times.
    let body = match host {
        Some(host) => {
            let path = utils::make_path(&host.path, "errors", code.as_str(), Some("html"));

            match read_file_cached(&path, host.file_cache.as_ref()).await {
                Some(file) => file,
                None => utils::hardcoded_error_body(code, message),
            }
        }
        None => utils::hardcoded_error_body(code, message),
    };
    let mut builder = Response::builder()
        .status(code)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-encoding", "identity");
    if let Some(message) = message.map(HeaderValue::from_bytes).and_then(Result::ok) {
        builder = builder.header("reason", message);
    }
    // Unwrap is ok; I know it's valid
    builder.body(body).unwrap()
}

/// Get a error [`FatResponse`].
///
/// Can be very useful to return from [`extensions`].
#[inline]
pub async fn default_response(
    code: StatusCode,
    host: &Host,
    message: Option<&str>,
) -> FatResponse {
    FatResponse::cache(default(code, Some(host), message.map(str::as_bytes)).await)
        .with_server_cache(ServerCachePreference::None)
}

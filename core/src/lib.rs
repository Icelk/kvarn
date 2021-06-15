pub mod host;
pub mod limiting;
pub mod prelude;
pub mod utils;

pub use host::{Data, Host};
pub use utils::{AsCleanDebug, CleanDebug};

/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "windows")]
pub const SERVER: &str = "Kvarn/0.2.0 (Windows)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "macos")]
pub const SERVER: &str = "Kvarn/0.2.0 (macOS)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "linux")]
pub const SERVER: &str = "Kvarn/0.2.0 (Linux)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(target_os = "freebsd")]
pub const SERVER: &str = "Kvarn/0.2.0 (FreeBSD)";
/// The Kvarn `server` header.
/// Can also be used for identifying the client when using
/// Kvarn as a reverse-proxy.
#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd"
)))]
pub const SERVER: &str = "Kvarn/0.2.0 (unknown OS)";

//! ## The Kvarn Prelude
//!
//! The purpose of this module is to *simplify*, *make modules dependencies obvious*,
//! and *keep consistency* in the development of the Kvarn web server.
//!
//! Other specialised preludes can be found as modules, including
//! - a fs prelude
//! - a networking prelude
//! - an internals prelude
//! - a threading prelude

// Commonly used external dependencies
pub use bytes::{Bytes, BytesMut};
pub use http::{
    self, header, header::HeaderName, uri, HeaderMap, HeaderValue, Method, Request, Response,
    StatusCode, Uri, Version,
};
pub use log::*;
pub use mime::Mime;
pub use mime_guess;
pub use std::collections::HashMap;
pub use std::fmt::{self, Debug, Display, Formatter};
pub use std::io::{self, prelude::*};
pub use std::net::{self, IpAddr, SocketAddr};
pub use std::path::{Path, PathBuf};
pub use std::str;
pub use std::sync::Arc;
pub use std::time;
pub use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
pub use tokio::sync::Mutex;

// Modules
pub use crate::application;
pub use crate::comprash;
pub use crate::encryption;
pub use crate::extensions;
pub use crate::host;
pub use crate::limiting;
pub use crate::parse;
pub use crate::utility;

// Crate exports
pub use crate::Config;
pub use crate::*;
pub use comprash::UriKey;
pub use extensions::{Package, Post, Pre, Prepare, Present, Prime};
pub use host::{Host, HostData};
pub use utility::chars::*;
pub use utility::{read_file, read_file_cached};

/// File System prelude.
///
/// The purpose of this module is to expose common file system operations.
pub mod fs {
    use super::*;
    pub use tokio::fs::File;
    pub use utility::{read_file, read_file_cached};
}

/// Networking prelude.
///
/// The purpose of this module is to expose Tokio network types used in Kvarn.
pub mod networking {
    pub use tokio::net::{TcpListener, TcpStream};
}

/// Internal prelude.
///
/// The purpose of this module is to expose the commonly used internals of Kvarn.
///
/// **This is not part of the public API and may change rapidly**
pub mod internals {
    use super::*;
    pub use application::*;
    pub use comprash::{Cache, FileCache, PathQuery, ResponseCache};
    pub use encryption::Encryption;
    pub use extensions::{RetFut, RetSyncFut};
    pub use limiting::*;
    pub use tokio::time::{timeout, Duration};
    pub use utility::default_error;
}

/// Threading prelude.
///
/// The purpose of this module is to expose common threading types.
pub mod threading {
    pub use std::sync::atomic;
    pub use tokio::task::{spawn, spawn_blocking, spawn_local};
}

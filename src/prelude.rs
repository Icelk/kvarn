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

pub use kvarn_async::prelude::*;
pub use kvarn_utils::prelude::*;

// Commonly used external dependencies
pub use mime::Mime;
pub use mime_guess;

// Modules
pub use crate::application;
pub use crate::comprash;
pub use crate::encryption;
pub use crate::extensions;
pub use crate::host;
pub use crate::limiting;
pub use kvarn_async as async_bits;
pub use kvarn_utils as utils;

// Crate exports
pub use crate::*;
pub use comprash::UriKey;
pub use error::{default as default_error, default_response as default_error_response};
pub use extensions::{
    Cors, CorsAllowList, Package, Post, Prepare, Present, Prime, ResponsePipeFuture,
};
pub use host::{Data, Host};
pub use read::{file as read_file, file_cached as read_file_cached};
pub use shutdown::{AcceptAction, AcceptManager};
pub use utils::{build_bytes, chars::*, parse, parse::SanitizeError, AsCleanDebug};

/// **Prelude:** file system
///
/// The purpose of this module is to expose common file system operations.
pub mod fs {
    pub use super::async_bits::*;
    pub use super::read::{file as read_file, file_cached as read_file_cached};
    pub use tokio::fs::File;
}

/// **Prelude:** networking
///
/// The purpose of this module is to expose Tokio network types used in Kvarn.
pub mod networking {
    pub use super::async_bits::*;
    pub use tokio::net::{TcpListener, TcpSocket, TcpStream};
}

/// **Prelude:** internal
///
/// The purpose of this module is to expose the commonly used internals of Kvarn.
///
/// **This is not part of the public API and may change rapidly**
pub mod internals {
    use super::{application, async_bits, comprash, encryption, error, extensions, limiting};
    pub use application::{
        Body, HttpConnection, PushedResponsePipe, ResponseBodyPipe, ResponsePipe,
    };
    pub use async_bits::*;
    pub use comprash::{Cache, CacheOut, FileCache, PathQuery, ResponseCache};
    pub use encryption::Encryption;
    pub use error::default as default_error;
    pub use extensions::{ready, RetFut, RetSyncFut};
    pub use limiting::{Action as LimitAction, Manager as LimitManager};
    pub use tokio::time::timeout;
}

/// **Prelude:** internal
///
/// The purpose of this module is to expose common threading types.
pub mod threading {
    pub use std::sync::atomic::{self, Ordering};
    pub use std::task::{Context, Wake, Waker};
    pub use tokio::task::{spawn, spawn_blocking, spawn_local};
}

/// **Prelude:** time
///
/// Here, all relevant time items are imported.
pub mod time {
    pub use chrono::{
        Date, DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, NaiveTime, TimeZone,
        Timelike, Utc,
    };
}

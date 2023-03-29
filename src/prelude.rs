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
#[allow(unreachable_pub)] // incorrect lint?
pub use kvarn_utils::prelude::*;

// Modules
pub use crate::application;
pub use crate::comprash;
pub use crate::cors;
pub use crate::csp;
pub use crate::encryption;
pub use crate::extensions;
pub use crate::host;
pub use crate::limiting;
pub use crate::vary;
pub use kvarn_async as async_bits;
pub use kvarn_utils as utils;

// Crate exports
pub use crate::*;
pub use comprash::UriKey;
pub use cors::{AllowList as CorsAllowList, Cors};
pub use csp::{Csp, Rule as CspRule, Value as CspValue, ValueSet as CspValueSet};
pub use error::{default as default_error, default_response as default_error_response};
pub use extensions::{Package, Post, Prepare, Present, Prime, ResponsePipeFuture};
pub use host::{Collection as HostCollection, Host};
pub use read::{file as read_file, file_cached as read_file_cached};
pub use shutdown::{AcceptAction, AcceptManager};
pub use utils::{build_bytes, chars::*, parse, parse::SanitizeError, AsCleanDebug};

/// **Prelude:** file system
///
/// The purpose of this module is to expose common file system operations.
pub mod fs {
    pub use super::async_bits::*;
    pub use super::read::{file as read_file, file_cached as read_file_cached};
    pub use tokio_uring::fs::File;
}

/// **Prelude:** networking
///
/// The purpose of this module is to expose Tokio network types used in Kvarn.
pub mod networking {
    pub use super::async_bits::*;
    #[cfg(not(feature = "async-networking"))]
    pub use std::net::{TcpListener, TcpStream};
    #[cfg(feature = "async-networking")]
    pub use tokio_uring::net::{TcpListener, TcpStream};
    // pub use tokio::net::{TcpListener, TcpSocket, TcpStream};
}

/// **Prelude:** internal
///
/// The purpose of this module is to expose the commonly used internals of Kvarn.
///
/// **This is not part of the public API and may change rapidly**
pub mod internals {
    use super::{
        application, async_bits, comprash, encryption, error, extensions, limiting, utils, vary,
    };
    pub use application::{
        Body, HttpConnection, PushedResponsePipe, ResponseBodyPipe, ResponsePipe,
    };
    pub use async_bits::*;
    pub use comprash::{CacheOut, FileCache, MokaCache, PathQuery, ResponseCache};
    pub use encryption::Encryption;
    pub use error::default as default_error;
    pub use extensions::{ready, RetFut, RetSyncFut};
    pub use limiting::{Action as LimitAction, Manager as LimitManager};
    pub use mime::{self, Mime};
    pub use mime_guess;
    pub use tokio::time::timeout;
    pub use utils::{
        PresentArguments, PresentArgumentsIter, PresentExtensions, PresentExtensionsIter,
    };
    pub use vary::{VariedResponse, Vary};
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
/// Here, all relevant time items from [`time`] are imported.
pub mod chrono {
    pub use time::{self, ext::NumericalDuration, ext::NumericalStdDuration, OffsetDateTime};
}

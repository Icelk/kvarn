//! ## **The Kvarn Prelude**
//!
//! The purpose of this module is to *simplify*, *make modules dependencies obvious*, and *keep consistency* in the development of the *Kvarn web server*.
//!
//! Other niche preludes can be found as submodules, including
//! * a FS prelude
//! * a networking prelude
//! * a internal prelude
//! * a threading prelude
//! * a connection-struct prelude
//! * and a Rustls prelude

// External commonly used dependencies
pub use http;
pub use mime::Mime;
pub use mime_guess;
pub use num_cpus;
pub use std::borrow::Cow;
pub use std::collections::HashMap;
pub use std::ffi::{self, OsStr, OsString};
pub use std::fmt::{self, Debug, Display, Formatter};
pub use std::io;
pub use std::mem::MaybeUninit;
pub use std::net;
pub use std::path::{Path, PathBuf};
pub use std::str;
pub use std::sync::{self, Arc};
pub use std::time;

// Modules
pub use crate::bindings;
pub use crate::cache;
pub use crate::compression;
pub use crate::connection;
pub use crate::cryptography;
pub use crate::extensions;
#[cfg(feature = "limiting")]
pub use crate::limiting;
pub use crate::parse;
pub use crate::utility;

// Crate types
pub use crate::{Config, Storage};
pub use bindings::FunctionBindings;
pub use cache::{Cached, Cached::*};
pub use connection::{ConnectionScheme, ConnectionSecurity};
pub use cryptography::{Host, HostData};
pub use utility::chars::*;
pub use utility::{
    read_file, read_file_cached, to_option_str, write_error, write_generic_error, ContentType::*,
    SRO,
};

/// ## **The Kvarn *File System* Prelude**
///
/// The purpose of this module is to expose common file system operations.
pub mod fs {
    use super::*;
    pub use std::{
        fs::File,
        io::{self, prelude::*},
    };
    pub use utility::{read_file, read_file_cached};
}

/// ## **The Kvarn *Networking* Prelude**
///
/// The purpose of this module is to expose MetalIO network types used in Kvarn.
pub mod networking {
    use super::*;

    pub use connection::ConnectionHeader;
    #[cfg(feature = "limiting")]
    pub use limiting::LimitStrength;
    pub use mio::net::{TcpListener, TcpStream};
    pub use std::io::{Read, Write};
    pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
}

/// ## **The Kvarn *Cryptography* Prelude**
///
/// The purpose of this module is to help development of cryptographic functionality.
pub mod crypto {
    use super::*;

    pub use cryptography::{get_certified_key, Host, HostBinding, HostData};
}

/// ## **The Kvarn *Internal* Prelude**
///
/// The purpose of this module is to expose the commonly used internals of Kvarn.
///
/// **This is not intended to be user-facing and may change rapidly**
pub mod internals {
    use super::*;
    pub use cache::types::*;
    pub use cache::ByteResponse;
    pub use extensions::{BoundExtension, Extension, ExtensionMap, Extensions};
    #[cfg(feature = "limiting")]
    pub use limiting::LimitManager;
    pub use utility::default_error;
}

/// ## **The Kvarn *Threading* Prelude**
///
/// The purpose of this module is to expose common threading types.
pub mod threading {
    pub use std::sync::{self, atomic, Mutex, TryLockError};
    pub use std::thread;
}

/// ## **The Kvarn *Connection* Prelude**
///
/// The purpose of this module is to expose the internal connections types and operations.
pub mod con {
    use super::*;
    pub use connection::{Connection, ConnectionScheme, ConnectionSecurity};
}

/// ## **The Kvarn *Rustless* Prelude**
///
/// The purpose of this module is to expose the used Rustls structs and traits.
pub mod rustls_prelude {
    pub use rustls::{ServerConfig, ServerSession, Session};
}

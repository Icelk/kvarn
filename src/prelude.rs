//! ## **The Arktis Prelude**
//!
//! The purpose of this module is to *simplify*, *make modules dependencies obvious*, and *keep consistency* in the development of the Arktis web server.
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
pub use std::fmt;
pub use std::io;
pub use std::mem::MaybeUninit;
pub use std::net;
pub use std::path::{Path, PathBuf};
pub use std::str;
pub use std::sync::{self, Arc};

// Modules
pub use crate::bindings;
pub use crate::cache;
pub use crate::compression;
pub use crate::connection;
pub use crate::extensions;
pub use crate::parse;
pub use crate::utility;

// Crate types
pub use crate::chars::*;
pub use crate::tls_server_config::{get_server_config, optional_server_config};
pub use crate::{Config, Storage};
pub use bindings::FunctionBindings;
pub use cache::{Cached, Cached::*};
pub use connection::ConnectionSecurity;
pub use utility::{read_file, write_error, write_generic_error, ContentType::*};

/// ## **The Arktis *File System* Prelude**
///
/// The purpose of this module is to expose common file system operations.
pub mod fs {
    use super::*;
    pub use std::{
        fs::File,
        io::{self, prelude::*},
    };
    pub use utility::read_file;
}

/// ## **The Arktis *Networking* Prelude**
///
/// The purpose of this module is to expose MetalIO network types used in Arktis.
pub mod networking {
    pub use mio::net::{TcpListener, TcpStream};
}

/// ## **The Arktis *Internal* Prelude**
///
/// The purpose of this module is to expose the commonly used internals of Arktis.
///
/// **This is not intended to be user-facing and may change rapidly**
pub mod internals {
    use super::*;
    pub use cache::types::*;
    pub use cache::ByteResponse;
    pub use extensions::{BoundExtension, Extension, ExtensionMap, Extensions};
    pub use utility::default_error;
}

/// ## **The Arktis *Threading* Prelude**
///
/// The purpose of this module is to expose common threading types.
pub mod threading {
    pub use std::sync::Mutex;
    pub use std::thread;
}

/// ## **The Arktis *Connection* Prelude**
///
/// The purpose of this module is to expose the internal connections types and operations.
pub mod con {
    use super::*;
    pub use connection::{Connection, ConnectionSecurity};
}

/// ## **The Arktis *Rustless* Prelude**
///
/// The purpose of this module is to expose the used Rustls structs and traits.
pub mod rustls_prelude {
    pub use rustls::{ServerConfig, ServerSession, Session};
}

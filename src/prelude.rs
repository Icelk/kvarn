//! **The Arktis Prelude**
//!
//! The purpose of this module is to *simplify*, *make modules dependencies obvious*, and *keep consistency* in the development of the Arktis web server.
//!
//! A optional FS prelude can be found as a submodule

// External commonly used dependencies
pub use http;
pub use mime::Mime;
pub use mime_guess;
pub use mio::net::{TcpListener, TcpStream};
pub use num_cpus;
pub use std::borrow::Cow;
pub use std::collections::HashMap;
pub use std::fmt;
pub use std::io;
pub use std::mem::MaybeUninit;
pub use std::net;
pub use std::path::{Path, PathBuf};
pub use std::str;
pub use std::sync::{self, Arc, Mutex};

// Modules
pub use crate::bindings;
pub use crate::cache;
pub use crate::compression;
pub use crate::connection;
pub use crate::extensions;
pub use crate::parse;
pub use crate::prelude;
pub use crate::utility;

// Crate types
pub use crate::*;
pub use bindings::{
    ContentType::{self, *},
    FunctionBindings,
};
pub use cache::types::*;
pub use cache::{
    ByteResponse,
    Cached::{self, *},
};
pub use chars::*;
pub use connection::{Connection, ConnectionSecurity};
pub use extensions::{BoundExtension, Extension, ExtensionMap, Extensions};
pub use tls_server_config::{get_server_config, optional_server_config};
pub use utility::{read_file, write_error, write_generic_error};

/// **The Arktis *File System* Prelude**
///
/// The purpose of this module is to expose common file system operations.
pub mod fs {
    pub use std::{
        fs::File,
        io::{self, prelude::*},
    };
}

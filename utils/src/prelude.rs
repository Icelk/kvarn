//! The prelude for common web application utilities.
//!
//! This should contains the most commonly used items in [`std`], [`http`], [`mod@log`], and [`bytes`].
//! It also exports all the items in [`crate`].

pub use bytes::{self, Bytes, BytesMut};
pub use compact_str::{self, format_compact, CompactString, ToCompactString};
pub use http::{
    header, header::HeaderName, uri, HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    Uri, Version,
};
pub use log::{debug, error, info, log, trace, warn};
pub use std::borrow::Cow;
pub use std::cmp::{self, Ord, PartialOrd};
pub use std::collections::HashMap;
pub use std::convert::TryFrom;
pub use std::fmt::{self, Debug, Display, Formatter};
pub use std::io::{self, prelude::*};
pub use std::net::{self, IpAddr, SocketAddr};
pub use std::path::{Path, PathBuf};
pub use std::str;
pub use std::sync::Arc;
pub use std::time::{Duration, Instant};

pub use crate::{build_bytes, chars, extensions, parse, AsCleanDebug, WriteableBytes};

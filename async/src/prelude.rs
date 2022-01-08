//! Prelude for async utilities for use in web applications.
//!
//! This includes all the imports from [`kvarn_utils::prelude`].
//! It also imports async-related [`std`] items and the common [`tokio`] items.

pub use kvarn_utils as utils;
pub use kvarn_utils::prelude::*;
pub use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
pub use tokio::sync::{Mutex, RwLock};

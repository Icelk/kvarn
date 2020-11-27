use crate::prelude::{fs::*, internals::*, *};

pub mod chars {
    /// Line feed
    pub const LF: u8 = 10;
    /// Carrage return
    pub const CR: u8 = 13;
    /// ` `
    pub const SPACE: u8 = 32;
    /// `!`
    pub const BANG: u8 = 33;
    /// `&`
    pub const AMPERSAND: u8 = 38;
    /// `>`
    pub const PIPE: u8 = 62;
    /// `[`
    pub const L_SQ_BRACKET: u8 = 91;
    /// `\`
    pub const ESCAPE: u8 = 92;
    /// `]`
    pub const R_SQ_BRACKET: u8 = 93;
}

#[cfg(not(feature = "no-fs-cache"))]
pub fn read_file(path: &PathBuf, cache: &mut FsCache) -> Option<Arc<Vec<u8>>> {
    match cache.try_lock() {
        Ok(lock) => {
            if let Some(cached) = lock.get(path) {
                return Some(cached);
            }
        }
        Err(ref err) => match err {
            sync::TryLockError::Poisoned(..) => {
                panic!("File System cache is poisoned!");
            }
            sync::TryLockError::WouldBlock => {}
        },
    }

    match File::open(path) {
        Ok(mut file) => {
            let mut buffer = Vec::with_capacity(4096);
            match file.read_to_end(&mut buffer) {
                Ok(..) => {
                    let buffer = Arc::new(buffer);
                    match cache.try_lock() {
                        Ok(mut lock) => match lock.cache(path.clone(), buffer) {
                            Err(failed) => Some(failed),
                            Ok(()) => Some(lock.get(path).unwrap()),
                        },
                        Err(ref err) => match err {
                            sync::TryLockError::Poisoned(..) => {
                                panic!("File System cache is poisoned!");
                            }
                            sync::TryLockError::WouldBlock => Some(buffer),
                        },
                    }
                }
                Err(..) => None,
            }
        }
        Err(..) => None,
    }
}
#[cfg(feature = "no-fs-cache")]
pub fn read_file(path: &PathBuf, _: &mut FsCache) -> Option<Arc<Vec<u8>>> {
    match File::open(path) {
        Ok(mut file) => {
            let mut buffer = Vec::with_capacity(4096);
            match file.read_to_end(&mut buffer) {
                Ok(..) => {
                    return Some(Arc::new(buffer));
                }
                Err(..) => None,
            }
        }
        Err(..) => None,
    }
}

#[inline]
pub fn read_to_end(
    bytes: &mut [u8],
    reader: &mut dyn io::Read,
    emit_close: bool,
) -> Result<usize, io::Error> {
    let mut read = 0;
    loop {
        match reader.read(&mut bytes[read..]) {
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                std::thread::yield_now();
                continue;
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => {
                return Err(err);
            }
            Ok(0) => match emit_close {
                true => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "unexpectedly read zero bytes from source",
                    ))
                }
                false => break,
            },
            Ok(rd) => read += rd,
        }
    }
    Ok(read)
}

pub fn default_error(
    code: u16,
    close: &connection::ConnectionHeader,
    cache: Option<&mut FsCache>,
) -> ByteResponse {
    let mut buffer = Vec::with_capacity(512);
    buffer.extend(b"HTTP/1.1 ");
    buffer.extend(
        format!(
            "{}\r\n",
            http::StatusCode::from_u16(code).unwrap_or(http::StatusCode::from_u16(500).unwrap())
        )
        .as_bytes(),
    );
    buffer.extend(
        &b"Content-Type: text/html\r\n\
        Connection: "[..],
    );
    if close.close() {
        buffer.extend(b"Close\r\n");
    } else {
        buffer.extend(b"Keep-Alive\r\n");
    }
    buffer.extend(b"Content-Encoding: identity\r\n");

    let body = match cache
        .and_then(|cache| read_file(&PathBuf::from(format!("{}.html", code)), cache))
    {
        Some(file) => {
            buffer.extend(b"Content-Length: ");
            buffer.extend(format!("{}\r\n\r\n", file.len()).as_bytes());
            // buffer.extend(file.get_body());
            (*file).clone()
        }
        None => {
            let mut body = Vec::with_capacity(1024);
            // let error = get_default(code);
            match code {
                _ => {
                    // Get code and reason!
                    let status = http::StatusCode::from_u16(code).ok();
                    let write_code = |body: &mut Vec<_>| match status {
                        #[inline]
                        Some(status) => body.extend(status.as_str().as_bytes()),
                        None => body.extend(code.to_string().as_bytes()),
                    };
                    let reason = status.and_then(|status| status.canonical_reason());

                    body.extend(b"<html><head><title>");
                    // Code and reason
                    write_code(&mut body);
                    body.extend(b" ");
                    if let Some(reason) = reason {
                        body.extend(reason.as_bytes());
                    }

                    body.extend(&b"</title></head><body><center><h1>"[..]);
                    // Code and reason
                    write_code(&mut body);
                    body.extend(b" ");
                    if let Some(reason) = reason {
                        body.extend(reason.as_bytes());
                    }
                    body.extend(&b"</h1><hr>An unexpected error occurred. <a href='/'>Return home</a>?</center></body></html>"[..]);
                }
            }

            buffer.extend(b"Content-Length: ");
            buffer.extend(format!("{}\r\n\r\n", body.len()).as_bytes());
            // buffer.append(&mut body);
            body
        }
    };

    ByteResponse::Both(buffer, body, false)
}

/// Writes a generic error to `buffer`.
/// For the version using the file system to deliver error messages, use `write_error`.
///
/// Returns (`text/html`, `Cached::Static`) to feed to binding closure.
/// If you don't want it to cache, construct a custom return value.
///
/// # Examples
/// ```
/// use kvarn::{FunctionBindings, write_generic_error};
///
/// let mut bindings = FunctionBindings::new();
///
/// bindings.bind_page("/throw_500", |mut buffer, _, _| {
///   write_generic_error(&mut buffer, 500)
/// });
/// ```
pub fn write_generic_error(buffer: &mut Vec<u8>, code: u16) -> (ContentType, Cached) {
    default_error(code, &connection::ConnectionHeader::KeepAlive, None)
        .write_all(buffer)
        .expect("Failed to write to vec!");
    (ContentType::Html, Cached::Dynamic)
}
/// Writes a error to `buffer`.
/// For the version not using the file system, but generic hard-coded errors, use `write_generic_error`.
///
/// Returns (`text/html`, `Cached::Static`) to feed to binding closure.
/// If you don't want it to cache, construct a custom return value.
///
/// # Examples
/// ```
/// use kvarn::{FunctionBindings, write_error};
///
/// let mut bindings = FunctionBindings::new();
///
/// bindings.bind_page("/throw_500", |mut buffer, _, storage| {
///   write_error(&mut buffer, 500, storage)
/// });
/// ```
pub fn write_error(buffer: &mut Vec<u8>, code: u16, cache: &mut FsCache) -> (ContentType, Cached) {
    default_error(code, &connection::ConnectionHeader::KeepAlive, Some(cache))
        .write_all(buffer)
        .expect("Failed to write to vec!");
    (ContentType::Html, Cached::Dynamic)
}

/// Strips the `vec` from first `split_at` elements, dropping them and returning a `Vec` of the items after `split_at`.
///
/// # Panics
/// Panics if `split_at` is greater than `len()`, since then it would drop uninitialized memory.
pub fn into_last<T>(mut vec: Vec<T>, split_at: usize) -> Vec<T> {
    let p = vec.as_mut_ptr();
    let len = vec.len();
    let cap = vec.capacity();

    assert!(split_at < len);

    unsafe {
        use std::ptr;
        // Drop slice
        ptr::drop_in_place(ptr::slice_from_raw_parts_mut(p, split_at));
        Vec::from_raw_parts(p.offset(split_at as isize), len - split_at, cap - split_at)
    }
}
/// Strips the `vec` from first `split_at` elements, dropping them and returning a `Vec` of the items after `split_at`.
///
/// # Panics
/// Panics if `split_at` is greater than `len()`, since then it would drop uninitialized memory.
pub fn into_two<T>(mut vec: Vec<T>, split_at: usize) -> (Vec<T>, Vec<T>) {
    let p = vec.as_mut_ptr();
    let len = vec.len();
    let cap = vec.capacity();

    assert!(split_at < len);

    unsafe {
        let first_vec = Vec::from_raw_parts(p, split_at, split_at);
        let last_vec =
            Vec::from_raw_parts(p.offset(split_at as isize), len - split_at, cap - split_at);
        (first_vec, last_vec)
    }
}

#[derive(Debug)]
pub enum ContentType {
    FromMime(Mime),
    Html,
    PlainText,
    Download,
    AutoOrDownload,
    AutoOrPlain,
    AutoOrHTML,
}
impl ContentType {
    pub fn as_str<P: AsRef<Path>>(&self, path: P) -> Cow<'static, str> {
        match self {
            ContentType::FromMime(mime) => Cow::Owned(format!("{}", mime)),
            ContentType::Html => Cow::Borrowed("text/html"),
            ContentType::PlainText => Cow::Borrowed("text/plain"),
            ContentType::Download => Cow::Borrowed("application/octet-stream"),
            ContentType::AutoOrDownload => Cow::Owned(format!(
                "{}",
                mime_guess::from_path(&path).first_or_octet_stream()
            )),
            ContentType::AutoOrPlain => Cow::Owned(format!(
                "{}",
                mime_guess::from_path(&path).first_or_text_plain()
            )),
            ContentType::AutoOrHTML => Cow::Owned(format!(
                "{}",
                mime_guess::from_path(&path).first_or(mime::TEXT_HTML)
            )),
        }
    }
    pub fn as_str_utf8<P: AsRef<Path>>(&self, path: P, is_valid_utf8: bool) -> Cow<'static, str> {
        if is_valid_utf8 {
            match self {
                ContentType::FromMime(mime) => Cow::Owned(format!("{}; charset=utf-8", mime)),
                ContentType::Html => Cow::Borrowed("text/html; charset=utf-8"),
                ContentType::PlainText => Cow::Borrowed("text/plain; charset=utf-8"),
                ContentType::Download => Cow::Borrowed("application/octet-stream"),
                ContentType::AutoOrDownload => {
                    let mime = mime_guess::from_path(&path).first_or_octet_stream();
                    match mime.type_().as_str() {
                        "text" => Cow::Owned(format!("{}; charset=utf-8", mime)),
                        _ => Cow::Owned(format!("{}", mime)),
                    }
                }
                ContentType::AutoOrPlain => {
                    let mime = mime_guess::from_path(&path).first_or_text_plain();
                    match mime.type_().as_str() {
                        "text" => Cow::Owned(format!("{}; charset=utf-8", mime)),
                        _ => Cow::Owned(format!("{}", mime)),
                    }
                }
                ContentType::AutoOrHTML => {
                    let mime = mime_guess::from_path(&path).first_or(mime::TEXT_HTML);
                    match mime.type_().as_str() {
                        "text" => Cow::Owned(format!("{}; charset=utf-8", mime)),
                        _ => Cow::Owned(format!("{}", mime)),
                    }
                }
            }
        } else {
            self.as_str(path)
        }
    }
}
impl Default for ContentType {
    fn default() -> Self {
        Self::AutoOrDownload
    }
}

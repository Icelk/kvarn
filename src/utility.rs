use crate::{
    comprash::FileCache,
    prelude::{fs::*, internals::*, *},
};

pub const BUFFER_SIZE: usize = 1024 * 8;

pub mod chars {
    /// Tab
    pub const TAB: u8 = 9;
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
    /// `.`
    pub const PERIOD: u8 = 46;
    /// `/`
    pub const FORWARD_SLASH: u8 = 47;
    /// `:`
    pub const COLON: u8 = 58;
    /// `>`
    pub const PIPE: u8 = 62;
    /// `[`
    pub const L_SQ_BRACKET: u8 = 91;
    /// `\`
    pub const ESCAPE: u8 = 92;
    /// `]`
    pub const R_SQ_BRACKET: u8 = 93;
}

/// Should only be used when a file is typically access several times or from several requests.
#[cfg(not(feature = "no-fs-cache"))]
pub fn read_file_cached<P: AsRef<Path>>(path: &P, cache: &FileCache) -> Option<Arc<Vec<u8>>> {
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
/// Should only be used when a file is typically access several times or from several requests.
///
/// ToDo: optimize!
pub async fn read_file_cached<P: AsRef<Path>>(path: &P, _: &FileCache) -> Option<Bytes> {
    let mut file = File::open(path).await.ok()?;
    let mut buffer = BytesMut::with_capacity(4096);
    unsafe { buffer.set_len(buffer.capacity()) };
    let mut read = 0;
    loop {
        match file.read(&mut buffer[..]).await {
            Ok(0) => break,
            Ok(len) => {
                read += len;
                if read > buffer.len() - 512 {
                    buffer.reserve(2048);
                }
            }
            Err(_) => return None,
        }
    }
    unsafe { buffer.set_len(read) };
    Some(buffer.freeze())
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// Shared Reference or Owned defines either a Arc<T> or T.
pub enum SRO<T, B: std::ops::Deref<Target = T>> {
    Shared(B),
    Owned(T),
}
impl<T, B: std::ops::Deref<Target = T>> SRO<T, B> {
    pub fn into_owned(self) -> T
    where
        T: Clone,
    {
        match self {
            SRO::Shared(arc) => (*arc).clone(),
            SRO::Owned(value) => value,
        }
    }
}
impl<T, B: std::ops::Deref<Target = T>> std::ops::Deref for SRO<T, B> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            SRO::Shared(arc) => &**arc,
            SRO::Owned(value) => value,
        }
    }
}
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
///
/// It can prevent one `clone` if only used once, else results in several system calls.
#[cfg(not(feature = "no-fs-cache"))]
pub async fn read_file(path: &PathBuf, cache: &FileCache) -> Option<SRO<Vec<u8>, Arc<Vec<u8>>>> {
    if let Some(cached) = cache.lock().await.get(path) {
        return Some(SRO::Shared(Arc::clone(cached)));
    }

    match File::open(path).await {
        Ok(mut file) => {
            let mut buffer = Vec::with_capacity(4096);
            match file.read_to_end(&mut buffer).await {
                Ok(..) => Some(SRO::Owned(buffer)),
                Err(..) => None,
            }
        }
        Err(..) => None,
    }
}
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
///
/// It can prevent one `clone` if only used once, else results in several system calls.
#[cfg(feature = "no-fs-cache")]
pub async fn read_file(path: &PathBuf, _: &mut FileCache) -> Option<SRO<Vec<u8>, Arc<Vec<u8>>>> {
    match File::open(path).await {
        Ok(mut file) => {
            let mut buffer = Vec::with_capacity(4096);
            match file.read_to_end(&mut buffer).await {
                Ok(..) => {
                    return Some(SRO::Owned(buffer));
                }
                Err(..) => None,
            }
        }
        Err(..) => None,
    }
}

pub fn hardcoded_error_body(code: http::StatusCode) -> Bytes {
    let mut body = BytesMut::with_capacity(1024);
    match code {
        _ => {
            // Get code and reason!
            let reason = code.canonical_reason();

            body.extend(b"<html><head><title>");
            // Code and reason
            body.extend(code.as_str().as_bytes());
            body.extend(b" ");
            if let Some(reason) = reason {
                body.extend(reason.as_bytes());
            }

            body.extend(&b"</title></head><body><center><h1>"[..]);
            // Code and reason
            body.extend(code.as_str().as_bytes());
            body.extend(b" ");
            if let Some(reason) = reason {
                body.extend(reason.as_bytes());
            }
            body.extend(&b"</h1><hr>An unexpected error occurred. <a href='/'>Return home</a>?</center></body></html>"[..]);
        }
    }

    body.freeze()
}

pub async fn default_error(
    code: http::StatusCode,
    close: &connection::ConnectionHeader,
    cache: Option<&FileCache>,
) -> http::Response<Bytes> {
    // Error files will be used several times.
    let body = match cache {
        Some(cache) => {
            match read_file_cached(&PathBuf::from(format!("{}.html", code.as_str())), cache).await {
                Some(file) => file,
                None => hardcoded_error_body(code),
            }
        }
        None => hardcoded_error_body(code),
    };
    http::Response::builder()
        .status(code)
        .header("content-type", "text/html; charset=utf-8")
        .header("connection", close.as_bytes())
        .header("content-encoding", "identity")
        .body(body)
        .unwrap()
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

pub fn to_option_str(header: &http::HeaderValue) -> Option<&str> {
    header.to_str().ok()
}

pub fn empty_clone_response<T>(response: &http::Response<T>) -> http::Response<()> {
    let mut builder = http::Response::builder()
        .version(response.version())
        .status(response.status());
    // match builder.headers_mut() {
    //     Some(headers) => *headers = response.headers().clone(),
    //     None => {}
    // };
    *builder.headers_mut().unwrap() = response.headers().clone();
    builder.body(()).unwrap()
}
pub fn empty_clone_request<T>(request: &http::Request<T>) -> http::Request<()> {
    let mut builder = http::Request::builder()
        .method(request.method())
        .version(request.version())
        .uri(request.uri().clone());
    *builder.headers_mut().unwrap() = request.headers().clone();
    builder.body(()).unwrap()
}

pub fn replace_header<K: http::header::IntoHeaderName + Copy>(
    headers: &mut http::HeaderMap,
    name: K,
    new: http::HeaderValue,
) {
    match headers.entry(name) {
        http::header::Entry::Vacant(slot) => {
            slot.insert(new);
        }
        http::header::Entry::Occupied(slot) => {
            slot.remove_entry_mult();
            headers.insert(name, new);
        }
    }
}

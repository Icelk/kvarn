use crate::{
    comprash::{ClientCachePreference, CompressPreference, FileCache, ServerCachePreference},
    extensions::Response,
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

pub struct WriteableBytes {
    bytes: BytesMut,
    len: usize,
}
impl WriteableBytes {
    pub fn new(mut bytes: BytesMut) -> Self {
        let len = bytes.len();
        unsafe { bytes.set_len(bytes.capacity()) };
        Self { len, bytes }
    }
    pub fn into_inner(mut self) -> BytesMut {
        unsafe { self.bytes.set_len(self.len) };
        self.bytes
    }
}
impl Write for WriteableBytes {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.len + buf.len() > self.bytes.capacity() {
            self.bytes.reserve(buf.len() + 512);
            unsafe { self.bytes.set_len(self.bytes.capacity()) };
        }
        self.bytes[self.len..self.len + buf.len()].copy_from_slice(buf);
        self.len += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// ToDo: optimize!
async fn read_to_end<R: AsyncRead + Unpin>(mut file: R, capacity: usize) -> io::Result<BytesMut> {
    let mut buffer = BytesMut::with_capacity(capacity);
    unsafe { buffer.set_len(buffer.capacity()) };
    let mut read = 0;
    loop {
        match file.read(&mut buffer[read..]).await? {
            0 => break,
            len => {
                read += len;
                if read > buffer.len() - 512 {
                    buffer.reserve(2048);
                    unsafe { buffer.set_len(buffer.capacity()) };
                }
            }
        }
    }
    unsafe { buffer.set_len(read) };
    Ok(buffer)
}

/// Should only be used when a file is typically access several times or from several requests.
#[cfg(not(feature = "no-fs-cache"))]
pub async fn read_file_cached<P: AsRef<Path>>(path: &P, cache: &FileCache) -> Option<Bytes> {
    if let Some(file) = cache.lock().await.get(path.as_ref()) {
        return Some(Bytes::clone(file));
    }

    let file = File::open(path).await.ok()?;
    let buffer = read_to_end(file, 4096).await.ok()?;
    let buffer = buffer.freeze();
    cache
        .lock()
        .await
        .cache(path.as_ref().to_path_buf(), Bytes::clone(&buffer));
    Some(buffer)
}
#[cfg(feature = "no-fs-cache")]
/// Should only be used when a file is typically access several times or from several requests.
pub async fn read_file_cached<P: AsRef<Path>>(path: &P, _: &FileCache) -> Option<Bytes> {
    let file = File::open(path).await.ok()?;
    read_to_end(file, 4096).await.ok().map(BytesMut::freeze)
}

/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
///
/// It can prevent one `clone` if only used once, else results in several system calls.
#[cfg(not(feature = "no-fs-cache"))]
pub async fn read_file<P: AsRef<Path>>(path: &P, cache: &FileCache) -> Option<Bytes> {
    if let Some(cached) = cache.lock().await.get(path.as_ref()) {
        return Some(Bytes::clone(cached));
    }

    let file = File::open(path).await.ok()?;
    read_to_end(file, 4096).await.ok().map(BytesMut::freeze)
}
/// Should be used when a file is typically only accessed once, and cached in the response cache, not files multiple requests often access.
#[cfg(feature = "no-fs-cache")]
pub async fn read_file<P: AsRef<Path>>(path: &P, _: &FileCache) -> Option<Bytes> {
    let file = File::open(path).await.ok()?;
    read_to_end(file, 4096).await.ok().map(BytesMut::freeze)
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
        .header("content-encoding", "identity")
        .body(body)
        .unwrap()
}

pub async fn default_error_response(code: http::StatusCode, host: &Host) -> Response {
    (
        default_error(code, Some(&host.file_cache)).await,
        ClientCachePreference::Full,
        ServerCachePreference::None,
        CompressPreference::Full,
    )
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
pub fn replace_header_static<K: http::header::IntoHeaderName + Copy>(
    headers: &mut http::HeaderMap,
    name: K,
    new: &'static str,
) {
    replace_header(headers, name, http::HeaderValue::from_static(new))
}

pub fn valid_method(bytes: &[u8]) -> bool {
    bytes.starts_with(b"GET")
        || bytes.starts_with(b"HEAD")
        || bytes.starts_with(b"POST")
        || bytes.starts_with(b"PUT")
        || bytes.starts_with(b"DELETE")
        || bytes.starts_with(b"TRACE")
        || bytes.starts_with(b"OPTIONS")
        || bytes.starts_with(b"CONNECT")
        || bytes.starts_with(b"PATCH")
}

pub struct CleanDebug<'a, T: ?Sized + Display>(&'a T);
impl<'a, T: ?Sized + Display> CleanDebug<'a, T> {
    pub fn new(value: &'a T) -> Self {
        Self(value)
    }
}
impl<'a, T: ?Sized + Display> Debug for CleanDebug<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, f)
    }
}
impl<'a, T: ?Sized + Display> Display for CleanDebug<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, f)
    }
}

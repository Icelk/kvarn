// #![warn(missing_docs, missing_debug_implementations, unreachable_pub)]

// Module declaration
pub mod bindings;
pub mod cache;
pub mod compression;
pub mod connection;
pub mod cryptography;
pub mod encryption;
pub mod extensions;
#[cfg(feature = "limiting")]
pub mod limiting;
pub mod parse;
pub mod prelude;
pub mod transport;
pub mod utility;

use net::SocketAddrV4;
use prelude::{internals::*, networking::*, threading::*, *};

use rustls::ServerConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
// When user only imports crate::* and not crate::prelude::*
pub use utility::{read_file, write_error, write_generic_error};

#[cfg(target_os = "windows")]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (Windows)\r\n";
#[cfg(target_os = "macos")]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (macOS)\r\n";
#[cfg(target_os = "linux")]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (Linux)\r\n";
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub const SERVER_HEADER: &[u8] = b"Server: Kvarn/0.1.0 (unknown OS)\r\n";
pub const SERVER_NAME: &str = "Kvarn";
pub const LINE_ENDING: &[u8] = b"\r\n";

async fn main<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    _address: &net::SocketAddr,
    host: Arc<HostDescriptor>,
) -> io::Result<()> {
    let _buffer = encryption::decrypt(stream, &host.r#type).await.unwrap();

    Ok(())
}

#[derive(Debug)]
pub struct HostDescriptor {
    port: u16,
    r#type: ConnectionSecurity,
    host_data: Arc<HostData>,
}
impl HostDescriptor {
    pub fn http_1(host: Arc<HostData>) -> Self {
        Self {
            port: 80,
            r#type: ConnectionSecurity::http1(),
            host_data: host,
        }
    }
    pub fn https_1(host: Arc<HostData>, security: Arc<ServerConfig>) -> Self {
        Self {
            port: 443,
            r#type: ConnectionSecurity::http1s(security),
            host_data: host,
        }
    }
    pub fn new(port: u16, host: Arc<HostData>, security: ConnectionSecurity) -> Self {
        Self {
            port,
            r#type: security,
            host_data: host,
        }
    }
}

#[derive(Debug)]
pub struct Config {
    sockets: Vec<HostDescriptor>,
    storage: Storage,
    extensions: Extensions,
}
impl Config {
    pub fn new(descriptors: Vec<HostDescriptor>) -> Self {
        Config {
            sockets: descriptors,
            storage: Storage::new(),
            extensions: Extensions::new(),
        }
    }

    /// Clones the Storage of this config, returning an owned reference-counted struct containing all caches and bindings
    pub fn clone_storage(&self) -> Storage {
        Storage::clone(&self.storage)
    }

    pub fn add_extension(&mut self, ext: BoundExtension) {
        self.extensions.add_extension(ext);
    }
    pub fn mount_extension<F: Fn() -> BoundExtension>(&mut self, external_extension: F) {
        self.extensions.add_extension(external_extension());
    }

    /// Runs a server from the config on a new thread, not blocking the current thread.
    ///
    /// Use a loop to capture the main thread.
    ///
    /// # Examples
    /// ```no_run
    /// use kvarn::prelude::*;
    /// use std::io::{stdin, BufRead};
    /// use std::thread;
    ///
    /// let server = Config::on_ports(&[(443, ConnectionScheme::HTTP1S)]);
    /// let mut storage = server.clone_storage();
    ///
    /// thread::spawn(move || server.run());
    ///
    /// for line in stdin().lock().lines() {
    ///     if let Ok(line) = line {
    ///         let mut words = line.split(" ");
    ///         if let Some(command) = words.next() {
    ///             match command {
    ///                 "cfc" => match storage.try_fs() {
    ///                      Some(mut lock) => {
    ///                          lock.clear();
    ///                          println!("Cleared file system cache!");
    ///                      }
    ///                      None => println!("File system cache in use by server!"),
    ///                  },
    ///                  "crc" => match storage.try_response() {
    ///                      Some(mut lock) => {
    ///                          lock.clear();
    ///                          println!("Cleared response cache!");
    ///                      }
    ///                      None => println!("Response cache in use by server!"),
    ///                  },
    ///                 _ => {
    ///                     eprintln!("Unknown command!");
    ///                 }
    ///             }
    ///         }
    ///     };
    /// };
    ///
    /// ```
    pub async fn run(self) -> Vec<tokio::task::JoinHandle<()>> {
        trace!("Running from config");

        let mut tasks = Vec::new();

        for descriptor in self.sockets {
            let listener =
                TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, descriptor.port))
                    .await
                    .expect("Failed to bind to port");

            let storage = Storage::clone(&self.storage);

            tasks.push(tokio::spawn(async move {
                Self::accept(listener, descriptor, storage)
                    .await
                    .expect("Failed to accept message!")
            }));
        }
        tasks
    }

    async fn accept(
        listener: TcpListener,
        host: HostDescriptor,
        mut storage: Storage,
    ) -> Result<(), io::Error> {
        trace!("Started listening on {:?}", listener.local_addr());
        let host = Arc::new(host);
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    #[cfg(feature = "limiting")]
                    match storage.register(addr) {
                        LimitStrength::Send | LimitStrength::Drop => {
                            drop(socket);
                            return Ok(());
                        }
                        LimitStrength::Passed => {}
                    }
                    let host = Arc::clone(&host);
                    tokio::spawn(async move {
                        main(socket, &addr, host)
                            .await
                            .expect("Failed with main fn");
                    });
                    continue;
                }
                Err(err) => {
                    // An error occurred
                    error!("Failed to accept() on listener");

                    return Err(err);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Storage {
    fs: FsCache,
    #[cfg(feature = "limiting")]
    limits: LimitManager,
}
impl Storage {
    pub fn new() -> Self {
        Storage {
            fs: Arc::new(Mutex::new(cache::Cache::with_max_size(65536))),
            #[cfg(feature = "limiting")]
            limits: LimitManager::default(),
        }
    }
    pub fn from_cache(fs: FsCache) -> Self {
        Storage {
            fs,
            #[cfg(feature = "limiting")]
            limits: LimitManager::default(),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.fs.lock().unwrap().clear();
    }

    /// Tries to get the lock of file cache.
    ///
    /// Always remember to handle the case if the lock isn't acquired; just don't return `None`!
    #[inline]
    pub fn try_fs(&mut self) -> Option<sync::MutexGuard<'_, FsCacheInner>> {
        #[cfg(feature = "no-fs-cache")]
        return None;
        #[cfg(not(feature = "no-fs-cache"))]
        match self.fs.try_lock() {
            Ok(lock) => Some(lock),
            Err(ref err) => match err {
                sync::TryLockError::WouldBlock => None,
                sync::TryLockError::Poisoned(..) => panic!("Lock is poisoned!"),
            },
        }
    }
    #[inline]
    pub fn get_fs(&mut self) -> &mut FsCache {
        &mut self.fs
    }

    #[cfg(feature = "limiting")]
    #[inline]
    pub fn register(&mut self, addr: SocketAddr) -> LimitStrength {
        self.limits.register(addr)
    }
}
impl Clone for Storage {
    fn clone(&self) -> Self {
        Storage {
            fs: Arc::clone(&self.fs),
            #[cfg(feature = "limiting")]
            limits: LimitManager::clone(&self.limits),
        }
    }
}

/// The main request processing function.
///
/// First checks if something's in cache, then write it to the socket and return.
///
/// Then, check if a binding is available. If one is, give it a `Vec` to populate. Wrap that `Vec` in a `ByteResponse` to get separation between body and head.
/// If not, get from the FS instead, and wrap in `Arc` inside a `ByteResponse`. Sets appropriate content type and cache settings.
///
/// Then matches content type to get a `str`.
///
/// Checks extension in body of `ByteResponse`.
pub(crate) fn process_request<W: io::Write>(
    socket: &mut W,
    address: &net::SocketAddr,
    request: http::Request<&[u8]>,
    raw_request: &[u8],
    close: &ConnectionHeader,
    storage: &mut Storage,
    extensions: &mut ExtensionMap,
    host: &Host,
    scheme: ConnectionScheme,
) -> Result<(), io::Error> {
    let is_get = match request.method() {
        &http::Method::GET | &http::Method::HEAD => true,
        _ => false,
    };

    // println!("Got request: {:?}", &request);
    if is_get {
        // Load from cache
        // Try get response cache lock
        if let Some(lock) = host.get_cache() {
            // If response is in cache
            if let Some(response) = lock.resolve(request.uri(), request.headers()) {
                // println!("Got cache! {}", request.uri());
                return response.write_as_method(socket, request.method());
            }
        }
    }
    let mut allowed_method = is_get;

    // Get from function or cache, to enable processing (extensions) from functions!
    let path = match parse::convert_uri(
        request.uri().path(),
        host.path.as_path(),
        host.get_folder_default_or("index.html"),
        host.get_extension_default_or("html"),
    ) {
        Some(path) => path,
        None => {
            &default_error(400, close, Some(storage.get_fs())).write_all(socket)?;
            return Ok(());
        }
    };

    // Extensions need body and cache setting to be mutable; to replace it.
    // Used to bypass immutable/mutable rule. It is safe because the binding reference isn't affected by changing the cache.
    let cache: *mut Storage = storage;
    let (mut byte_response, mut content_type, mut cached) = {
        let binding = match scheme {
            ConnectionScheme::HTTP1 | ConnectionScheme::WS => host
                .get_binding_overrides()
                .and_then(|bindings| bindings.get_binding(request.uri().path())),
            _ => None,
        };
        if let Some(binding) = binding {
            let mut response = Vec::with_capacity(2048);
            let (content_type, cache) =
                binding(&mut response, &request, unsafe { (*cache).get_fs() });

            allowed_method = true;
            // Check if callback contains headers. Change to response struct in future!
            if &response[..5] == b"HTTP/" {
                (ByteResponse::with_header(response), content_type, cache)
            } else {
                (ByteResponse::without_header(response), content_type, cache)
            }
        } else if let Some(binding) = host.get_bindings().get_binding(request.uri().path()) {
            let mut response = Vec::with_capacity(2048);
            let (content_type, cache) =
                binding(&mut response, &request, unsafe { (*cache).get_fs() });

            allowed_method = true;
            // Check if callback contains headers. Change to response struct in future!
            if &response[..5] == b"HTTP/" {
                (
                    ByteResponse::with_partial_header(response),
                    content_type,
                    cache,
                )
            } else {
                (ByteResponse::without_header(response), content_type, cache)
            }
        } else if let Some(file) = read_file_cached(&path, storage.get_fs()) {
            (
                ByteResponse::without_header_shared(file),
                AutoOrDownload,
                Static,
            )
        } else {
            (
                default_error(404, close, Some(storage.get_fs())),
                Html,
                Cached::Static,
            )
        }
    };

    // Apply extensions
    {
        {
            // Search through extension map!
            let (extension_args, content_start) =
                extensions::parse::extension_args(byte_response.get_body());

            // Get head and body reference.
            let (mut head, mut body) = match &byte_response {
                ByteResponse::Merged(vec, start, _) => {
                    (Some(&vec[content_start..*start]), &vec[*start..])
                }
                ByteResponse::Both(head, body, _) => (Some(&head[content_start..]), &body[..]),
                ByteResponse::Body(body) => (None, &body[content_start..]),
                ByteResponse::BorrowedBody(borrow) => (None, &borrow[content_start..]),
            };
            // Declare temp response variable for extensions to assign to.
            let mut response = None;

            for segment in extension_args {
                if let Some(extension_name) = segment.get(0).map(String::as_str) {
                    match extensions.get_name(extension_name) {
                        Some(extension) => unsafe {
                            let mut data = extensions::RequestData::new(
                                address,
                                head,
                                body,
                                content_start,
                                &mut cached,
                                segment,
                                storage,
                                &request,
                                raw_request,
                                &path,
                                &mut content_type,
                                close,
                                host,
                            );
                            extension.run(&mut data);
                            match data.into_response() {
                                // If got response, replace `response` with new one and calculate head and body.
                                Some(new_response) => {
                                    response = Some(new_response);
                                    let (new_head, new_body) = match response.as_ref().unwrap() {
                                        ByteResponse::Merged(vec, start, _) => {
                                            (Some(&vec[..*start]), &vec[*start..])
                                        }
                                        ByteResponse::Both(head, body, _) => {
                                            (Some(&head[..]), &body[..])
                                        }
                                        ByteResponse::Body(body) => (None, &body[..]),
                                        ByteResponse::BorrowedBody(borrow) => (None, &borrow[..]),
                                    };
                                    head = new_head;
                                    body = new_body;
                                }
                                None => {}
                            }
                        },
                        // }
                        None => {}
                    }
                }
            }

            if let Some(file_extension) = path.extension().and_then(OsStr::to_str) {
                match extensions.get_file_extension(file_extension) {
                    Some(extension) => unsafe {
                        let mut data = extensions::RequestData::new(
                            address,
                            head,
                            body,
                            content_start,
                            &mut cached,
                            Vec::new(),
                            storage,
                            &request,
                            raw_request,
                            &path,
                            &mut content_type,
                            close,
                            host,
                        );
                        extension.run(&mut data);
                        match data.into_response() {
                            Some(new_response) => response = Some(new_response),
                            None => {}
                        }
                    },
                    None => {}
                }
            }
            if !allowed_method {
                byte_response = default_error(405, close, Some(storage.get_fs()));
            }
            match response {
                Some(response) => byte_response = response,
                None => byte_response.remove_first(content_start),
            }
        }
    }

    if !cached.query_matters() {
        let bytes = request.uri().path().as_bytes().to_vec(); // ToDo: Remove cloning of slice! Perhaps by Vec::from_raw?
        if let Ok(uri) = http::Uri::from_maybe_shared(bytes) {
            if let Some(lock) = host.get_cache() {
                if let Some(response) = lock.resolve(&uri, request.headers()) {
                    return response.write_as_method(socket, request.method());
                };
            }
        }
    }

    // Check takes about 1 micro second for a 4MB image.
    let valid_utf8 = std::str::from_utf8(byte_response.get_body()).is_ok();
    let content_str = content_type.as_str_utf8(path, valid_utf8);

    // The response MUST contain all vary headers, else it won't be cached!
    let vary: Vec<&str> = vec!["Accept-Encoding"];

    let compression = match request
        .headers()
        .get("Accept-Encoding")
        .and_then(to_option_str)
    {
        Some(header) => {
            let (algorithm, identity_forbidden) = compression::compression_from_header(header);
            // Filter content types for compressed formats
            if (content_str.starts_with("application")
                && !content_str.contains("xml")
                && !content_str.contains("json")
                && content_str != "application/pdf"
                && content_str != "application/javascript"
                && content_str != "application/graphql")
                || content_str.starts_with("image")
                || content_str.starts_with("audio")
                || content_str.starts_with("video")
                || content_str.starts_with("font")
            {
                if identity_forbidden {
                    byte_response = default_error(406, &close, Some(&mut storage.fs));
                    algorithm
                } else {
                    compression::CompressionAlgorithm::Identity
                }
            } else {
                algorithm
            }
        }
        None => compression::CompressionAlgorithm::Identity,
    };

    let response = match byte_response {
        ByteResponse::Merged(_, _, partial_header) | ByteResponse::Both(_, _, partial_header)
            if partial_header =>
        {
            let partial_head = byte_response.get_head().unwrap();
            let mut head = Vec::with_capacity(2048);
            if !partial_head.starts_with(b"HTTP") {
                head.extend(b"HTTP/1.1 200 OK\r\n");
            }
            // Adding partial head
            head.extend_from_slice(partial_head);
            // Remove last CRLF if, header doesn't end here!
            if head.ends_with(&[CR, LF]) {
                head.truncate(head.len() - 2);
            }
            // Parse the present headers
            let present_headers = parse::parse_only_headers(partial_head);
            let compress = !present_headers.contains_key(CONTENT_ENCODING);
            let varies = present_headers.contains_key(VARY);
            let body = if compress && !varies {
                compression::Compressors::compress(byte_response.get_body(), &compression)
            } else {
                byte_response.into_body()
            };

            use http::header::*;

            if !present_headers.contains_key(CONNECTION) {
                head.extend(b"Connection: ");
                head.extend(close.as_bytes());
                head.extend(LINE_ENDING);
            }
            if compress && !varies {
                // Compression
                head.extend(b"Content-Encoding: ");
                head.extend(compression.as_bytes());
                head.extend(LINE_ENDING);
            }
            if !present_headers.contains_key(CONTENT_LENGTH) {
                // Length
                head.extend(b"Content-Length: ");
                head.extend(body.len().to_string().as_bytes());
                head.extend(LINE_ENDING);
            }

            if !present_headers.contains_key(CONTENT_TYPE) {
                head.extend(b"Content-Type: ");
                head.extend(content_str.as_bytes());
                head.extend(LINE_ENDING);
            }
            if !present_headers.contains_key(CACHE_CONTROL) {
                // Cache header!
                head.extend(cached.as_bytes());
            }

            if !varies && !vary.is_empty() {
                head.extend(b"Vary: ");
                let mut iter = vary.iter();
                head.extend(iter.next().unwrap().as_bytes());

                for vary in iter {
                    head.extend(b", ");
                    head.extend(vary.as_bytes());
                }
                head.extend(LINE_ENDING);
            }

            // Add server signature
            head.extend(SERVER_HEADER);
            // Close header
            head.extend(LINE_ENDING);

            // Return byte response
            ByteResponse::Both(head, body, false)
        }
        ByteResponse::Body(_) | ByteResponse::BorrowedBody(_) => {
            let mut response = Vec::with_capacity(4096);
            response.extend(b"HTTP/1.1 200 OK\r\n");
            response.extend(b"Connection: ");
            response.extend(close.as_bytes());
            response.extend(LINE_ENDING);
            // Compression
            response.extend(b"Content-Encoding: ");
            response.extend(compression.as_bytes());
            response.extend(LINE_ENDING);
            let body = compression::Compressors::compress(byte_response.get_body(), &compression);
            // Length
            response.extend(b"Content-Length: ");
            response.extend(body.len().to_string().as_bytes());
            response.extend(LINE_ENDING);

            response.extend(b"Content-Type: ");
            response.extend(content_str.as_bytes());
            response.extend(LINE_ENDING);
            // Cache header!
            response.extend(cached.as_bytes());

            if !vary.is_empty() {
                response.extend(b"Vary: ");
                let mut iter = vary.iter();
                // Can unwrap, since it isn't empty!
                response.extend(iter.next().unwrap().as_bytes());

                for vary in iter {
                    response.extend(b", ");
                    response.extend(vary.as_bytes());
                }
                response.extend(LINE_ENDING);
            }

            response.extend(SERVER_HEADER);
            // Close header
            response.extend(LINE_ENDING);

            // Return byte response
            ByteResponse::Both(response, body, false)
        }
        // Headers handled! Taking for granted user handled HEAD method.
        _ => byte_response,
    };

    // Write to socket!
    response.write_as_method(socket, request.method())?;

    if is_get && cached.do_internal_cache() {
        if let Some(mut lock) = host.get_cache() {
            #[cfg(feature = "info-log")]
            println!(
                "Caching uri {} on host {:?}",
                request.uri(),
                request.headers().get("host")
            );
            let uri = request.into_parts().0.uri;

            let uri = if !cached.query_matters() {
                let bytes = uri.path().as_bytes().to_vec(); // ToDo: Remove cloning of slice! Perhaps by Vec::from_raw?
                if let Ok(uri) = http::Uri::from_maybe_shared(bytes) {
                    uri
                } else {
                    uri
                }
            } else {
                uri
            };
            match vary.is_empty() {
                false => {
                    let headers = {
                        let headers = parse::parse_only_headers(response.get_head().unwrap());
                        let mut is_ok = true;
                        let mut buffer = Vec::with_capacity(vary.len());
                        for vary_header in vary.iter() {
                            let header = match *vary_header {
                                "Accept-Encoding" => "Content-Encoding",
                                _ => *vary_header,
                            };
                            match headers.get(header) {
                                Some(header) => {
                                    buffer.push(header.clone()) // ToDo: Remove in future by iterating over and adding matching items.
                                }
                                None => {
                                    is_ok = false;
                                    break;
                                }
                            }
                        }
                        match is_ok {
                            true => Some(buffer),
                            false => None,
                        }
                    };
                    match headers {
                        Some(headers) => {
                            let _ = lock.add_variant(uri, response, headers, &vary[..]);
                        }
                        None => {
                            #[cfg(feature = "info-log")]
                            eprintln!("Vary header not present in response! Will not cache.")
                        }
                    }
                }
                true => {
                    let _ = lock.cache(uri, Arc::new(cache::CacheType::with_data(response)));
                }
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
mod stack_buffered_write {
    use crate::fs::*;

    const BUFFER_SIZE: usize = 8192;
    // const BUFFER_SIZE: usize = 8;
    pub struct Buffered<'a, W: Write> {
        buffer: [u8; BUFFER_SIZE],
        // Must not be more than buffer.len()
        index: usize,
        writer: &'a mut W,
    }
    impl<'a, W: Write> Buffered<'a, W> {
        pub fn new(writer: &'a mut W) -> Self {
            Self {
                buffer: [0; BUFFER_SIZE],
                index: 0,
                writer,
            }
        }

        #[inline]
        pub fn left(&self) -> usize {
            self.buffer.len() - self.index
        }

        pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
            if buf.len() > self.left() {
                if buf.len() + self.index < self.buffer.len() * 2 {
                    let copy = self.left();
                    self.buffer[self.index..].copy_from_slice(&buf[..copy]);
                    unsafe {
                        self.flush_all()?;
                    }
                    self.buffer[..buf.len() - copy].copy_from_slice(&buf[copy..]);
                    self.index = buf.len() - copy;

                    self.try_flush()?;
                } else {
                    self.flush_remaining()?;
                    self.writer.write_all(buf)?;
                }
            } else {
                self.buffer[self.index..self.index + buf.len()].copy_from_slice(buf);
                self.index += buf.len();

                self.try_flush()?;
            }
            Ok(())
        }
        #[inline]
        pub unsafe fn flush_all(&mut self) -> io::Result<()> {
            self.index = 0;
            self.writer.write_all(&self.buffer[..])
        }
        pub fn flush_remaining(&mut self) -> io::Result<()> {
            self.writer.write_all(&self.buffer[..self.index])?;
            self.index = 0;
            Ok(())
        }
        pub fn try_flush(&mut self) -> io::Result<()> {
            if self.index == self.buffer.len() {
                unsafe {
                    self.flush_all()?;
                }
            }
            Ok(())
        }

        #[inline]
        pub fn inner(&mut self) -> &mut W {
            &mut self.writer
        }
    }
    impl<'a, W: Write> Drop for Buffered<'a, W> {
        fn drop(&mut self) {
            let _ = self.flush_remaining();
        }
    }
    impl<'a, W: Write> Write for Buffered<'a, W> {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write(buf)?;
            Ok(buf.len())
        }
        #[inline]
        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.write(buf)
        }
        #[inline]
        fn flush(&mut self) -> io::Result<()> {
            self.flush_remaining()
        }
    }
}

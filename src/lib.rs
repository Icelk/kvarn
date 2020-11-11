#![warn(missing_debug_implementations)]

// Module declaration
pub mod bindings;
pub mod cache;
pub mod compression;
pub mod connection;
pub mod extensions;
pub mod parse;
pub mod prelude;
mod threading;
pub mod utility;

use prelude::*;

// When user only imports crate::* and not crate::prelude::*
pub use utility::{read_file, write_error, write_generic_error};

const RESERVED_TOKENS: usize = 1024;
#[cfg(target_os = "windows")]
pub const SERVER_HEADER: &[u8] = b"Server: Arktis/0.1.0 (Windows)\r\n";
#[cfg(target_os = "macos")]
pub const SERVER_HEADER: &[u8] = b"Server: Arktis/0.1.0 (MacOS)\r\n";
#[cfg(target_os = "linux")]
pub const SERVER_HEADER: &[u8] = b"Server: Arktis/0.1.0 (Linux)\r\n";
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub const SERVER_HEADER: &[u8] = b"Server: Arktis/0.1.0 (unknown OS)\r\n";
pub const SERVER_NAME: &str = "Arktis";
pub const LINE_ENDING: &[u8] = b"\r\n";

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

#[derive(Debug)]
pub struct Config {
    sockets: HashMap<mio::Token, (u16, ConnectionSecurity)>,
    con_id: usize,
    storage: Storage,
    extensions: Extensions,
}
impl Config {
    pub fn on_ports(ports: &[(u16, ConnectionSecurity)]) -> Self {
        Config {
            sockets: Self::make_portmap(ports),
            con_id: RESERVED_TOKENS,
            storage: Storage::new(),
            extensions: Extensions::new(),
        }
    }
    pub fn new(bindings: FunctionBindings, ports: &[(u16, ConnectionSecurity)]) -> Self {
        Config {
            sockets: Self::make_portmap(ports),
            con_id: RESERVED_TOKENS,
            storage: Storage::from_bindings(Arc::new(bindings)),
            extensions: Extensions::new(),
        }
    }

    fn make_portmap(
        ports: &[(u16, ConnectionSecurity)],
    ) -> HashMap<mio::Token, (u16, ConnectionSecurity)> {
        let mut map = HashMap::new();
        for (position, port) in ports.iter().enumerate() {
            map.insert(mio::Token(position), port.clone());
        }
        map
    }

    /// Clones the Storage of this config, returning an owned reference-counted struct containing all caches and bindings
    #[inline]
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
    /// use arktis::*;
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
    pub fn run(mut self) {
        let mut poll = mio::Poll::new().expect("Failed to create a poll instance");
        let mut events = mio::Events::with_capacity(1024);
        let mut listeners: HashMap<_, _> = self
            .sockets
            .iter()
            .map(|(token, (port, connection))| {
                let mut socket = TcpListener::bind(net::SocketAddr::new(
                    net::IpAddr::V4(net::Ipv4Addr::new(0, 0, 0, 0)),
                    *port,
                ))
                .expect("Failed to bind port");

                poll.registry()
                    .register(&mut socket, *token, mio::Interest::READABLE)
                    .expect("Failed to register HTTPS server");

                (*token, (socket, ConnectionSecurity::clone(&connection)))
            })
            .collect();

        let mut thread_handler = threading::HandlerPool::new(
            self.clone_storage(),
            Extensions::clone(&self.extensions),
            poll.registry(),
        );

        loop {
            poll.poll(&mut events, None).expect("Failed to poll!");

            for event in events.iter() {
                match listeners.get_mut(&event.token()) {
                    Some((listener, scheme)) => {
                        let id = self.next_id();
                        Self::accept(&mut thread_handler, scheme.clone(), listener, id)
                            .expect("Failed to accept message!");
                    }
                    _ => {
                        let time = std::time::Instant::now();
                        thread_handler.handle(connection::MioEvent::from_event(event), time);
                    }
                }
            }
        }
    }
    #[inline]
    fn next_id(&mut self) -> usize {
        self.con_id = match self.con_id.checked_add(1) {
            Some(id) => id,
            None => RESERVED_TOKENS,
        };
        self.con_id
    }

    pub fn accept(
        handler: &mut threading::HandlerPool,
        connection: ConnectionSecurity,
        socket: &mut TcpListener,
        id: usize,
    ) -> Result<(), io::Error> {
        loop {
            match socket.accept() {
                Ok((socket, addr)) => {
                    let token = mio::Token(id);
                    handler.accept(socket, addr, token, connection.clone());
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    eprintln!("Encountered error while accepting connection. {:?}", err);
                    return Err(err);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Storage {
    fs: FsCache,
    response: ResponseCache,
    template: TemplateCache,
    bindings: Bindings,
}
impl Storage {
    pub fn new() -> Self {
        use cache::Cache;
        Storage {
            fs: Arc::new(Mutex::new(Cache::with_max_size(65536))),
            response: Arc::new(Mutex::new(Cache::new())),
            template: Arc::new(Mutex::new(Cache::with_max(128))),
            bindings: Arc::new(FunctionBindings::new()),
        }
    }
    pub fn from_caches(fs: FsCache, response: ResponseCache, template: TemplateCache) -> Self {
        Storage {
            fs,
            response,
            template,
            bindings: Arc::new(FunctionBindings::new()),
        }
    }
    pub fn from_bindings(bindings: Bindings) -> Self {
        use cache::Cache;
        Storage {
            fs: Arc::new(Mutex::new(Cache::with_max_size(65536))),
            response: Arc::new(Mutex::new(Cache::new())),
            template: Arc::new(Mutex::new(Cache::with_max(128))),
            bindings,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.fs.lock().unwrap().clear();
        self.response.lock().unwrap().clear();
        self.template.lock().unwrap().clear();
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
    /// Tries to get the lock of response cache.
    ///
    /// Always remember to handle the case if the lock isn't acquired; just don't return None!
    #[inline]
    pub fn try_response(&mut self) -> Option<sync::MutexGuard<'_, ResponseCacheInner>> {
        #[cfg(feature = "no-response-cache")]
        return None;
        #[cfg(not(feature = "no-response-cache"))]
        match self.response.try_lock() {
            Ok(lock) => Some(lock),
            Err(ref err) => match err {
                sync::TryLockError::WouldBlock => None,
                sync::TryLockError::Poisoned(..) => panic!("Lock is poisoned!"),
            },
        }
    }
    /// Gets the lock of response cache.
    #[inline]
    pub fn response_blocking(&mut self) -> Option<sync::MutexGuard<'_, ResponseCacheInner>> {
        #[cfg(feature = "no-response-cache")]
        return None;
        #[cfg(not(feature = "no-response-cache"))]
        match self.response.lock() {
            Ok(lock) => Some(lock),
            Err(..) => panic!("Lock is poisoned!"),
        }
    }
    /// Tries to get the lock of template cache.
    ///
    /// Always remember to handle the case if the lock isn't acquired; just don't return None!
    #[inline]
    pub fn try_template(&mut self) -> Option<sync::MutexGuard<'_, TemplateCacheInner>> {
        #[cfg(feature = "no-template-cache")]
        return None;
        #[cfg(not(feature = "no-template-cache"))]
        match self.template.try_lock() {
            Ok(lock) => Some(lock),
            Err(ref err) => match err {
                sync::TryLockError::WouldBlock => None,
                sync::TryLockError::Poisoned(..) => panic!("Lock is poisoned!"),
            },
        }
    }
    #[inline]
    pub fn get_bindings(&self) -> &Bindings {
        &self.bindings
    }
}
impl Clone for Storage {
    fn clone(&self) -> Self {
        Storage {
            fs: Arc::clone(&self.fs),
            response: Arc::clone(&self.response),
            template: Arc::clone(&self.template),
            bindings: Arc::clone(&self.bindings),
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
    adress: &net::SocketAddr,
    request: http::Request<&[u8]>,
    raw_request: &[u8],
    close: &connection::ConnectionHeader,
    storage: &mut Storage,
    extensions: &mut ExtensionMap,
) -> Result<(), io::Error> {
    let is_get = match request.method() {
        &http::Method::GET | &http::Method::HEAD => true,
        _ => false,
    };

    // println!("Got request: {:?}", &request);
    if is_get {
        // Load from cache
        // Try get response cache lock
        if let Some(lock) = storage.response_blocking() {
            // If response is in cache
            if let Some(response) = lock.resolve(request.uri(), request.headers()) {
                // println!("Got cache! {}", request.uri());
                return response.write_as_method(socket, request.method());
            }
        }
    }
    let mut allowed_method = is_get;

    // Get from function or cache, to enable processing (extensions) from functions!
    let path = match parse::convert_uri(request.uri()) {
        Ok(path) => path,
        Err(()) => {
            &utility::default_error(403, close, Some(storage.get_fs())).write_all(socket)?;
            return Ok(());
        }
    };

    // Extensions need body and cache setting to be mutable; to replace it.
    // Used to bypass immutable/mutable rule. It is safe because the binding reference isn't affected by changing the cache.
    let cache: *mut Storage = storage;
    let (mut byte_response, mut content_type, mut cached) =
        match storage.get_bindings().get_binding(request.uri().path()) {
            // We've got an function, call it and return body and result!
            Some(callback) => {
                let mut response = Vec::with_capacity(2048);
                let (content_type, cache) =
                    callback(&mut response, &request, unsafe { (*cache).get_fs() });

                allowed_method = true;
                // Check if callback contains headers. Change to response struct in future!
                if &response[..5] == b"HTTP/" {
                    (ByteResponse::with_header(response), content_type, cache)
                } else {
                    (ByteResponse::without_header(response), content_type, cache)
                }
            }
            // No function, try read from FS cache.
            None => {
                // Body
                let body = match read_file(&path, storage.get_fs()) {
                    Some(response) => ByteResponse::without_header_shared(response),
                    None => utility::default_error(404, close, Some(storage.get_fs())),
                };
                // Content mime type
                (body, AutoOrDownload, Cached::Static)
            }
        };

    // Apply extensions
    {
        {
            // Search through extension map!
            let (extension_args, content_start) =
                extensions::parse::extension_args(byte_response.get_body());
            // Extension line is removed from body before it is handed to extensions, saving them the confusion.
            let vec = byte_response.get_first_vec();
            *vec = vec[content_start..].to_vec();

            for segment in extension_args {
                if let Some(extension_name) = segment.get(0).map(|string| string.as_str()) {
                    match extensions.get_name(extension_name) {
                        Some(extension) => unsafe {
                            extension.run(extensions::RequestData {
                                adress,
                                response: &mut byte_response,
                                content_start,
                                cached: &mut cached,
                                args: segment,
                                storage,
                                request: &request,
                                raw_request,
                                path: &path,
                                content_type: &mut content_type,
                            });
                        },
                        // Do nothing
                        None if allowed_method => {}
                        _ => {
                            byte_response =
                                utility::default_error(405, close, Some(storage.get_fs()));
                        }
                    }
                }
            }

            if let Some(file_extension) = path.extension().and_then(|path| path.to_str()) {
                match extensions.get_file_extension(file_extension) {
                    Some(extension) => unsafe {
                        extension.run(extensions::RequestData {
                            adress,
                            response: &mut byte_response,
                            content_start,
                            cached: &mut cached,
                            args: Vec::new(),
                            storage,
                            request: &request,
                            raw_request,
                            path: &path,
                            content_type: &mut content_type,
                        });
                    },
                    // Do nothing
                    None if allowed_method => {}
                    _ => {
                        byte_response = utility::default_error(405, close, Some(storage.get_fs()));
                    }
                }
            }
        }
    }

    if cached.cached_without_query() {
        let bytes = request.uri().path().as_bytes().to_vec(); // ToDo: Remove cloning of slice!
        if let Ok(uri) = http::Uri::from_maybe_shared(bytes) {
            if let Some(lock) = storage.response_blocking() {
                if let Some(response) = lock.resolve(&uri, request.headers()) {
                    return response.write_as_method(socket, request.method());
                };
            }
        }
    }

    let content_str = content_type.as_str(path);
    // The response MUST contain all vary headers, else it won't be cached!
    let vary: Vec<&str> = vec![/* "Content-Type", */ "Accept-Encoding"];

    let compression = match request
        .headers()
        .get("Accept-Encoding")
        .and_then(|header| header.to_str().ok())
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
            {
                if identity_forbidden {
                    byte_response = utility::default_error(406, &close, Some(&mut storage.fs));
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
        if let Some(mut lock) = storage.response_blocking() {
            let uri = request.into_parts().0.uri;
            let uri = if !cached.query_matters() {
                let bytes = uri.path().as_bytes().to_vec(); // ToDo: Remove cloning of slice!
                if let Ok(uri) = http::Uri::from_maybe_shared(bytes) {
                    uri
                } else {
                    uri
                }
            } else {
                uri
            };
            println!("Caching uri {}", &uri);
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
                                    buffer.push(header.clone()) // ToDo: Remove in future!
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
                        None => eprintln!("Vary header not present in response!"),
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

pub mod tls_server_config {
    use super::*;
    use crate::prelude::fs::*;
    use rustls::{internal::pemfile, NoClientAuth, ServerConfig};

    #[derive(Debug)]
    pub enum ServerConfigError {
        IO(io::Error),
        ImproperPrivateKeyFormat,
        ImproperCertificateFormat,
        NoKey,
        InvalidPrivateKey,
    }
    impl From<io::Error> for ServerConfigError {
        fn from(error: io::Error) -> Self {
            Self::IO(error)
        }
    }
    pub fn get_server_config<P: AsRef<Path>>(
        cert_path: P,
        private_key_path: P,
    ) -> Result<ServerConfig, ServerConfigError> {
        let mut chain = io::BufReader::new(File::open(&cert_path)?);
        let mut private_key = io::BufReader::new(File::open(&private_key_path)?);

        let mut server_config = ServerConfig::new(NoClientAuth::new());
        let mut private_keys = Vec::with_capacity(4);
        private_keys.extend(match pemfile::pkcs8_private_keys(&mut private_key) {
            Ok(key) => key,
            Err(()) => return Err(ServerConfigError::ImproperPrivateKeyFormat),
        });
        private_keys.extend(match pemfile::rsa_private_keys(&mut private_key) {
            Ok(key) => key,
            Err(()) => return Err(ServerConfigError::ImproperPrivateKeyFormat),
        });
        if let Err(..) = server_config.set_single_cert(
            match pemfile::certs(&mut chain) {
                Ok(cert) => cert,
                Err(()) => return Err(ServerConfigError::ImproperCertificateFormat),
            },
            match private_keys.into_iter().next() {
                Some(key) => key,
                None => return Err(ServerConfigError::NoKey),
            },
        ) {
            Err(ServerConfigError::InvalidPrivateKey)
        } else {
            Ok(server_config)
        }
    }
    pub fn optional_server_config<P: AsRef<Path>>(
        cert_path: P,
        private_key_path: P,
    ) -> Option<Arc<ServerConfig>> {
        get_server_config(cert_path, private_key_path)
            .ok()
            .map(|config| Arc::new(config))
    }
}

#[allow(dead_code)]
mod stack_buffered_write {
    use crate::prelude::fs::*;

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

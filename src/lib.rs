// #![warn(missing_docs, missing_debug_implementations, unreachable_pub)]

// Module declaration
pub mod application;
pub mod comprash;
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

use comprash::{ClientCachePreference, CompressPreference, ServerCachePreference};
use extensions::{Extensions, Response};
use limiting::LimitWrapper;
use net::SocketAddrV4;
use prelude::{internals::*, networking::*, threading::*, *};
use rustls::ServerConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
// When user only imports crate::* and not crate::prelude::*
pub use utility::read_file;

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

pub(crate) async fn handle_connection(
    stream: TcpStream,
    address: net::SocketAddr,
    host_descriptors: Arc<HostDescriptor>,
) -> io::Result<()> {
    // LAYER 2
    let encrypted =
        encryption::Encryption::new_from_connection_security(stream, &host_descriptors.r#type)
            .await?;

    let version = match encrypted.get_alpn_protocol() {
        Some(b"h2") => http::Version::HTTP_2,
        None | Some(b"http/1.1") => http::Version::HTTP_11,
        Some(b"http/1.0") => http::Version::HTTP_10,
        Some(b"http/0.9") => http::Version::HTTP_09,
        _ => unimplemented!(),
    };
    let hostname = encrypted.get_sni_hostname().map(str::to_string);
    println!("ALPN: {:?}", encrypted.get_alpn_protocol());
    // LAYER 3
    let mut http = application::HttpConnection::new(encrypted, version)
        .await
        .map_err::<io::Error, _>(application::Error::into)?;

    while let Ok((request, response_pipe)) = http.accept().await {
        let host = application::get_host(
            &request,
            hostname.as_ref().map(String::as_str),
            &host_descriptors.host_data,
        );
        // fn to handle getting from cache, generating response and sending it
        handle_cache(request, address, response_pipe, host).await?;
    }

    Ok(())
}

/// LAYER 4
pub(crate) async fn handle_cache(
    mut request: http::Request<application::Body>,
    address: net::SocketAddr,
    mut response_pipe: application::ResponsePipe,
    host: &Host,
) -> io::Result<()> {
    let path_query = comprash::UriKey::path_and_query(request.uri());

    let lock = host.response_cache.lock().await;
    let cached = path_query.call_all(|path| lock.get(path)).1;
    match cached {
        Some(resp) => {
            info!("Found in cache!");
            let resp = resp.get_preferred();
            let response = utility::empty_clone_response(resp);
            let response_body = Bytes::clone(resp.body());
            drop(lock);

            let mut body_pipe = response_pipe
                .send_response(response, false)
                .await
                .map_err::<io::Error, _>(application::Error::into)?;
            body_pipe
                .send(Bytes::clone(&response_body), true)
                .await
                .map_err::<io::Error, _>(application::Error::into)?;
        }
        None => {
            drop(lock);
            let path_query = comprash::PathQuery::from_uri(request.uri());
            // LAYER 5.1
            let (resp, client_cache, server_cache, compress) =
                handle_request(&mut request, address, host).await.unwrap();

            let extension = match Path::new(request.uri().path())
                .extension()
                .and_then(|s| s.to_str())
            {
                Some(ext) => ext,
                None => match host.extension_default.as_ref() {
                    Some(ext) => ext.as_str(),
                    None => "",
                },
            };
            let compressed_response =
                comprash::CompressedResponse::new(resp, compress, client_cache, extension);

            let response = compressed_response.get_preferred();

            let resp_no_body = utility::empty_clone_response(response);
            let mut pipe = response_pipe
                .send_response(resp_no_body, false)
                .await
                .map_err::<io::Error, _>(application::Error::into)?;
            pipe.send(Bytes::clone(response.body()), true)
                .await
                .map_err::<io::Error, _>(application::Error::into)?;
            if server_cache.cache() {
                let mut lock = host.response_cache.lock().await;
                let key = match server_cache.query_matters() {
                    true => comprash::UriKey::PathQuery(path_query),
                    false => comprash::UriKey::Path(path_query.into_path()),
                };
                info!("Caching uri {:?}!", &key);
                lock.cache(key, compressed_response);
            }
            // process response push
        }
    }
    Ok(())
}

/// LAYER 5.1
pub(crate) async fn handle_request(
    _request: &mut http::Request<application::Body>,
    _address: net::SocketAddr,
    host: &Host,
) -> io::Result<Response> {
    let path = match parse::convert_uri(
        _request.uri().path(),
        host.path.as_path(),
        host.get_folder_default_or("index.html"),
        host.get_extension_default_or("html"),
    ) {
        Some(p) => p,
        None => {
            return Ok(utility::default_error_response(http::StatusCode::BAD_REQUEST, host).await)
        }
    };
    let response = match utility::read_file(&path, &host.file_cache).await {
        Some(response) => response,
        None => {
            return Ok(utility::default_error_response(http::StatusCode::NOT_FOUND, host).await)
        }
    };
    // let content = b"<h1>Hello!</h1>What can I do for you?";

    Ok((
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(response)
            .unwrap(),
        comprash::ClientCachePreference::Full,
        comprash::ServerCachePreference::Full,
        comprash::CompressPreference::Full,
    ))
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

pub struct Config {
    sockets: Vec<HostDescriptor>,
    extensions: Extensions,
}
impl Config {
    pub fn new(descriptors: Vec<HostDescriptor>) -> Self {
        Config {
            sockets: descriptors,
            extensions: Extensions::new(),
        }
    }

    pub async fn run(self) {
        trace!("Running from config");

        let mut limiter = LimitWrapper::default();

        let len = self.sockets.len();
        for (pos, descriptor) in self.sockets.into_iter().enumerate() {
            let listener =
                TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, descriptor.port))
                    .await
                    .expect("Failed to bind to port");

            let limiter = limiter.clone();
            let future = async move {
                Self::accept(listener, descriptor, limiter)
                    .await
                    .expect("Failed to accept message!")
            };

            if pos + 1 == len {
                future.await;
            } else {
                tokio::spawn(future);
            }
        }
    }

    async fn accept(
        listener: TcpListener,
        host: HostDescriptor,
        mut limiter: LimitWrapper,
    ) -> Result<(), io::Error> {
        trace!("Started listening on {:?}", listener.local_addr());
        let host = Arc::new(host);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    #[cfg(feature = "limiting")]
                    match limiter.register(addr) {
                        LimitStrength::Send | LimitStrength::Drop => {
                            drop(socket);
                            return Ok(());
                        }
                        LimitStrength::Passed => {}
                    }
                    let host = Arc::clone(&host);
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(socket, addr, host).await {
                            warn!(
                                "An error occurred in the main processing function {:?}",
                                err
                            );
                        }
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
impl Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Config {{ sockets: {:?}, extensions }}", self.sockets)
    }
}

// / The main request processing function.
// /
// / First checks if something's in cache, then write it to the socket and return.
// /
// / Then, check if a binding is available. If one is, give it a `Vec` to populate. Wrap that `Vec` in a `ByteResponse` to get separation between body and head.
// / If not, get from the FS instead, and wrap in `Arc` inside a `ByteResponse`. Sets appropriate content type and cache settings.
// /
// / Then matches content type to get a `str`.
// /
// / Checks extension in body of `ByteResponse`.
// pub(crate) fn process_request<W: io::Write>(
//     socket: &mut W,
//     address: &net::SocketAddr,
//     request: http::Request<&[u8]>,
//     raw_request: &[u8],
//     close: &ConnectionHeader,
//     storage: &mut Storage,
//     extensions: &mut ExtensionMap,
//     host: &Host,
//     scheme: ConnectionScheme,
// ) -> Result<(), io::Error> {
//     let is_get = match request.method() {
//         &http::Method::GET | &http::Method::HEAD => true,
//         _ => false,
//     };

//     // println!("Got request: {:?}", &request);
//     if is_get {
//         // Load from cache
//         // Try get response cache lock
//         if let Some(lock) = host.get_cache() {
//             // If response is in cache
//             if let Some(response) = lock.resolve(request.uri(), request.headers()) {
//                 // println!("Got cache! {}", request.uri());
//                 return response.write_as_method(socket, request.method());
//             }
//         }
//     }
//     let mut allowed_method = is_get;

//     // Get from function or cache, to enable processing (extensions) from functions!
//     let path = match parse::convert_uri(
//         request.uri().path(),
//         host.path.as_path(),
//         host.get_folder_default_or("index.html"),
//         host.get_extension_default_or("html"),
//     ) {
//         Some(path) => path,
//         None => {
//             &default_error(http::StatusCode::BAD_REQUEST, close, Some(storage.get_fs()))
//                 .write_all(socket)?;
//             return Ok(());
//         }
//     };

//     // Extensions need body and cache setting to be mutable; to replace it.
//     // Used to bypass immutable/mutable rule. It is safe because the binding reference isn't affected by changing the cache.
//     let cache: *mut Storage = storage;
//     let (mut byte_response, mut content_type, mut cached) = {
//         let binding = match scheme {
//             ConnectionScheme::HTTP1 | ConnectionScheme::WS => host
//                 .get_binding_overrides()
//                 .and_then(|bindings| bindings.get_binding(request.uri().path())),
//             _ => None,
//         };
//         if let Some(binding) = binding {
//             let mut response = Vec::with_capacity(2048);
//             let (content_type, cache) =
//                 binding(&mut response, &request, unsafe { (*cache).get_fs() });

//             allowed_method = true;
//             // Check if callback contains headers. Change to response struct in future!
//             if &response[..5] == b"HTTP/" {
//                 (ByteResponse::with_header(response), content_type, cache)
//             } else {
//                 (ByteResponse::without_header(response), content_type, cache)
//             }
//         } else if let Some(binding) = host.get_bindings().get_binding(request.uri().path()) {
//             let mut response = Vec::with_capacity(2048);
//             let (content_type, cache) =
//                 binding(&mut response, &request, unsafe { (*cache).get_fs() });

//             allowed_method = true;
//             // Check if callback contains headers. Change to response struct in future!
//             if &response[..5] == b"HTTP/" {
//                 (
//                     ByteResponse::with_partial_header(response),
//                     content_type,
//                     cache,
//                 )
//             } else {
//                 (ByteResponse::without_header(response), content_type, cache)
//             }
//         } else if let Some(file) = read_file_cached(&path, storage.get_fs()) {
//             (
//                 ByteResponse::without_header_shared(file),
//                 AutoOrDownload,
//                 Static,
//             )
//         } else {
//             (
//                 default_error(http::StatusCode::NOT_FOUND, close, Some(storage.get_fs())),
//                 Html,
//                 Cached::Static,
//             )
//         }
//     };

//     // Apply extensions
//     {
//         {
//             // Search through extension map!
//             let (extension_args, content_start) =
//                 extensions_old::parse::extension_args(byte_response.get_body());

//             // Get head and body reference.
//             let (mut head, mut body) = match &byte_response {
//                 ByteResponse::Merged(vec, start, _) => {
//                     (Some(&vec[content_start..*start]), &vec[*start..])
//                 }
//                 ByteResponse::Both(head, body, _) => (Some(&head[content_start..]), &body[..]),
//                 ByteResponse::Body(body) => (None, &body[content_start..]),
//                 ByteResponse::BorrowedBody(borrow) => (None, &borrow[content_start..]),
//             };
//             // Declare temp response variable for extensions to assign to.
//             let mut response = None;

//             for segment in extension_args {
//                 if let Some(extension_name) = segment.get(0).map(String::as_str) {
//                     match extensions.get_name(extension_name) {
//                         Some(extension) => unsafe {
//                             let mut data = extensions_old::RequestData::new(
//                                 address,
//                                 head,
//                                 body,
//                                 content_start,
//                                 &mut cached,
//                                 segment,
//                                 storage,
//                                 &request,
//                                 raw_request,
//                                 &path,
//                                 &mut content_type,
//                                 close,
//                                 host,
//                             );
//                             extension.run(&mut data);
//                             match data.into_response() {
//                                 // If got response, replace `response` with new one and calculate head and body.
//                                 Some(new_response) => {
//                                     response = Some(new_response);
//                                     let (new_head, new_body) = match response.as_ref().unwrap() {
//                                         ByteResponse::Merged(vec, start, _) => {
//                                             (Some(&vec[..*start]), &vec[*start..])
//                                         }
//                                         ByteResponse::Both(head, body, _) => {
//                                             (Some(&head[..]), &body[..])
//                                         }
//                                         ByteResponse::Body(body) => (None, &body[..]),
//                                         ByteResponse::BorrowedBody(borrow) => (None, &borrow[..]),
//                                     };
//                                     head = new_head;
//                                     body = new_body;
//                                 }
//                                 None => {}
//                             }
//                         },
//                         // }
//                         None => {}
//                     }
//                 }
//             }

//             if let Some(file_extension) = path.extension().and_then(OsStr::to_str) {
//                 match extensions.get_file_extension(file_extension) {
//                     Some(extension) => unsafe {
//                         let mut data = extensions_old::RequestData::new(
//                             address,
//                             head,
//                             body,
//                             content_start,
//                             &mut cached,
//                             Vec::new(),
//                             storage,
//                             &request,
//                             raw_request,
//                             &path,
//                             &mut content_type,
//                             close,
//                             host,
//                         );
//                         extension.run(&mut data);
//                         match data.into_response() {
//                             Some(new_response) => response = Some(new_response),
//                             None => {}
//                         }
//                     },
//                     None => {}
//                 }
//             }
//             if !allowed_method {
//                 byte_response = default_error(
//                     http::StatusCode::METHOD_NOT_ALLOWED,
//                     close,
//                     Some(storage.get_fs()),
//                 );
//             }
//             match response {
//                 Some(response) => byte_response = response,
//                 None => byte_response.remove_first(content_start),
//             }
//         }
//     }

//     if !cached.query_matters() {
//         let bytes = request.uri().path().as_bytes().to_vec(); // ToDo: Remove cloning of slice! Perhaps by Vec::from_raw?
//         if let Ok(uri) = http::Uri::from_maybe_shared(bytes) {
//             if let Some(lock) = host.get_cache() {
//                 if let Some(response) = lock.resolve(&uri, request.headers()) {
//                     return response.write_as_method(socket, request.method());
//                 };
//             }
//         }
//     }

//     // Check takes about 1 micro second for a 4MB image.
//     let valid_utf8 = std::str::from_utf8(byte_response.get_body()).is_ok();
//     let content_str = content_type.as_str_utf8(path, valid_utf8);

//     // The response MUST contain all vary headers, else it won't be cached!
//     let vary: Vec<&str> = vec!["Accept-Encoding"];

//     let compression = match request
//         .headers()
//         .get("Accept-Encoding")
//         .and_then(to_option_str)
//     {
//         Some(header) => {
//             let (algorithm, identity_forbidden) = compression::compression_from_header(header);
//             // Filter content types for compressed formats
//             if (content_str.starts_with("application")
//                 && !content_str.contains("xml")
//                 && !content_str.contains("json")
//                 && content_str != "application/pdf"
//                 && content_str != "application/javascript"
//                 && content_str != "application/graphql")
//                 || content_str.starts_with("image")
//                 || content_str.starts_with("audio")
//                 || content_str.starts_with("video")
//                 || content_str.starts_with("font")
//             {
//                 if identity_forbidden {
//                     byte_response = default_error(
//                         http::StatusCode::NOT_ACCEPTABLE,
//                         &close,
//                         Some(&mut storage.fs),
//                     );
//                     algorithm
//                 } else {
//                     compression::CompressionAlgorithm::Identity
//                 }
//             } else {
//                 algorithm
//             }
//         }
//         None => compression::CompressionAlgorithm::Identity,
//     };

//     let response = match byte_response {
//         ByteResponse::Merged(_, _, partial_header) | ByteResponse::Both(_, _, partial_header)
//             if partial_header =>
//         {
//             let partial_head = byte_response.get_head().unwrap();
//             let mut head = Vec::with_capacity(2048);
//             if !partial_head.starts_with(b"HTTP") {
//                 head.extend(b"HTTP/1.1 200 OK\r\n");
//             }
//             // Adding partial head
//             head.extend_from_slice(partial_head);
//             // Remove last CRLF if, header doesn't end here!
//             if head.ends_with(&[CR, LF]) {
//                 head.truncate(head.len() - 2);
//             }
//             // Parse the present headers
//             let present_headers = parse::parse_only_headers(partial_head);
//             let compress = !present_headers.contains_key(CONTENT_ENCODING);
//             let varies = present_headers.contains_key(VARY);
//             let body = if compress && !varies {
//                 compression::Compressors::compress(byte_response.get_body(), &compression)
//             } else {
//                 byte_response.into_body()
//             };

//             use http::header::*;

//             if !present_headers.contains_key(CONNECTION) {
//                 head.extend(b"Connection: ");
//                 head.extend(close.as_bytes());
//                 head.extend(LINE_ENDING);
//             }
//             if compress && !varies {
//                 // Compression
//                 head.extend(b"Content-Encoding: ");
//                 head.extend(compression.as_bytes());
//                 head.extend(LINE_ENDING);
//             }
//             if !present_headers.contains_key(CONTENT_LENGTH) {
//                 // Length
//                 head.extend(b"Content-Length: ");
//                 head.extend(body.len().to_string().as_bytes());
//                 head.extend(LINE_ENDING);
//             }

//             if !present_headers.contains_key(CONTENT_TYPE) {
//                 head.extend(b"Content-Type: ");
//                 head.extend(content_str.as_bytes());
//                 head.extend(LINE_ENDING);
//             }
//             if !present_headers.contains_key(CACHE_CONTROL) {
//                 // Cache header!
//                 head.extend(cached.as_bytes());
//             }

//             if !varies && !vary.is_empty() {
//                 head.extend(b"Vary: ");
//                 let mut iter = vary.iter();
//                 head.extend(iter.next().unwrap().as_bytes());

//                 for vary in iter {
//                     head.extend(b", ");
//                     head.extend(vary.as_bytes());
//                 }
//                 head.extend(LINE_ENDING);
//             }

//             // Add server signature
//             head.extend(SERVER_HEADER);
//             // Close header
//             head.extend(LINE_ENDING);

//             // Return byte response
//             ByteResponse::Both(head, body, false)
//         }
//         ByteResponse::Body(_) | ByteResponse::BorrowedBody(_) => {
//             let mut response = Vec::with_capacity(4096);
//             response.extend(b"HTTP/1.1 200 OK\r\n");
//             response.extend(b"Connection: ");
//             response.extend(close.as_bytes());
//             response.extend(LINE_ENDING);
//             // Compression
//             response.extend(b"Content-Encoding: ");
//             response.extend(compression.as_bytes());
//             response.extend(LINE_ENDING);
//             let body = compression::Compressors::compress(byte_response.get_body(), &compression);
//             // Length
//             response.extend(b"Content-Length: ");
//             response.extend(body.len().to_string().as_bytes());
//             response.extend(LINE_ENDING);

//             response.extend(b"Content-Type: ");
//             response.extend(content_str.as_bytes());
//             response.extend(LINE_ENDING);
//             // Cache header!
//             response.extend(cached.as_bytes());

//             if !vary.is_empty() {
//                 response.extend(b"Vary: ");
//                 let mut iter = vary.iter();
//                 // Can unwrap, since it isn't empty!
//                 response.extend(iter.next().unwrap().as_bytes());

//                 for vary in iter {
//                     response.extend(b", ");
//                     response.extend(vary.as_bytes());
//                 }
//                 response.extend(LINE_ENDING);
//             }

//             response.extend(SERVER_HEADER);
//             // Close header
//             response.extend(LINE_ENDING);

//             // Return byte response
//             ByteResponse::Both(response, body, false)
//         }
//         // Headers handled! Taking for granted user handled HEAD method.
//         _ => byte_response,
//     };

//     // Write to socket!
//     response.write_as_method(socket, request.method())?;

//     if is_get && cached.do_internal_cache() {
//         if let Some(mut lock) = host.get_cache() {
//             #[cfg(feature = "info-log")]
//             println!(
//                 "Caching uri {} on host {:?}",
//                 request.uri(),
//                 request.headers().get("host")
//             );
//             let uri = request.into_parts().0.uri;

//             let uri = if !cached.query_matters() {
//                 let bytes = uri.path().as_bytes().to_vec(); // ToDo: Remove cloning of slice! Perhaps by Vec::from_raw?
//                 if let Ok(uri) = http::Uri::from_maybe_shared(bytes) {
//                     uri
//                 } else {
//                     uri
//                 }
//             } else {
//                 uri
//             };
//             match vary.is_empty() {
//                 false => {
//                     let headers = {
//                         let headers = parse::parse_only_headers(response.get_head().unwrap());
//                         let mut is_ok = true;
//                         let mut buffer = Vec::with_capacity(vary.len());
//                         for vary_header in vary.iter() {
//                             let header = match *vary_header {
//                                 "Accept-Encoding" => "Content-Encoding",
//                                 _ => *vary_header,
//                             };
//                             match headers.get(header) {
//                                 Some(header) => {
//                                     buffer.push(header.clone()) // ToDo: Remove in future by iterating over and adding matching items.
//                                 }
//                                 None => {
//                                     is_ok = false;
//                                     break;
//                                 }
//                             }
//                         }
//                         match is_ok {
//                             true => Some(buffer),
//                             false => None,
//                         }
//                     };
//                     match headers {
//                         Some(headers) => {
//                             let _ = lock.add_variant(uri, response, headers, &vary[..]);
//                         }
//                         None => {
//                             #[cfg(feature = "info-log")]
//                             eprintln!("Vary header not present in response! Will not cache.")
//                         }
//                     }
//                 }
//                 true => {
//                     let _ = lock.cache(uri, Arc::new(cache_old::CacheType::with_data(response)));
//                 }
//             }
//         }
//     }
//     Ok(())
// }

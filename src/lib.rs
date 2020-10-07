pub use cache::Cache;
pub use config::{Config, FsCache, FunctionBindings, ResponseCache};
use http::{Request, StatusCode, Uri};
use mime_guess;
use mio::net::TcpStream;
use mio::Token;
use rustls::{ServerSession, Session};
use std::borrow::Cow;
use std::convert::From;
use std::path::PathBuf;
use std::sync::Arc;
use std::{
  fs::File,
  io::{self, Read, Write},
};
mod threading;

const HTTPS_SERVER: Token = Token(0);
const RESERVED_TOKENS: usize = 1024;

pub mod config {
  use super::{threading::HandlerPool, Cache, Connection, MioEvent};
  use super::{HTTPS_SERVER, RESERVED_TOKENS};
  use http::{Request, Uri};
  use mio::net::TcpListener;
  use mio::{Events, Interest, Poll, Token};
  use rustls::ServerConfig;
  use std::collections::HashMap;
  use std::io::ErrorKind;
  use std::net::{IpAddr, Ipv4Addr, SocketAddr};
  use std::path::PathBuf;
  use std::sync::{Arc, Mutex};

  type Binding = dyn Fn(&mut Vec<u8>, &Request<&[u8]>) -> (&'static str, bool) + Send + Sync;
  pub type FsCache = Arc<Mutex<Cache<PathBuf, Vec<u8>>>>;
  pub type ResponseCache = Arc<Mutex<Cache<Uri, Vec<u8>>>>;

  /// Function bindings to have fast dynamic pages.
  ///
  /// Functions can be associated with URLs by calling the `bind` function.
  pub struct FunctionBindings {
    map: HashMap<
      String,
      Box<dyn Fn(&mut Vec<u8>, &Request<&[u8]>) -> (&'static str, bool) + Send + Sync>,
    >,
  }
  #[allow(dead_code)]
  impl FunctionBindings {
    /// Creates a new, empty set of bindings.
    ///
    /// Use `bind` to populate it
    #[inline]
    pub fn new() -> Self {
      FunctionBindings {
        map: HashMap::new(),
      }
    }
    /// Binds a function to a path
    ///
    /// Fn needs to return a tuple with the content type (e.g. "text/html"), and whether the return value should be cached or not
    /// # Examples
    /// ```
    /// use arktis::FunctionBindings;
    ///
    /// let mut bindings = FunctionBindings::new();
    ///
    /// bindings.bind(String::from("/test"), |buffer, uri| {
    ///    buffer.extend(b"<h1>Welcome to my site!</h1> You are calling: ".iter());
    ///    buffer.extend(format!("{}", uri).as_bytes());
    ///
    ///    ("text/html", true)
    /// });
    /// ```
    #[inline]
    pub fn bind<F>(&mut self, path: String, callback: F)
    where
      F: Fn(&mut Vec<u8>, &Request<&[u8]>) -> (&'static str, bool) + 'static + Send + Sync,
    {
      self.map.insert(path, Box::new(callback));
    }
    #[inline]
    pub fn unbind(&mut self, path: &str) -> Option<()> {
      self.map.remove(path).and(Some(()))
    }
    /// Gets the function associated with the URL, if there is one.
    #[inline]
    pub fn get(&self, path: &str) -> Option<&Box<Binding>> {
      self.map.get(path)
    }
  }

  pub struct Config {
    socket: TcpListener,
    connections: HashMap<Token, Connection>,
    server_config: Arc<ServerConfig>,
    con_id: usize,
    // handler: HandlerPool,
    bindings: Arc<FunctionBindings>,
    fs_cache: FsCache,
    response_cache: ResponseCache,
  }
  #[allow(dead_code)]
  impl Config {
    // pub fn on_port(port: u16) -> Self {
    //   Config {
    //     socket: TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
    //       .expect("Failed to bind to port"),
    //     server_config: Arc::new(
    //       server_config::get_server_config("cert.pem", "privkey.pem")
    //         .expect("Failed to read certificate"),
    //     ),
    //     bindings: Arc::new(FunctionBindings::new()),
    //     fs_cache: Arc::new(Mutex::new(Cache::new())),
    //     response_cache: Arc::new(Mutex::new(Cache::new())),
    //   }
    // }
    // pub fn with_config_on_port(config: ServerConfig, port: u16) -> Self {
    //   Config {
    //     socket: TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
    //       .expect("Failed to bind to port"),
    //     server_config: Arc::new(config),
    //     bindings: Arc::new(FunctionBindings::new()),
    //     fs_cache: Arc::new(Mutex::new(Cache::new())),
    //     response_cache: Arc::new(Mutex::new(Cache::new())),
    //   }
    // }
    // pub fn with_bindings(bindings: FunctionBindings, port: u16) -> Self {
    //   Config {
    //     socket: TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
    //       .expect("Failed to bind to port"),
    //     server_config: Arc::new(
    //       server_config::get_server_config("cert.pem", "privkey.pem")
    //         .expect("Failed to read certificate"),
    //     ),
    //     bindings: Arc::new(bindings),
    //     fs_cache: Arc::new(Mutex::new(Cache::new())),
    //     response_cache: Arc::new(Mutex::new(Cache::new())),
    //   }
    // }
    pub fn new(config: ServerConfig, bindings: FunctionBindings, port: u16) -> Self {
      let server_config = Arc::new(config);
      let fs_cache = Arc::new(Mutex::new(Cache::new()));
      let response_cache = Arc::new(Mutex::new(Cache::new()));
      let bindings = Arc::new(bindings);

      Config {
        socket: TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
          .expect("Failed to bind to port"),
        server_config,
        connections: HashMap::new(),
        con_id: RESERVED_TOKENS,
        fs_cache,
        response_cache,
        bindings,
      }
    }

    pub fn get_fs_cache(&self) -> FsCache {
      Arc::clone(&self.fs_cache)
    }
    pub fn get_response_cache(&self) -> ResponseCache {
      Arc::clone(&self.response_cache)
    }
    pub fn get_config(&self) -> Arc<ServerConfig> {
      Arc::clone(&self.server_config)
    }
    pub fn get_bindings(&self) -> Arc<FunctionBindings> {
      Arc::clone(&self.bindings)
    }

    /// Runs a server from the config on a new thread, not blocking the current thread.
    ///
    /// Use a loop to capture the main thread.
    ///
    /// # Examples
    /// ```
    /// use arktis::Config;
    /// use std::io::{stdin, BufRead};
    ///
    /// let server = Config::on_port(443);
    /// let fc = server.get_fs_cache();
    /// let rc = server.get_response_cache();
    /// server.run();
    ///
    /// for line in stdin().lock().lines() {
    ///     if let Ok(line) = line {
    ///         let mut words = line.split(" ");
    ///         if let Some(command) = words.next() {
    ///             match command {
    ///                 "crc" => {
    ///                     let mut rc = rc.lock().unwrap();
    ///                     rc.clear();
    ///                     println!("Cleared response cache!");
    ///                 }
    ///                 "cfc" => {
    ///                     let mut rc = rc.lock().unwrap();
    ///                     rc.clear();
    ///                     println!("Cleared file system cache!");
    ///                 }
    ///                 _ => {
    ///                     eprintln!("Unknown command!");
    ///                 }
    ///             }
    ///         }
    ///     };
    /// }
    ///
    /// ```
    pub fn run(mut self) {
      let mut poll = Poll::new().expect("Failed to create a poll instance");
      let mut events = Events::with_capacity(1024);
      poll
        .registry()
        .register(&mut self.socket, HTTPS_SERVER, Interest::READABLE)
        .expect("Failed to register HTTPS server");

      let mut handler = HandlerPool::new(
        self.get_config(),
        self.get_fs_cache(),
        self.get_response_cache(),
        self.get_bindings(),
        poll.registry(),
      );

      loop {
        poll.poll(&mut events, None).expect("Failed to poll!");

        for event in events.iter() {
          match event.token() {
            HTTPS_SERVER => {
              self
                .accept_handler(&mut handler)
                .expect("Failed to accept message!");
            }
            _ => {
              handler.handle(MioEvent::from_event(event));
            }
          }
        }
      }
    }
    fn next_id(&mut self) -> usize {
      self.con_id = match self.con_id.checked_add(1) {
        Some(id) => id,
        None => RESERVED_TOKENS,
      };
      self.con_id
    }

    pub fn accept(&mut self, registry: &mio::Registry) -> Result<(), std::io::Error> {
      loop {
        match self.socket.accept() {
          Ok((socket, addr)) => {
            println!("Accepting new connection from: {:?}", addr);

            let session = rustls::ServerSession::new(&self.server_config);
            let response_cache = self.get_response_cache();
            let fs_cache = self.get_fs_cache();
            let bindings = self.get_bindings();

            let token = Token(self.next_id());
            println!("Inserting with token {}", token.0);

            let mut connection =
              Connection::new(socket, token, session, fs_cache, response_cache, bindings);

            connection.register(&registry);
            self.connections.insert(token, connection);
            // let token = Token(self.next_id());
            // self.handler.accept(socket, addr, registry, token);
          }
          Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
          Err(err) => {
            eprintln!("Encountered error while accepting connection. {:?}", err);
            return Err(err);
          }
        }
      }
    }
    pub fn accept_handler(&mut self, handler: &mut HandlerPool) -> Result<(), std::io::Error> {
      loop {
        match self.socket.accept() {
          Ok((socket, addr)) => {
            let token = Token(self.next_id());
            handler.accept(socket, addr, token);
          }
          Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
          Err(err) => {
            eprintln!("Encountered error while accepting connection. {:?}", err);
            return Err(err);
          }
        }
      }
    }

    pub fn new_con(&mut self, registry: &mio::Registry, event: &MioEvent) {
      let token = event.token();

      if let Some(connection) = self.connections.get_mut(&token) {
        connection.ready(registry, event);
        if connection.is_closed() {
          self.connections.remove(&token);
        }
      } else {
        eprintln!("Connection not found!");
      }
    }
  }

  pub mod server_config {
    use rustls::{internal::pemfile, NoClientAuth, ServerConfig};
    use std::{
      fs::File,
      io::{self, BufReader},
      path::Path,
    };

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
      let mut chain = BufReader::new(File::open(&cert_path)?);
      let mut private_key = BufReader::new(File::open(&private_key_path)?);

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
  }
}

pub struct Connection {
  socket: TcpStream,
  token: Token,
  session: rustls::ServerSession,
  closing: bool,

  fs_cache: FsCache,
  response_cache: ResponseCache,
  bindings: Arc<FunctionBindings>,
}
impl Connection {
  pub fn new(
    socket: TcpStream,
    token: Token,
    session: ServerSession,
    fs_cache: FsCache,
    response_cache: ResponseCache,
    bindings: Arc<FunctionBindings>,
  ) -> Self {
    Self {
      socket,
      token,
      session,
      closing: false,
      fs_cache,
      response_cache,
      bindings,
    }
  }

  pub fn ready(&mut self, registry: &mio::Registry, event: &MioEvent) {
    // If socket is readable, read from socket to session
    if event.readable() && self.decrypt().is_ok() {
      // Read request from session to buffer
      let request = {
        let mut buffer = Vec::with_capacity(4096);
        match self.session.read_to_end(&mut buffer) {
          Err(err) => {
            eprintln!("Failed to read from session! {:?}", err);
            self.close();
          }
          Ok(..) => {}
        };
        buffer
      };
      // If not empty, parse and process it!
      if !request.is_empty() {
        if request.len() > 1024 * 16 {
          eprintln!("Request too large!");
        }
        let close = match parse::parse_request(&request[..]) {
          Ok(parsed) => {
            let close = ConnectionHeader::from_close({
              match parsed.headers().get("connection") {
                Some(connection) => connection == http::header::HeaderValue::from_static("close"),
                None => false,
              }
            });
            if let Err(err) = process_request(
              &mut self.session,
              parsed,
              &request[..],
              &close,
              &mut self.fs_cache,
              &mut self.response_cache,
              &self.bindings,
            ) {
              eprintln!("Failed to write to session! {:?}", err);
            };
            close
          }
          Err(err) => {
            eprintln!(
              "Failed to parse request, write something as a response? Err: {:?}",
              err
            );
            let _ = self
              .session
              .write_all(&default_error(400, &ConnectionHeader::Close, &mut self.fs_cache)[..]);
            ConnectionHeader::Close
          }
        };
        // If request is unsupported, do something
        if close.close() {
          self.session.send_close_notify();
        };
      }
    }
    if event.writable() {
      if let Err(..) = self.session.write_tls(&mut self.socket) {
        eprintln!("Error writing to socket!");
        self.close();
      };
    }

    if self.closing {
      println!("Closing connection!");
      let _ = self.socket.shutdown(std::net::Shutdown::Both);
      self.deregister(registry);
    } else {
      self.reregister(registry);
    };
  }
  fn decrypt(&mut self) -> Result<(), ()> {
    // Loop on read_tls
    match self.session.read_tls(&mut self.socket) {
      Err(err) => {
        if let io::ErrorKind::WouldBlock = err.kind() {
          eprintln!("Would block!");
          return Err(());
        } else {
          self.close();
          return Err(());
        }
      }
      Ok(0) => {
        self.close();
        return Err(());
      }
      _ => {
        if self.session.process_new_packets().is_err() {
          eprintln!("Failed to process packets");
          self.close();
          return Err(());
        };
      }
    };
    Ok(())
  }

  #[inline]
  pub fn register(&mut self, registry: &mio::Registry) {
    let es = self.event_set();
    registry
      .register(&mut self.socket, self.token, es)
      .expect("Failed to register connection!");
  }
  #[inline]
  pub fn reregister(&mut self, registry: &mio::Registry) {
    let es = self.event_set();
    registry
      .reregister(&mut self.socket, self.token, es)
      .expect("Failed to register connection!");
  }
  #[inline]
  pub fn deregister(&mut self, registry: &mio::Registry) {
    registry
      .deregister(&mut self.socket)
      .expect("Failed to register connection!");
  }

  fn event_set(&self) -> mio::Interest {
    let rd = self.session.wants_read();
    let wr = self.session.wants_write();

    if rd && wr {
      mio::Interest::READABLE | mio::Interest::WRITABLE
    } else if wr {
      mio::Interest::WRITABLE
    } else {
      mio::Interest::READABLE
    }
  }

  #[inline]
  pub fn is_closed(&self) -> bool {
    self.closing
  }
  #[inline]
  fn close(&mut self) {
    self.closing = true;
  }
}

pub mod parse {
  use http::{header::*, Method, Request, Uri, Version};

  enum DecodeStage {
    Method,
    Path,
    Version,
    HeaderName(i32),
    HeaderValue(i32),
  }
  impl DecodeStage {
    fn next(&mut self) {
      *self = match self {
        DecodeStage::Method => DecodeStage::Path,
        DecodeStage::Path => DecodeStage::Version,
        DecodeStage::Version => DecodeStage::HeaderName(0),
        DecodeStage::HeaderName(n) => DecodeStage::HeaderValue(*n),
        DecodeStage::HeaderValue(n) => DecodeStage::HeaderName(*n + 1),
      }
    }
  }
  const LF: u8 = 10;
  const CR: u8 = 13;
  const SPACE: u8 = 32;
  const COLON: u8 = 58;
  pub fn parse_request(buffer: &[u8]) -> Result<Request<&[u8]>, http::Error> {
    let mut parse_stage = DecodeStage::Method;
    let mut method = [0; 7];
    let mut method_index = 0;
    let mut path = Vec::with_capacity(32);
    let mut version = [0; 8];
    let mut version_index = 0;
    let mut parsed = Request::builder();
    let mut current_header_name = Vec::new();
    let mut current_header_value = Vec::new();
    let mut lf_in_row = 0;
    let mut last_header_byte = 0;
    for byte in buffer {
      last_header_byte += 1;
      if *byte == CR {
        continue;
      }
      if *byte == LF {
        lf_in_row += 1;
        if lf_in_row == 2 {
          break;
        }
      } else {
        lf_in_row = 0;
      }
      match parse_stage {
        DecodeStage::Method => {
          if *byte == SPACE || method_index == method.len() {
            parse_stage.next();
            continue;
          }
          method[method_index] = *byte;
          method_index += 1;
        }
        DecodeStage::Path => {
          if *byte == SPACE {
            parse_stage.next();
            continue;
          }
          path.push(*byte);
        }
        DecodeStage::Version => {
          if *byte == LF || version_index == version.len() {
            parse_stage.next();
            continue;
          }
          version[version_index] = *byte;
          version_index += 1;
        }
        DecodeStage::HeaderName(..) => {
          if *byte == COLON {
            continue;
          }
          if *byte == SPACE {
            parse_stage.next();
            continue;
          }
          current_header_name.push(*byte);
        }
        DecodeStage::HeaderValue(..) => {
          if *byte == LF {
            let name = HeaderName::from_bytes(&current_header_name[..]);
            let value = HeaderValue::from_bytes(&current_header_value[..]);
            if name.is_ok() && value.is_ok() {
              parsed = parsed.header(name.unwrap(), value.unwrap());
            }
            current_header_name.clear();
            current_header_value.clear();
            parse_stage.next();
            continue;
          }
          current_header_value.push(*byte);
        }
      };
    }
    parsed
      .method(Method::from_bytes(&method[..]).unwrap_or(Method::GET))
      .uri(Uri::from_maybe_shared(path).unwrap_or(Uri::from_static("/")))
      .version(match &version[..] {
        b"HTTP/0.9" => Version::HTTP_09,
        b"HTTP/1.0" => Version::HTTP_10,
        b"HTTP/1.1" => Version::HTTP_11,
        b"HTTP/2" => Version::HTTP_2,
        b"HTTP/2.0" => Version::HTTP_2,
        b"HTTP/3" => Version::HTTP_3,
        b"HTTP/3.0" => Version::HTTP_3,
        _ => Version::default(),
      })
      .body(&buffer[last_header_byte..])
  }
}
pub mod cache {
  use std::collections::HashMap;
  use std::sync::Arc;

  pub trait Count {
    fn count(&self) -> usize;
  }
  impl<T> Count for Vec<T> {
    fn count(&self) -> usize {
      self.len()
    }
  }
  impl<T> Count for Arc<Vec<T>> {
    fn count(&self) -> usize {
      self.len()
    }
  }
  impl<K, V> Count for HashMap<K, V> {
    fn count(&self) -> usize {
      self.len()
    }
  }
  pub struct Cache<K, V> {
    map: HashMap<K, Arc<V>>,
    max_items: usize,
    size_limit: usize,
  }
  #[allow(dead_code)]
  impl<K: std::cmp::Eq + std::hash::Hash + std::clone::Clone, V: Count> Cache<K, V> {
    #[inline]
    pub fn cache(&mut self, key: K, value: Arc<V>) -> Option<Arc<V>> {
      if value.count() > self.size_limit {
        return Some(value);
      }
      // fn get_first<K: std::clone::Clone, V>(map: &HashMap<K, V>) -> Option<K> {
      //   map.iter().next().and_then(|value| Some(value.0.clone()))
      // };
      if self.map.len() >= self.max_items {
        // Reduce number of items!
        if let Some(last) = self
          .map
          .iter()
          .next()
          .and_then(|value| Some(value.0.clone()))
        {
          self.map.remove(&last);
        }
      }
      self.map.insert(key, value);
      None
    }
  }
  impl<K: std::cmp::Eq + std::hash::Hash + std::clone::Clone, V> Cache<K, V> {
    pub fn new() -> Self {
      Cache {
        map: HashMap::new(),
        max_items: 1024,
        size_limit: 4194304, // 4MiB
      }
    }
    pub fn with_max(max_items: usize) -> Self {
      assert!(max_items > 1);
      Cache {
        map: HashMap::new(),
        max_items,
        size_limit: 4194304,
      }
    }
    pub fn with_max_and_size(max_items: usize, size_limit: usize) -> Self {
      assert!(max_items > 1);
      assert!(size_limit >= 1024);

      Cache {
        map: HashMap::new(),
        max_items,
        size_limit,
      }
    }
    #[inline]
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
      self.map.get(key).and_then(|value| Some(Arc::clone(value)))
    }
    #[inline]
    pub fn cached(&self, key: &K) -> bool {
      self.map.contains_key(key)
    }
    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<Arc<V>> {
      self.map.remove(key)
    }
    #[inline]
    pub fn clear(&mut self) {
      self.map.clear()
    }
  }
}

#[derive(PartialEq)]
enum ConnectionHeader {
  KeepAlive,
  Close,
}
impl ConnectionHeader {
  fn from_close(close: bool) -> Self {
    if close {
      Self::Close
    } else {
      Self::KeepAlive
    }
  }
  fn close(&self) -> bool {
    *self == Self::Close
  }
}
pub struct MioEvent {
  writable: bool,
  readable: bool,
  token: usize,
}
impl MioEvent {
  fn from_event(event: &mio::event::Event) -> Self {
    Self {
      writable: event.is_writable(),
      readable: event.is_readable(),
      token: event.token().0,
    }
  }
  fn writable(&self) -> bool {
    self.writable
  }
  fn readable(&self) -> bool {
    self.readable
  }
  fn token(&self) -> Token {
    Token(self.token)
  }
  fn raw_token(&self) -> usize {
    self.token
  }
}

#[cfg(windows)]
static SERVER_HEADER: &[u8] = b"Server: Arktis/0.1.0 (Windows)\r\n";
#[cfg(unix)]
static SERVER_HEADER: &[u8] = b"Server: Arktis/0.1.0 (Unix)\r\n";

fn process_request<W: Write>(
  mut socket: &mut W,
  request: Request<&[u8]>,
  raw_request: &[u8],
  close: &ConnectionHeader,
  mut fs_cache: &mut FsCache,
  response_cache: &mut ResponseCache,
  bindings: &Arc<FunctionBindings>,
) -> Result<(), io::Error> {
  // println!("Got request: {:?}", &request);
  // Load from cache
  {
    // Get response cache lock
    let response_cache = response_cache.lock().unwrap();
    // If response is in cache
    if let Some(response) = response_cache.get(request.uri()) {
      // println!("Getting from cache!");
      socket.write_all(&response[..])?;
      return Ok(());
    }
  }
  let mut write_headers = true;
  // If a function exists
  let (body, content_type, cache) = match bindings.get(request.uri().path()) {
    Some(callback) => {
      let mut body = Vec::with_capacity(4096);
      let (content_type, cache) = callback(&mut body, &request);
      (Arc::new(body), Cow::Borrowed(content_type), cache)
    }
    None => {
      // FS
      let path = match convert_uri(request.uri()) {
        Ok(path) => path,
        Err(()) => {
          socket.write_all(&default_error(403, close, &mut fs_cache)[..])?;
          return Ok(());
        }
      };
      let body = match read_file(&path, &mut fs_cache) {
        Some(response) => response,
        None => {
          socket.write_all(&default_error(404, close, &mut fs_cache)[..])?;
          return Ok(());
        }
      };
      let mut do_cache = true;
      // Read file etc...
      let mut iter = body.iter();
      static LF: u8 = 10;
      static CR: u8 = 13;
      static SPACE: u8 = 32;
      static BANG: u8 = 33;
      static PIPE: u8 = 62;
      // println!("Data: '{}'", String::from_utf8_lossy(&body[..100]));
      // println!("Data: {}, {}", iter.next().unwrap(), iter.next().unwrap());
      if iter.next() == Some(&BANG) && iter.next() == Some(&PIPE) {
        // We have a file to interpret
        let interpreter = {
          let mut buffer = Vec::with_capacity(8);
          let mut last_break = 2;
          let mut current_index = 2;
          for byte in iter {
            if *byte == CR || *byte == LF {
              if current_index - last_break > 1 {
                buffer.push(&body[last_break..current_index]);
              }
              break;
            }
            if *byte == SPACE && current_index - last_break > 1 {
              buffer.push(&body[last_break..current_index]);
            }
            current_index += 1;
            if *byte == SPACE {
              last_break = current_index;
            }
          }
          buffer
        };
        println!("Found: {} items", interpreter.len());

        for item in &interpreter {
          println!("Got text: '{}'", String::from_utf8_lossy(item));
        }
        if let Some(test) = interpreter.get(0) {
          match test {
            &b"php" if interpreter.len() > 0 => {
              println!("Handle php!");
              match handle_php(&mut socket, raw_request, &path) {
                Ok(..) => {
                  // Don't write headers!
                  write_headers = false;
                  // Check cache settings
                  do_cache = match interpreter.get(1) {
                    Some(cache) => {
                      match cache {
                        &b"false" | &b"no-cache" | &b"nocache" => false,
                        _ => true,
                      }
                      // String::from_utf8_lossy(cache).parse().unwrap_or(true)
                    }
                    None => true,
                  };
                }
                _ => {}
              };
            }
            _ => {}
          }
        }
      };

      let content_type = format!("{}", mime_guess::from_path(&path).first_or_octet_stream());
      (body, Cow::Owned(content_type), do_cache)
    }
  };
  let response = if write_headers {
    let mut response = Vec::with_capacity(512);
    // Revert connection to keep-alive in future
    response.extend(
      b"HTTP/1.1 200 OK\r\n\
    Connection: "
        .iter(),
    );
    if close.close() {
      response.extend(b"Close\r\n".iter());
    } else {
      response.extend(b"Keep-Alive\r\n".iter());
    }
    response.extend(b"Content-Length: ".iter());
    response.extend(format!("{}\r\n", body.len()).as_bytes());
    response.extend(b"Content-Type: ".iter());
    response.extend(content_type.as_bytes());
    response.extend(b"\r\n");
    response.extend(SERVER_HEADER);
    response.extend(b"\r\n");
    response.extend(body.iter());

    socket.write_all(&response[..])?;
    Arc::new(response)
  } else {
    socket.write_all(&body[..])?;
    body
  };

  if cache {
    println!("Caching!");
    let mut response_cache = response_cache.lock().unwrap();
    response_cache.cache(request.into_parts().0.uri, response);
  }
  Ok(())
}
fn convert_uri(uri: &Uri) -> Result<PathBuf, ()> {
  let mut path = uri.path();
  if path.contains("../") {
    return Err(());
  }
  let is_dir = path.ends_with("/");
  path = path.split_at(1).1;

  let mut buf = PathBuf::from("public");
  buf.push(path);
  if is_dir {
    buf.push("index.html");
  };
  Ok(buf)
}

fn default_error(code: u16, close: &ConnectionHeader, cache: &mut FsCache) -> Vec<u8> {
  let mut buffer = Vec::with_capacity(1024);

  buffer.extend(b"HTTP/1.1 ");
  buffer.extend(
    format!(
      "{}\r\n",
      StatusCode::from_u16(code).unwrap_or(StatusCode::from_u16(500).unwrap())
    )
    .as_bytes(),
  );
  buffer.extend(
    b"Content-Type: text/html\r\n\
    Connection: "
      .iter(),
  );
  if close.close() {
    buffer.extend(b"Close\r\n".iter());
  } else {
    buffer.extend(b"Keep-Alive\r\n".iter());
  }

  fn get_default(code: u16) -> &'static [u8] {
    // Hard-coded defaults
    match code {
      404 => &b"<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1><hr><a href='/'>Return home</a></center></body></html>"[..],
      _ => &b"<html><head><title>Unknown Error</title></head><body><center><h1>An unexpected error occurred, <a href='/'>return home?</a></h1></center></body></html>"[..],
    }
  }

  match read_file(&PathBuf::from(format!("{}.html", code)), cache) {
    Some(file) => {
      buffer.extend(b"Content-Length: ");
      buffer.extend(format!("{}\r\n\r\n", file.len()).as_bytes());
      buffer.extend(&file[..]);
    }
    None => {
      let error = get_default(code);
      buffer.extend(b"Content-Length: ");
      buffer.extend(format!("{}\r\n\r\n", error.len()).as_bytes());
      buffer.extend(error);
    }
  };

  buffer
}

fn read_file(path: &PathBuf, cache: &mut FsCache) -> Option<Arc<Vec<u8>>> {
  {
    let cache = cache.lock().unwrap();
    if let Some(cached) = cache.get(&path) {
      return Some(cached);
    }
  }

  match File::open(path) {
    Ok(mut file) => {
      let mut buffer = Vec::with_capacity(4096);
      match file.read_to_end(&mut buffer) {
        Ok(..) => {
          let mut cache = cache.lock().unwrap();
          Some(match cache.cache(path.clone(), Arc::new(buffer)) {
            Some(failed) => failed,
            None => cache.get(&path).unwrap(),
          })
        }
        Err(..) => None,
      }
    }
    Err(..) => None,
  }
}

#[allow(unused_variables)]
fn handle_php<W: Write>(socket: &mut W, request: &[u8], path: &PathBuf) -> Result<(), io::Error> {
  unimplemented!();
  use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};

  let attention: i32;
  // Take the thread name and make a file of that instead. Try the line for line mode instead.
  let mut tmp = File::create("tmp.php")?;
  let mut file = File::open(path)?;
  let mut buffer = [0; 4096];
  let mut first = true;
  loop {
    let read = file.read(&mut buffer)?;
    if read == 0 {
      break;
    }
    if first {
      let read_till = {
        let mut out = 0;
        for byte in buffer.iter() {
          out += 1;
          if *byte == 10 {
            break;
          }
        }
        out
      };
      println!("Discard first {}", read_till);
      tmp.write_all(&mut &buffer[read_till..read])?;
      first = false;
    } else {
      tmp.write_all(&mut buffer[..read])?;
    }
  }

  let mut php =
    match TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6633))) {
      Err(err) => {
        panic!("Failed to get PHP: {:?}", err);
      }
      Ok(socket) => socket,
    };

  todo!("Change path to /tmp.php! Or implement interpreter!");
  php.write_all(request)?;
  loop {
    let mut buffer = [0; 4096];
    let read = php.read(&mut buffer)?;
    if read == 0 {
      break;
    }
    socket.write_all(&mut buffer[0..read])?;
  }

  Ok(())
}

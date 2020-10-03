pub use cache::Cache;
use http::{Request, StatusCode, Uri};
use mime_guess;
use rustls::{internal::pemfile, NoClientAuth, ServerConfig, ServerSession, Session};
use std::convert::From;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::{
  fs::File,
  io::{self, BufReader, Read, Write},
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

pub struct Config {
  socket: TcpListener,
  server_config: Arc<ServerConfig>,
  fs_cache: Arc<Mutex<Cache<PathBuf, Vec<u8>>>>,
  response_cache: Arc<Mutex<Cache<Uri, Vec<u8>>>>,
}
impl Config {
  pub fn on_port(port: u16) -> Self {
    Config {
      socket: TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .expect("Failed to bind to port"),
      server_config: Arc::new(
        get_server_config("cert.pem", "privkey.pem").expect("Failed to read certificate"),
      ),
      fs_cache: Arc::new(Mutex::new(Cache::new())),
      response_cache: Arc::new(Mutex::new(Cache::new())),
    }
  }
  pub fn with_config_on_port(config: ServerConfig, port: u16) -> Self {
    Config {
      socket: TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .expect("Failed to bind to port"),
      server_config: Arc::new(config),
      fs_cache: Arc::new(Mutex::new(Cache::new())),
      response_cache: Arc::new(Mutex::new(Cache::new())),
    }
  }

  pub fn get_fs_cache(&self) -> Arc<Mutex<Cache<PathBuf, Vec<u8>>>> {
    Arc::clone(&self.fs_cache)
  }
  pub fn get_response_cache(&self) -> Arc<Mutex<Cache<Uri, Vec<u8>>>> {
    Arc::clone(&self.response_cache)
  }
  fn get_config(&self) -> Arc<ServerConfig> {
    Arc::clone(&self.server_config)
  }

  pub fn run(self) {
    // To get responsive cmd, use MIO in future
    thread::spawn(move || {
      loop {
        match self.socket.accept() {
          Ok((mut socket, addr)) => {
            let config = self.get_config();
            let mut response_cache = self.get_response_cache();
            let mut fs_cache = self.get_fs_cache();
            // Move to separate thread
            thread::spawn(move || {
              use internal::{decrypt, DecryptResult::*};
              println!("New connection from {}!", addr);

              let mut session = ServerSession::new(&config);
              // loop {
              let request = match decrypt(&mut socket, &mut session) {
                Content(req) => req,
                StreamClosed => return,
                NoContent => return,
              };
              let request = match parse::parse_request(&request[..]) {
                Ok(req) => req,
                Err(err) => {
                  eprintln!(
                    "Failed to parse request, write something as a response? Err: {:?}",
                    err
                  );
                  return;
                }
              };
              // If request is unsupported, do something
              process_request(&mut session, request, &mut response_cache, &mut fs_cache);

              session.send_close_notify();
              let _ = session.write_tls(&mut socket);
              // }
              let _ = socket.shutdown(Shutdown::Both);
            });
          }
          Err(..) => {
            // eprintln!("Failed to accept connection: {}", err);
          }
        }
      }
    });
  }
}

pub mod internal {
  use rustls::{ServerSession, Session};
  use std::io::Read;
  use std::net::TcpStream;

  pub enum DecryptResult {
    Content(Vec<u8>),
    NoContent,
    StreamClosed,
  }

  pub fn decrypt(socket: &mut TcpStream, session: &mut ServerSession) -> DecryptResult {
    use DecryptResult::*;
    // Loop on read_tls
    loop {
      match session.read_tls(socket) {
        Err(..) => {
          // eprintln!("Error reading tls: {}", err);
          return StreamClosed;
        }
        Ok(0) => break,
        _ => {
          if session.process_new_packets().is_err() {
            return StreamClosed;
          };
          let mut buf = Vec::new();
          if session.read_to_end(&mut buf).is_err() {
            return StreamClosed;
          };
          if !buf.is_empty() {
            return Content(buf);
          }
          if session.wants_write() {
            if session.write_tls(socket).is_err() {
              return StreamClosed;
            };
          }
        }
      };
    }
    NoContent
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
    fn next(self) -> Self {
      match self {
        DecodeStage::Method => DecodeStage::Path,
        DecodeStage::Path => DecodeStage::Version,
        DecodeStage::Version => DecodeStage::HeaderName(0),
        DecodeStage::HeaderName(n) => DecodeStage::HeaderValue(n),
        DecodeStage::HeaderValue(n) => DecodeStage::HeaderName(n + 1),
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

  pub trait Len {
    fn len(&self) -> usize;
  }
  impl<T> Len for Vec<T> {
    fn len(&self) -> usize {
      self.len()
    }
  }
  impl<K, V> Len for HashMap<K, V> {
    fn len(&self) -> usize {
      self.len()
    }
  }
  pub struct Cache<K, V> {
    map: HashMap<K, V>,
    max_items: usize,
    size_limit: usize,
  }
  impl<K: std::cmp::Eq + std::hash::Hash + std::clone::Clone, V: Len> Cache<K, V> {
    pub fn new() -> Self {
      Cache {
        map: HashMap::new(),
        max_items: 1024,
        size_limit: 4194304, // 4MiB
      }
    }
    pub fn with_max(max_items: usize) -> Self {
      if max_items < 2 {
        panic!("Cache must have a maximum size of two or more");
      }
      Cache {
        map: HashMap::new(),
        max_items,
        size_limit: 4194304,
      }
    }
    pub fn with_max_and_size(max_items: usize, size_limit: usize) -> Self {
      if max_items < 2 {
        panic!("Cache must have a maximum size of two or more");
      }
      if size_limit < 1024 {
        panic!("Size limit must be above 1024");
      }
      Cache {
        map: HashMap::new(),
        max_items,
        size_limit,
      }
    }
    #[inline]
    pub fn cache(&mut self, key: K, value: V) -> Option<V> {
      if value.len() > self.size_limit {
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
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
      self.map.get(key)
    }
    #[inline]
    pub fn cached(&self, key: &K) -> bool {
      self.map.contains_key(key)
    }
    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<V> {
      self.map.remove(key)
    }
    #[inline]
    pub fn clear(&mut self) {
      self.map.clear()
    }
  }
}

static SERVER_HEADER: &[u8] = b"Server: Arktis/0.1.0\r\n";

pub fn process_request<W: Write>(
  socket: &mut W,
  request: Request<&[u8]>,
  response_cache: &mut Arc<Mutex<Cache<Uri, Vec<u8>>>>,
  mut fs_cache: &mut Arc<Mutex<Cache<PathBuf, Vec<u8>>>>,
) -> Result<(), io::Error> {
  {
    // Get response cache lock
    let response_cache = response_cache.lock().unwrap();
    // If response is in cache
    if let Some(response) = response_cache.get(request.uri()) {
      println!("Getting from cache!");
      socket.write_all(response)?;
      return Ok(());
    }
  }
  // todo!("Function bindings!");

  // FS
  let path = match convert_uri(&request.uri()) {
    Ok(path) => path,
    Err(()) => {
      socket.write_all(&default_error(403, &mut fs_cache)[..])?;
      return Ok(());
    }
  };
  let body = match read_file_alloc(&path, &mut fs_cache) {
    Some(response) => response,
    None => {
      socket.write_all(&default_error(404, &mut fs_cache)[..])?;
      return Ok(());
    }
  };
  // Read file etc...

  let mut response = Vec::with_capacity(512);
  // Revert connection to keep-alive in future
  response.extend(
    b"HTTP/1.1 200 OK\r\n\
    Connection: Close\r\n\
    Content-Length: "
      .iter(),
  );
  response.extend(format!("{}\r\n", body.len()).as_bytes());
  response.extend(b"Content-Type: ".iter());
  response.extend(
    format!(
      "{}\r\n",
      mime_guess::from_path(&path).first_or_octet_stream()
    )
    .as_bytes(),
  );
  response.extend(SERVER_HEADER);
  response.extend(b"\r\n");
  response.extend(body.iter());

  socket.write_all(&response[..])?;

  println!("{:?}", request);

  {
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

fn default_error(code: u16, cache: &mut Arc<Mutex<Cache<PathBuf, Vec<u8>>>>) -> Vec<u8> {
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
    Connection: Close\r\n"
      .iter(),
  );

  fn get_default(code: u16) -> &'static [u8] {
    // Hard-coded defaults
    match code {
      404 => &b"<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1><hr><a href='/'>Return home</a></center></body></html>"[..],
      _ => &b"<html><head><title>Unknown Error</title></head><body><center><h1>An unexpected error occurred, <a href='/'>return home?</a></h1></center></body></html>"[..],
    }
  }

  match read_file_alloc(&PathBuf::from(format!("{}.html", code)), cache) {
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

fn read_file_alloc(
  path: &PathBuf,
  cache: &mut Arc<Mutex<Cache<PathBuf, Vec<u8>>>>,
) -> Option<Vec<u8>> {
  {
    let cache = cache.lock().unwrap();
    if let Some(cached) = cache.get(&path) {
      return Some(cached.clone());
    }
  }

  match File::open(path) {
    Ok(mut file) => {
      let mut buffer = Vec::with_capacity(4096);
      match file.read_to_end(&mut buffer) {
        Ok(..) => {
          let mut cache = cache.lock().unwrap();
          Some(match cache.cache(path.clone(), buffer) {
            Some(failed) => failed,
            None => cache.get(&path).unwrap().clone(),
          })
        }
        Err(..) => None,
      }
    }
    Err(..) => None,
  }
}

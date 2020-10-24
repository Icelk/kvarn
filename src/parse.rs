use http::{header::*, Method, Request, Uri, Version};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;

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
  // Method is max 7 bytes long
  let mut method = [0; 7];
  let mut method_index = 0;
  let mut path = Vec::with_capacity(32);
  // Version is 8 bytes long
  let mut version = [0; 8];
  let mut version_index = 0;
  let mut parsed = Request::builder();
  let mut current_header_name = Vec::with_capacity(32);
  let mut current_header_value = Vec::with_capacity(128);
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
    .method(Method::from_bytes(&method[..method_index]).unwrap_or(Method::GET))
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

#[derive(Debug)]
pub struct HeaderInfo<'a> {
  url: Cow<'a, Uri>,
  queries: HashMap<&'a str, &'a str>,
  accept: Vec<ValueQualitySet<'a>>,
  accept_lang: Vec<ValueQualitySet<'a>>,
}
impl HeaderInfo<'_> {
  pub fn entire_known_url(&self) -> String {
    // Create with appropriate capacity
    let mut string = String::with_capacity(
      self
        .url
        .host()
        .and_then(|host| Some(host.len()))
        .unwrap_or(0)
        + self.url.path().len()
        + self
          .url
          .query()
          .and_then(|query| Some(query.len()))
          .unwrap_or(0),
    );
    if let Some(host) = self.url.host() {
      string.push_str(host);
    }
    string.push_str(self.url.path());
    if let Some(query) = self.url.query() {
      string.push_str(query);
    }
    string
  }
  pub fn host(&self) -> Option<&str> {
    self.url.host()
  }
  pub fn path(&self) -> &str {
    self.url.path()
  }

  pub fn queries(&self) -> &HashMap<&str, &str> {
    &self.queries
  }
  pub fn accept_types(&self) -> &Vec<ValueQualitySet> {
    &self.accept
  }
  pub fn accept_languages(&self) -> &Vec<ValueQualitySet> {
    &self.accept_lang
  }
}
#[derive(Debug)]
pub struct ValueQualitySet<'a> {
  pub value: &'a str,
  pub quality: f32,
}
#[derive(Debug)]
pub struct KeyValuePair<'a> {
  pub key: &'a str,
  pub value: &'a str,
}

/// Formats headers to extract useful info.
///
/// Only allocates vectors and hashmaps to references, and possibly an URI struct if a host is specified in the headers.
/// Only allocates once for expandable structs, as count is calculated before allocation.
///
/// Assumes scheme is https, since you can't construct a URI without a scheme. Should not be relied upon.
pub fn format_headers<T>(request: &Request<T>) -> HeaderInfo {
  let headers = request.headers();
  let uri = request.uri();
  let url = {
    match headers.get("host").and_then(|host| host.to_str().ok()) {
      Some(host) => {
        let mut url = Uri::builder().authority(host).scheme("https");
        url = match uri.path_and_query() {
          Some(path) => url.path_and_query(path.clone()),
          None => url.path_and_query(uri.path()),
        };
        match url.build() {
          Ok(url) => Cow::Owned(url),
          Err(..) => Cow::Borrowed(uri),
        }
      }
      None => Cow::Borrowed(uri),
    }
  };
  HeaderInfo {
    url,
    queries: uri
      .query()
      .and_then(|q| Some(format_query(q)))
      .unwrap_or(HashMap::new()),
    accept: request
      .headers()
      .get("accept")
      .and_then(|accept| accept.to_str().ok())
      .and_then(|accept| Some(format_list_header(accept)))
      .unwrap_or(Vec::new()),
    accept_lang: request
      .headers()
      .get("accept-language")
      .and_then(|accept| accept.to_str().ok())
      .and_then(|accept| Some(format_list_header(accept)))
      .unwrap_or(Vec::new()),
  }
}

pub fn format_list_header(header: &str) -> Vec<ValueQualitySet> {
  let elements = header
    .chars()
    .fold(1, |acc, byte| if byte == ',' { acc + 1 } else { acc });
  let mut list = Vec::with_capacity(elements);

  let mut start_byte = 0;
  let mut end_byte = 0;
  let mut in_quality = false;
  let mut previous_was_q = false;
  let mut quality_start_byte = 0;
  for (position, byte) in header.char_indices() {
    if byte == ' ' {
      continue;
    }

    if in_quality && quality_start_byte == 0 {
      match byte {
        '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '.' => {
          quality_start_byte = position;
        }
        _ => {}
      }
    }

    if byte == ';' && !in_quality {
      end_byte = position;
      in_quality = true;
    }
    if in_quality {
      if byte == '=' && previous_was_q {
        quality_start_byte = position + 1;
      }
      previous_was_q = if byte == 'q' { true } else { false }
    }

    if byte == ',' {
      let quality = match header
        .get(quality_start_byte..position)
        .and_then(|quality| quality.parse().ok())
      {
        Some(quality) => quality,
        None => 1.0,
      };
      match header.get(start_byte..if end_byte == 0 { position } else { end_byte }) {
        Some(accept) => list.push(ValueQualitySet {
          value: accept,
          quality,
        }),
        None => {}
      }
      quality_start_byte = 0;
      end_byte = 0;
      start_byte = position + 1;
      in_quality = false;
    }
  }
  // Last, when reaches EOF
  let quality = match header
    .get(quality_start_byte..)
    .and_then(|quality| quality.parse().ok())
  {
    Some(quality) => quality,
    None => 1.0,
  };
  match header.get(start_byte..end_byte) {
    Some(accept) => list.push(ValueQualitySet {
      value: accept,
      quality,
    }),
    None => {}
  }
  list
}
pub fn format_query(query: &str) -> HashMap<&str, &str> {
  let elements = query
    .chars()
    .fold(1, |acc, byte| if byte == '&' { acc + 1 } else { acc });
  let mut map = HashMap::with_capacity(elements);

  let mut pair_start = 0;
  let mut value_start = 0;
  for (position, byte) in query.char_indices() {
    match byte {
      '=' => {
        value_start = position;
      }
      '&' => {
        let key = query.get(pair_start..value_start);
        let value = query.get(value_start + 1..position);

        if key.is_some() && value.is_some() {
          map.insert(key.unwrap(), value.unwrap());
        }

        pair_start = position + 1;
      }
      _ => {}
    }
  }
  {
    let key = query.get(pair_start..value_start);
    let value = query.get(value_start + 1..);

    if key.is_some() && value.is_some() {
      map.insert(key.unwrap(), value.unwrap());
    }
  }
  map
}

pub fn convert_uri(uri: &Uri) -> Result<PathBuf, ()> {
  let mut path = uri.path();
  if path.contains("./") {
    return Err(());
  }
  let is_dir = path.ends_with("/");
  path = unsafe { std::str::from_utf8_unchecked(&path.as_bytes()[1..]) };

  let mut buf = PathBuf::from("public");
  buf.push(path);
  if is_dir {
    buf.push("index.html");
  };
  Ok(buf)
}

use crate::prelude::*;
use http::{header::HeaderName, HeaderValue, Method, Request, Uri, Version};
use std::{cell::RefCell, io, rc::Rc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite};

#[derive(Debug)]
pub enum Error {
    Http(http::Error),
    Io(io::Error),
    H2(h2::Error),
    NoPath,
    Done,
}
impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Self::Http(err)
    }
}
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<h2::Error> for Error {
    fn from(err: h2::Error) -> Self {
        Self::H2(err)
    }
}

pub enum HttpConnection<S> {
    Http1(Rc<RefCell<S>>),
    Http2(h2::server::Connection<S, bytes::Bytes>),
}

/// ToDo: trailers
pub enum Body<S> {
    Http1(S),
    Http2(h2::RecvStream),
}

pub enum ResponsePipe<S: AsyncWrite> {
    Http1(Rc<RefCell<S>>),
    Http2(h2::server::SendResponse<bytes::Bytes>),
}
pub enum ResponseBodyPipe<S: AsyncWrite> {
    Http1(Rc<RefCell<S>>),
    Http2(h2::SendStream<bytes::Bytes>),
}

impl<S: AsyncRead + AsyncWrite + AsyncSeek + Unpin> HttpConnection<S> {
    pub async fn new(stream: S, version: http::Version) -> Result<Self, Error> {
        match version {
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
                Ok(Self::Http1(Rc::new(RefCell::new(stream))))
            }
            Version::HTTP_2 => match h2::server::handshake(stream).await {
                Ok(connection) => Ok(HttpConnection::Http2(connection)),
                Err(err) => Err(Error::H2(err)),
            },
            Version::HTTP_3 => unimplemented!(),
            _ => todo!(),
        }
    }

    pub async fn accept(
        self,
    ) -> Result<(http::Request<Body<Rc<RefCell<S>>>>, ResponsePipe<S>), Error> {
        match self {
            Self::Http1(stream) => {
                let response = ResponsePipe::Http1(Rc::clone(&stream));
                request::parse_http_1(stream)
                    .await
                    .map(|request| (request, response))
            }
            Self::Http2(mut connection) => match connection.accept().await {
                Some(connection) => match connection {
                    Ok((request, response)) => Ok((
                        request.map(|body| Body::Http2(body)),
                        ResponsePipe::Http2(response),
                    )),
                    Err(err) => Err(Error::H2(err)),
                },
                None => Err(Error::Done),
            },
        }
    }
}

mod request {
    use super::*;

    pub async fn parse_http_1<S: AsyncRead + AsyncWrite + AsyncSeek + Unpin>(
        stream: Rc<RefCell<S>>,
    ) -> Result<http::Request<Body<Rc<RefCell<S>>>>, Error> {
        let (head, end) = parse_request(&stream).await?;
        stream
            .borrow_mut()
            .seek(io::SeekFrom::Start(end as u64))
            .await?;
        Ok(head.map(|()| Body::Http1(stream)))
    }

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

    /// # Errors
    /// Will return error if building the `http::Response` internally failed, or if path is empty.
    pub async fn parse_request<S: AsyncRead + Unpin>(
        stream: &Rc<RefCell<S>>,
    ) -> Result<(Request<()>, usize), Error> {
        let mut buffer = Vec::with_capacity(utility::BUFFER_SIZE);

        let mut parse_stage = DecodeStage::Method;
        // Method is max 7 bytes long
        let mut method = [0; 7];
        let mut method_len = 0;
        let mut path = Vec::with_capacity(128);
        // Version is 8 bytes long
        let mut version = [0; 8];
        let mut version_index = 0;
        let mut parsed = Request::builder();
        let mut current_header_name = Vec::with_capacity(128);
        let mut current_header_value = Vec::with_capacity(256);
        let mut lf_in_row = 0_u8;
        let mut header_end = 0;
        while header_end == 0 {
            unsafe { buffer.set_len(buffer.capacity()) };
            let read = stream
                .borrow_mut()
                .read(&mut buffer)
                .await
                .map_err(Error::Io)?;
            unsafe { buffer.set_len(read) };

            for byte in buffer.iter().copied() {
                header_end += 1;
                if byte == CR {
                    continue;
                }
                if byte == LF {
                    lf_in_row += 1;
                    if lf_in_row == 2 {
                        break;
                    }
                } else {
                    lf_in_row = 0;
                }
                match parse_stage {
                    DecodeStage::Method => {
                        if byte == SPACE || method_len == method.len() {
                            parse_stage.next();
                            continue;
                        }
                        method[method_len] = byte;
                        method_len += 1;
                    }
                    DecodeStage::Path => {
                        if byte == SPACE {
                            parse_stage.next();
                            continue;
                        }
                        path.push(byte);
                    }
                    DecodeStage::Version => {
                        if byte == LF || version_index == version.len() {
                            parse_stage.next();
                            continue;
                        }
                        version[version_index] = byte;
                        version_index += 1;
                    }
                    DecodeStage::HeaderName(..) => {
                        if byte == COLON {
                            continue;
                        }
                        if byte == SPACE {
                            parse_stage.next();
                            continue;
                        }
                        current_header_name.push(byte);
                    }
                    DecodeStage::HeaderValue(..) => {
                        if byte == LF {
                            let name = HeaderName::from_bytes(&current_header_name[..]);
                            let value = HeaderValue::from_bytes(&current_header_value[..]);
                            if name.is_ok() && value.is_ok() {
                                // Ok, because of ↑
                                parsed = parsed.header(name.unwrap(), value.unwrap());
                            }
                            current_header_name.clear();
                            current_header_value.clear();
                            parse_stage.next();
                            continue;
                        }
                        current_header_value.push(byte);
                    }
                };
            }
        }
        if path.is_empty() {
            return Err(Error::NoPath);
        }
        match parsed
            .method(Method::from_bytes(&method[..method_len]).unwrap_or(Method::GET))
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
            .body(())
        {
            Err(err) => Err(Error::Http(err)),
            Ok(request) => Ok((request, header_end)),
        }
    }
}

mod response {}

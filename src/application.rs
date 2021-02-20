use crate::prelude::*;
use http::{header::HeaderName, HeaderValue, Method, Request, Uri, Version};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

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
    Http1(Arc<Mutex<S>>),
    Http2(h2::server::Connection<S, bytes::Bytes>),
}

/// ToDo: trailers
#[derive(Debug)]
pub enum Body<S: AsyncRead + Unpin> {
    Http1(response::PreBufferedReader<S>),
    Http2(h2::RecvStream),
}

pub enum ResponsePipe<S: AsyncWrite> {
    Http1(Arc<Mutex<S>>),
    Http2(h2::server::SendResponse<bytes::Bytes>),
}
pub enum ResponseBodyPipe<S: AsyncWrite> {
    Http1(Arc<Mutex<S>>),
    Http2(h2::SendStream<bytes::Bytes>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpConnection<S> {
    pub async fn new(stream: S, version: http::Version) -> Result<Self, Error> {
        match version {
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
                Ok(Self::Http1(Arc::new(Mutex::new(stream))))
            }
            Version::HTTP_2 => match h2::server::handshake(stream).await {
                Ok(connection) => Ok(HttpConnection::Http2(connection)),
                Err(err) => Err(Error::H2(err)),
            },
            Version::HTTP_3 => unimplemented!(),
            _ => todo!(),
        }
    }

    pub async fn accept(&mut self) -> Result<(http::Request<Body<S>>, ResponsePipe<S>), Error> {
        match self {
            Self::Http1(stream) => {
                let response = ResponsePipe::Http1(Arc::clone(stream));
                request::parse_http_1(Arc::clone(stream))
                    .await
                    .map(|request| (request, response))
            }
            Self::Http2(connection) => match connection.accept().await {
                Some(connection) => match connection {
                    Ok((request, response)) => Ok((
                        request.map(|s| Body::Http2(s)),
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

    pub async fn parse_http_1<S: AsyncRead + AsyncWrite + Unpin>(
        stream: Arc<Mutex<S>>,
    ) -> Result<http::Request<Body<S>>, Error> {
        let (head, start, vec) = parse_request(&stream).await?;
        Ok(head.map(|()| Body::Http1(response::PreBufferedReader::new(stream, vec, start))))
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
    ///
    /// # Limitation
    /// request will be cut off at `crate::BUFFER_SIZE`.
    pub async fn parse_request<S: AsyncRead + Unpin>(
        stream: &Arc<Mutex<S>>,
    ) -> Result<(Request<()>, usize, Vec<u8>), Error> {
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
        unsafe { buffer.set_len(buffer.capacity()) };
        let read = stream
            .lock()
            .await
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
            Ok(request) => Ok((request, header_end, buffer)),
        }
    }

    impl<R: AsyncRead + Unpin> AsyncRead for Body<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Http1(s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
                Self::Http2(tls) => {
                    let data = match tls.poll_data(cx) {
                        Poll::Ready(data) => data,
                        Poll::Pending => return Poll::Pending,
                    };
                    match data {
                        Some(d) => match d {
                            Ok(data) => buf.put_slice(&data),
                            Err(err) => {
                                let err = io::Error::new(io::ErrorKind::InvalidData, err);
                                return Poll::Ready(Err(err));
                            }
                        },
                        None => return Poll::Ready(Ok(())),
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

mod response {
    use super::*;

    // #[derive(Debug)]
    pub struct PreBufferedReader<R: AsyncRead + Unpin> {
        reader: Arc<Mutex<R>>,
        buffer: Vec<u8>,
        offset: usize,
    }
    impl<R: AsyncRead + Unpin + Debug> Debug for PreBufferedReader<R> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "PreBufferedReader {{ reader: {:?}, buffer: [internal buffer], offset: {:?} }}",
                self.reader, self.offset
            )
        }
    }
    impl<R: AsyncRead + Unpin> PreBufferedReader<R> {
        pub fn new(reader: Arc<Mutex<R>>, buffer: Vec<u8>, start: usize) -> Self {
            Self {
                reader,
                buffer,
                offset: start,
            }
        }
    }
    impl<R: AsyncRead + Unpin> AsyncRead for PreBufferedReader<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let me = self.get_mut();
            if me.offset < me.buffer.len() {
                buf.put_slice(&me.buffer[me.offset..]);
                me.offset = me.buffer.len();
                Poll::Ready(Ok(()))
            } else {
                let mut reader = match me.reader.try_lock() {
                    Err(_) => return Poll::Pending,
                    Ok(r) => r,
                };
                unsafe { Pin::new_unchecked(&mut *reader).poll_read(cx, buf) }
            }
        }
    }

    
}

//! Encryption for incoming and outgoing traffic, implemented through streams.
//!
//! Based on [`rustls`]. [`encryption::Encryption`] implements both [`AsyncRead`] and [`AsyncWrite`]
//! to enable seamless integration with the [`tokio`] runtime.
//!
//! Most of the code is a subset of [`tokio-rustls`](https://crates.io/crates/tokio-rustls)
use crate::prelude::{networking::*, *};
#[cfg(feature = "https")]
use rustls::{ServerConfig, ServerSession, Session};

#[cfg(feature = "https")]
use tokio_tls::{MidHandshake, TlsState, TlsStream};

/// An encrypted stream.
///
/// For now only supports [`TcpStream`]s, which will
/// change when Kvarn gets HTTP/3 support.
#[derive(Debug)]
pub enum Encryption {
    /// A TLS encrypted TCP stream.
    #[cfg(feature = "https")]
    TcpTls(TlsStream<TcpStream>),
    /// A unencrypted TCP stream for use with
    /// non-secure HTTP.
    Tcp(TcpStream),
}
impl Encryption {
    /// Creates a new [`Encryption`] from a `tcp` connection.
    ///
    ///
    /// # Errors
    ///
    /// Will return an error if the TLS handshake failed, if `certificate.is_some()`.
    #[cfg(feature = "https")]
    pub async fn new_tcp(
        stream: TcpStream,
        certificate: Option<&Arc<ServerConfig>>,
    ) -> io::Result<Self> {
        match certificate {
            None => Ok(Self::Tcp(stream)),
            Some(config) => {
                let session = ServerSession::new(config);
                let stream = TlsStream {
                    io: stream,
                    session,
                    state: TlsState::Stream,
                };
                let acceptor = MidHandshake::Handshaking(stream);
                let connect = acceptor.await.map_err(|(err, _)| err)?;

                Ok(Self::TcpTls(connect))
            }
        }
    }
    /// Creates a new unencrypted stream from a [`TcpStream`].
    #[cfg(not(feature = "https"))]
    pub fn new_tcp(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }
}
impl Encryption {
    /// Gets the peer certificates, if any.
    ///
    /// If the underlying stream is not TLS, this function returns `None`.
    ///
    /// This function is gated behind the feature `https`
    /// due to a [`rustls`] type in it's definition.
    #[cfg(feature = "https")]
    #[inline]
    pub fn get_peer_certificates(&self) -> Option<Vec<rustls::Certificate>> {
        match self {
            Self::TcpTls(s) => s.session.get_peer_certificates(),
            Self::Tcp(_) => None,
        }
    }
    /// Gets the agreed upon ALPN protocol.
    ///
    /// If the underlying stream is not TLS, this function returns `None`.
    /// Else, a value of `None` means no protocol was agreed
    /// (because no protocols were offered or accepted by the peer).
    #[inline]
    pub fn get_alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            #[cfg(feature = "https")]
            Self::TcpTls(s) => s.session.get_alpn_protocol(),
            Self::Tcp(_) => None,
        }
    }
    /// Gets the protocol version.
    ///
    /// If the stream is `TLS`, it's safe to `unwrap()` the returned value;
    /// `This returns None until the version is agreed.`, from the [`rustls::Session`]
    /// docs means that a version must be available post-handshake,
    /// which [`Encryption`] is guaranteed to be.
    ///
    /// If the underlying stream is not TLS, this function returns `None`.
    ///
    /// This function is gated behind the feature `https`
    /// due to a [`rustls`] type in it's definition.
    #[cfg(feature = "https")]
    #[inline]
    pub fn get_protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        match self {
            Self::TcpTls(s) => s.session.get_protocol_version(),
            Self::Tcp(_) => None,
        }
    }
    /// Retrieves the SNI hostname, if any, used to select the certificate and private key.
    ///
    /// This value will be `Some` if `self` is [`Encryption::TcpTls`]
    /// and if the client supports SNI hostnames.
    // change docs for HTTP/3 ↑
    #[inline]
    pub fn get_sni_hostname(&self) -> Option<&str> {
        match self {
            #[cfg(feature = "https")]
            Self::TcpTls(s) => s.session.get_sni_hostname(),
            Self::Tcp(_) => None,
        }
    }
}
impl AsyncRead for Encryption {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
            #[cfg(feature = "https")]
            Self::TcpTls(tls) => unsafe { Pin::new_unchecked(tls).poll_read(cx, buf) },
        }
    }
}
impl AsyncWrite for Encryption {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => unsafe { Pin::new_unchecked(s).poll_write(cx, buf) },
            #[cfg(feature = "https")]
            Self::TcpTls(tls) => unsafe { Pin::new_unchecked(tls).poll_write(cx, buf) },
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => unsafe { Pin::new_unchecked(s).poll_flush(cx) },
            #[cfg(feature = "https")]
            Self::TcpTls(tls) => unsafe { Pin::new_unchecked(tls).poll_flush(cx) },
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => unsafe { Pin::new_unchecked(s).poll_shutdown(cx) },
            #[cfg(feature = "https")]
            Self::TcpTls(tls) => unsafe { Pin::new_unchecked(tls).poll_shutdown(cx) },
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => unsafe { Pin::new_unchecked(s).poll_write_vectored(cx, bufs) },
            #[cfg(feature = "https")]
            Self::TcpTls(tls) => unsafe { Pin::new_unchecked(tls).poll_write_vectored(cx, bufs) },
        }
    }
}
/// Generic encryption error.
///
/// Returns the [`io::Error`]s from IO during the handshake
/// and when reading and writing to the underlying stream.
/// If any [`rustls::TLSError`]s occur during reading and writing,
/// those are returned.
#[derive(Debug)]
pub enum Error {
    /// An IO error occurred during operation.
    Io(io::Error),
    /// A TLS error was emitted.
    #[cfg(feature = "https")]
    Tls(rustls::TLSError),
}
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
#[cfg(feature = "https")]
impl From<rustls::TLSError> for Error {
    fn from(err: rustls::TLSError) -> Self {
        Self::Tls(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => {
                f.write_str("std::Io: ")?;
                Display::fmt(e, f)
            }
            #[cfg(feature = "https")]
            Self::Tls(e) => {
                f.write_str("rustls::TLSError: ")?;
                Display::fmt(e, f)
            }
        }
    }
}

impl std::error::Error for Error {}

/// Tokio-Rustls glue code
#[cfg(feature = "https")]
mod tokio_tls {
    use super::Error;
    use rustls::{ServerSession, Session};
    use std::future::Future;
    use std::io::{self, IoSlice, Read, Write};
    use std::mem;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Debug)]
    pub(crate) enum TlsState {
        Stream,
        ReadShutdown,
        WriteShutdown,
        FullyShutdown,
    }

    impl TlsState {
        #[inline]
        pub(crate) fn shutdown_read(&mut self) {
            match *self {
                TlsState::WriteShutdown | TlsState::FullyShutdown => {
                    *self = TlsState::FullyShutdown
                }
                _ => *self = TlsState::ReadShutdown,
            }
        }

        #[inline]
        pub(crate) fn shutdown_write(&mut self) {
            match *self {
                TlsState::ReadShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
                _ => *self = TlsState::WriteShutdown,
            }
        }

        #[inline]
        pub(crate) fn writeable(&self) -> bool {
            !matches!(*self, TlsState::WriteShutdown | TlsState::FullyShutdown)
        }

        #[inline]
        pub(crate) fn readable(&self) -> bool {
            !matches!(*self, TlsState::ReadShutdown | TlsState::FullyShutdown)
        }
    }

    /// A wrapper around an underlying raw stream
    /// which implements the TLS protocol.
    #[derive(Debug)]
    pub struct TlsStream<IO> {
        pub(crate) io: IO,
        pub(crate) session: ServerSession,
        pub(crate) state: TlsState,
    }

    impl<IO> IoSession for TlsStream<IO> {
        type Io = IO;
        type Session = ServerSession;

        #[inline]
        fn skip_handshake(&self) -> bool {
            false
        }

        #[inline]
        fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session) {
            (&mut self.state, &mut self.io, &mut self.session)
        }

        #[inline]
        fn into_io(self) -> Self::Io {
            self.io
        }
    }

    impl<IO> AsyncRead for TlsStream<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let mut stream =
                Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

            match &this.state {
                TlsState::Stream | TlsState::WriteShutdown => {
                    let prev = buf.remaining();

                    match stream.as_mut_pin().poll_read(cx, buf) {
                        Poll::Ready(Ok(())) => {
                            if prev == buf.remaining() {
                                this.state.shutdown_read();
                            }

                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(ref err))
                            if err.kind() == io::ErrorKind::ConnectionAborted =>
                        {
                            this.state.shutdown_read();
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(())),
            }
        }
    }

    impl<IO> AsyncWrite for TlsStream<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        /// Note: that it does not guarantee the final data to be sent.
        /// To be cautious, you must manually call `flush`.
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let mut stream =
                Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
            stream.as_mut_pin().poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let mut stream =
                Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
            stream.as_mut_pin().poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.state.writeable() {
                self.session.send_close_notify();
                self.state.shutdown_write();
            }

            let this = self.get_mut();
            let mut stream =
                Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
            stream.as_mut_pin().poll_shutdown(cx)
        }
    }

    pub(crate) struct Stream<'a, IO, S> {
        io: &'a mut IO,
        session: &'a mut S,
        eof: bool,
    }

    impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> Stream<'a, IO, S> {
        #[inline]
        pub(crate) fn new(io: &'a mut IO, session: &'a mut S) -> Self {
            Stream {
                io,
                session,
                // The state so far is only used to detect EOF, so either Stream
                // or EarlyData state should both be all right.
                eof: false,
            }
        }

        #[inline]
        pub(crate) fn set_eof(mut self, eof: bool) -> Self {
            self.eof = eof;
            self
        }

        #[inline]
        pub(crate) fn as_mut_pin(&mut self) -> Pin<&mut Self> {
            Pin::new(self)
        }

        pub(crate) fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
            struct Reader<'a, 'b, T> {
                io: &'a mut T,
                cx: &'a mut Context<'b>,
            }

            impl<'a, 'b, T: AsyncRead + Unpin> Read for Reader<'a, 'b, T> {
                #[inline]
                fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                    let mut buf = ReadBuf::new(buf);
                    match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
                        Poll::Ready(Ok(())) => Ok(buf.filled().len()),
                        Poll::Ready(Err(err)) => Err(err),
                        Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                    }
                }
            }

            let mut reader = Reader { io: self.io, cx };

            let n = match self.session.read_tls(&mut reader) {
                Ok(n) => n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(err) => return Poll::Ready(Err(err.into())),
            };

            self.session.process_new_packets().map_err(|err| {
                // In case we have an alert to send describing this error,
                // try a last-gasp write -- but don't predate the primary
                // error.
                let _ = self.write_io(cx);

                Error::from(err)
            })?;

            Poll::Ready(Ok(n))
        }

        pub(crate) fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
            struct Writer<'a, 'b, T> {
                io: &'a mut T,
                cx: &'a mut Context<'b>,
            }

            impl<'a, 'b, T: Unpin> Writer<'a, 'b, T> {
                #[inline]
                fn poll_with<U>(
                    &mut self,
                    f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<U>>,
                ) -> io::Result<U> {
                    match f(Pin::new(&mut self.io), self.cx) {
                        Poll::Ready(result) => result,
                        Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                    }
                }
            }

            impl<'a, 'b, T: AsyncWrite + Unpin> Write for Writer<'a, 'b, T> {
                #[inline]
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    self.poll_with(|io, cx| io.poll_write(cx, buf))
                }

                #[inline]
                fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
                    self.poll_with(|io, cx| io.poll_write_vectored(cx, bufs))
                }

                fn flush(&mut self) -> io::Result<()> {
                    self.poll_with(|io, cx| io.poll_flush(cx))
                }
            }

            let mut writer = Writer { io: self.io, cx };

            match self.session.write_tls(&mut writer) {
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                result => Poll::Ready(result),
            }
        }

        pub(crate) fn handshake(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(usize, usize), Error>> {
            let mut wrlen = 0;
            let mut rdlen = 0;

            loop {
                let mut write_would_block = false;
                let mut read_would_block = false;

                while self.session.wants_write() {
                    match self.write_io(cx) {
                        Poll::Ready(Ok(n)) => wrlen += n,
                        Poll::Pending => {
                            write_would_block = true;
                            break;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                    }
                }

                while !self.eof && self.session.wants_read() {
                    match self.read_io(cx) {
                        Poll::Ready(Ok(0)) => self.eof = true,
                        Poll::Ready(Ok(n)) => rdlen += n,
                        Poll::Pending => {
                            read_would_block = true;
                            break;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }

                return match (self.eof, self.session.is_handshaking()) {
                    (true, true) => {
                        let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                        Poll::Ready(Err(err.into()))
                    }
                    (_, false) => Poll::Ready(Ok((rdlen, wrlen))),
                    (_, true) if write_would_block || read_would_block => {
                        if rdlen != 0 || wrlen != 0 {
                            Poll::Ready(Ok((rdlen, wrlen)))
                        } else {
                            Poll::Pending
                        }
                    }
                    (..) => continue,
                };
            }
        }
    }

    impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> AsyncRead for Stream<'a, IO, S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let prev = buf.remaining();

            while buf.remaining() != 0 {
                let mut would_block = false;

                // read a packet
                while self.session.wants_read() {
                    match self.read_io(cx) {
                        Poll::Ready(Ok(0)) => {
                            self.eof = true;
                            break;
                        }
                        Poll::Ready(Ok(_)) => (),
                        Poll::Pending => {
                            would_block = true;
                            break;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(match err {
                                Error::Io(e) => e,
                                Error::Tls(e) => io::Error::new(io::ErrorKind::InvalidData, e),
                            }))
                        }
                    }
                }

                return match self.session.read(buf.initialize_unfilled()) {
                    Ok(0) if prev == buf.remaining() && would_block => Poll::Pending,
                    Ok(n) => {
                        buf.advance(n);

                        if self.eof || would_block {
                            break;
                        }
                        continue;
                    }
                    Err(ref err)
                        if err.kind() == io::ErrorKind::ConnectionAborted
                            && prev != buf.remaining() =>
                    {
                        break
                    }
                    Err(err) => Poll::Ready(Err(err)),
                };
            }

            Poll::Ready(Ok(()))
        }
    }

    impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> AsyncWrite for Stream<'a, IO, S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut pos = 0;

            while pos != buf.len() {
                let mut would_block = false;

                match self.session.write(&buf[pos..]) {
                    Ok(n) => pos += n,
                    Err(err) => return Poll::Ready(Err(err)),
                };

                while self.session.wants_write() {
                    match self.write_io(cx) {
                        Poll::Ready(Ok(0)) | Poll::Pending => {
                            would_block = true;
                            break;
                        }
                        Poll::Ready(Ok(_)) => (),
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }

                return match (pos, would_block) {
                    (0, true) => Poll::Pending,
                    (n, true) => Poll::Ready(Ok(n)),
                    (_, false) => continue,
                };
            }

            Poll::Ready(Ok(pos))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.session.flush()?;
            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(t) => t,
                    Poll::Pending => return Poll::Pending,
                }?;
            }
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(t) => t,
                    Poll::Pending => return Poll::Pending,
                }?;
            }
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    pub(crate) trait IoSession {
        type Io;
        type Session;

        fn skip_handshake(&self) -> bool;
        fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session);
        fn into_io(self) -> Self::Io;
    }

    pub(crate) enum MidHandshake<IS> {
        Handshaking(IS),
        End,
    }

    impl<IS> Future for MidHandshake<IS>
    where
        IS: IoSession + Unpin,
        IS::Io: AsyncRead + AsyncWrite + Unpin,
        IS::Session: Session + Unpin,
    {
        type Output = Result<IS, (io::Error, IS::Io)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();

            let mut stream =
                if let MidHandshake::Handshaking(stream) = mem::replace(this, MidHandshake::End) {
                    stream
                } else {
                    panic!("unexpected polling after handshake")
                };

            if !stream.skip_handshake() {
                let (state, io, session) = stream.get_mut();
                let mut tls_stream = Stream::new(io, session).set_eof(!state.readable());

                while tls_stream.session.is_handshaking() {
                    match tls_stream.handshake(cx) {
                        Poll::Ready(Ok(_)) => (),
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err((
                                io::Error::new(io::ErrorKind::InvalidData, err),
                                stream.into_io(),
                            )))
                        }
                        Poll::Pending => {
                            *this = MidHandshake::Handshaking(stream);
                            return Poll::Pending;
                        }
                    }
                }

                while tls_stream.session.wants_write() {
                    match tls_stream.write_io(cx) {
                        Poll::Ready(Ok(_)) => (),
                        Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.into_io()))),
                        Poll::Pending => {
                            *this = MidHandshake::Handshaking(stream);
                            return Poll::Pending;
                        }
                    }
                }
            }

            Poll::Ready(Ok(stream))
        }
    }
}

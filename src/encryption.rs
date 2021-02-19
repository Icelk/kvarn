use crate::prelude::*;
use connection::EncryptionType;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tls::*;

pub enum Encryption<S: AsyncRead + AsyncWrite + Unpin> {
    Tls(TlsStream<S>),
    None(S),
}
impl<S: AsyncRead + AsyncWrite + Unpin> Encryption<S> {
    pub async fn new_from_connection_security(
        stream: S,
        security: &ConnectionSecurity,
    ) -> io::Result<Self> {
        match security.get_config() {
            EncryptionType::NonSecure => Ok(Self::None(stream)),
            EncryptionType::Secure(config) => {
                let session = rustls::ServerSession::new(config);
                let stream = TlsStream {
                    io: stream,
                    session: session,
                    state: TlsState::Stream,
                };
                let acceptor = MidHandshake::Handshaking(stream);
                let connect = acceptor.await.map_err(|(err, _)| err)?;

                Ok(Self::Tls(connect))
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Encryption<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::None(s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
            Self::Tls(tls) => unsafe { Pin::new_unchecked(tls).poll_read(cx, buf) },
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Encryption<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::None(s) => unsafe { Pin::new_unchecked(s).poll_write(cx, buf) },
            Self::Tls(tls) => unsafe { Pin::new_unchecked(tls).poll_write(cx, buf) },
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::None(s) => unsafe { Pin::new_unchecked(s).poll_flush(cx) },
            Self::Tls(tls) => unsafe { Pin::new_unchecked(tls).poll_flush(cx) },
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::None(s) => unsafe { Pin::new_unchecked(s).poll_shutdown(cx) },
            Self::Tls(tls) => unsafe { Pin::new_unchecked(tls).poll_shutdown(cx) },
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::None(s) => unsafe { Pin::new_unchecked(s).poll_write_vectored(cx, bufs) },
            Self::Tls(tls) => unsafe { Pin::new_unchecked(tls).poll_write_vectored(cx, bufs) },
        }
    }
}
// unsafe impl<S: AsyncRead + AsyncWrite + Unpin> Unpin for Encryption<S> {}

async fn read_to_vec<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut buffer = Vec::with_capacity(1024 * 16);
    unsafe { buffer.set_len(buffer.capacity()) };
    let r = match reader.read(&mut buffer[..]).await {
        Ok(s) => s,
        Err(e) => {
            return Err(e);
        }
    };
    unsafe { buffer.set_len(r) };
    Ok(buffer)
}
#[derive(Debug)]
pub enum TlsIoError {
    Io(io::Error),
    Tls(rustls::TLSError),
}
impl From<io::Error> for TlsIoError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<rustls::TLSError> for TlsIoError {
    fn from(err: rustls::TLSError) -> Self {
        Self::Tls(err)
    }
}

/// Tokio Rustls glue code
mod tokio_tls {
    use super::TlsIoError;
    use futures_util::ready;
    use rustls::{ServerSession, Session};
    use std::future::Future;
    use std::io::{self, IoSlice, Read, Write};
    use std::mem;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Debug)]
    pub enum TlsState {
        Stream,
        ReadShutdown,
        WriteShutdown,
        FullyShutdown,
    }

    impl TlsState {
        #[inline]
        pub fn shutdown_read(&mut self) {
            match *self {
                TlsState::WriteShutdown | TlsState::FullyShutdown => {
                    *self = TlsState::FullyShutdown
                }
                _ => *self = TlsState::ReadShutdown,
            }
        }

        #[inline]
        pub fn shutdown_write(&mut self) {
            match *self {
                TlsState::ReadShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
                _ => *self = TlsState::WriteShutdown,
            }
        }

        #[inline]
        pub fn writeable(&self) -> bool {
            !matches!(*self, TlsState::WriteShutdown | TlsState::FullyShutdown)
        }

        #[inline]
        pub fn readable(&self) -> bool {
            !matches!(*self, TlsState::ReadShutdown | TlsState::FullyShutdown)
        }
    }

    /// A wrapper around an underlying raw stream which implements the TLS or SSL
    /// protocol.
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

    pub struct Stream<'a, IO, S> {
        pub io: &'a mut IO,
        pub session: &'a mut S,
        pub eof: bool,
    }

    impl<'a, IO: AsyncRead + AsyncWrite + Unpin, S: Session> Stream<'a, IO, S> {
        pub fn new(io: &'a mut IO, session: &'a mut S) -> Self {
            Stream {
                io,
                session,
                // The state so far is only used to detect EOF, so either Stream
                // or EarlyData state should both be all right.
                eof: false,
            }
        }

        pub fn set_eof(mut self, eof: bool) -> Self {
            self.eof = eof;
            self
        }

        pub fn as_mut_pin(&mut self) -> Pin<&mut Self> {
            Pin::new(self)
        }

        pub fn read_io(&mut self, cx: &mut Context) -> Poll<Result<usize, TlsIoError>> {
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

                TlsIoError::from(err)
            })?;

            Poll::Ready(Ok(n))
        }

        pub fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
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

        pub fn handshake(&mut self, cx: &mut Context) -> Poll<Result<(usize, usize), TlsIoError>> {
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
                                TlsIoError::Io(e) => e,
                                TlsIoError::Tls(e) => io::Error::new(io::ErrorKind::InvalidData, e),
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
                        } else {
                            continue;
                        }
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
            cx: &mut Context,
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

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            self.session.flush()?;
            while self.session.wants_write() {
                ready!(self.write_io(cx))?;
            }
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while self.session.wants_write() {
                ready!(self.write_io(cx))?;
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
                        Poll::Ready(Err(_)) => break,
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

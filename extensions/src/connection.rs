use kvarn::prelude::*;
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpStream, UdpSocket};

macro_rules! socket_addr_with_port {
    ($($port:literal $(,)+)*) => {
        &[
            $(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, $port)),)*
        ]
    };
}

#[derive(Debug, Clone)]
pub enum Connection {
    Tcp(SocketAddr),
    /// Keep in mind, this currently has a `60s` timeout.
    /// Please use [`Self::UnixSocket`]s instead if you are on Unix.
    Udp(SocketAddr),
    #[cfg(unix)]
    UnixSocket(String),
}
impl Connection {
    pub async fn establish(self) -> io::Result<EstablishedConnection> {
        match self {
            Self::Tcp(addr) => TcpStream::connect(addr)
                .await
                .map(EstablishedConnection::Tcp),
            Self::Udp(addr) => {
                // Random ports to bind to.
                let candidates = &socket_addr_with_port!(
                    17448, 64567, 40022, 56654, 52027, 44328, 29973, 27919, 26513, 42327, 64855,
                    5296, 52942, 43204, 15322, 13243,
                )[..];
                let socket = UdpSocket::bind(candidates).await?;
                socket.connect(addr).await?;
                Ok(EstablishedConnection::Udp(socket))
            }
            #[cfg(unix)]
            Self::UnixSocket(path) => UnixStream::connect(path)
                .await
                .map(EstablishedConnection::UnixSocket),
        }
    }
}

#[derive(Debug)]
pub enum EstablishedConnection {
    Tcp(TcpStream),
    Udp(UdpSocket),
    #[cfg(unix)]
    UnixSocket(UnixStream),
}
impl AsyncWrite for EstablishedConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Udp(s) => Pin::new(s).poll_send(cx, buf),
            #[cfg(unix)]
            Self::UnixSocket(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Udp(_) => Poll::Ready(Ok(())),
            #[cfg(unix)]
            Self::UnixSocket(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Udp(_) => Poll::Ready(Ok(())),
            #[cfg(unix)]
            Self::UnixSocket(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
impl AsyncRead for EstablishedConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Udp(s) => Pin::new(s).poll_recv(cx, buf),
            #[cfg(unix)]
            Self::UnixSocket(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

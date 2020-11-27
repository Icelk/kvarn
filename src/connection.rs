use crate::prelude::{fs::*, networking::*, rustls_prelude::*, *};

#[derive(PartialEq, Debug)]
pub enum ConnectionHeader {
    KeepAlive,
    Close,
}
impl ConnectionHeader {
    pub fn from_close(close: bool) -> Self {
        if close {
            Self::Close
        } else {
            Self::KeepAlive
        }
    }
    pub fn close(&self) -> bool {
        *self == Self::Close
    }
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            ConnectionHeader::Close => b"close",
            ConnectionHeader::KeepAlive => b"keep-alive",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct MioEvent {
    writable: bool,
    readable: bool,
    read_closed: bool,
    write_closed: bool,
    token: usize,
}
impl MioEvent {
    pub fn from_event(event: &mio::event::Event) -> Self {
        Self {
            writable: event.is_writable(),
            readable: event.is_readable(),
            read_closed: event.is_read_closed(),
            write_closed: event.is_write_closed(),
            token: event.token().0,
        }
    }
    #[inline]
    pub fn writable(&self) -> bool {
        self.writable
    }
    #[inline]
    pub fn readable(&self) -> bool {
        self.readable
    }
    #[inline]
    pub fn hint_write_closed(&self) -> bool {
        self.write_closed
    }
    #[inline]
    pub fn hint_read_closed(&self) -> bool {
        self.read_closed
    }
    #[inline]
    pub fn hint_either_closed(&self) -> bool {
        self.read_closed || self.write_closed
    }
    #[inline]
    pub fn hint_both_closed(&self) -> bool {
        self.read_closed && self.write_closed
    }
    #[inline]
    pub fn token(&self) -> mio::Token {
        mio::Token(self.token)
    }
    #[inline]
    pub fn raw_token(&self) -> usize {
        self.token
    }
}
#[derive(Debug)]
pub struct BufferedLayer {
    buffer: Vec<u8>,
}
impl BufferedLayer {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
        }
    }
    #[inline]
    pub fn push(&mut self, reader: &mut dyn io::Read) -> io::Result<()> {
        reader.read_to_end(&mut self.buffer).and(Ok(()))
    }
    #[inline]
    pub fn pull(&self) -> &[u8] {
        &self.buffer[..]
    }
    #[inline]
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}
#[derive(Debug)]
pub enum InformationLayer {
    Buffered(BufferedLayer),
    TLS(ServerSession),
}
#[derive(Debug)]
pub enum PullError {
    IO(io::Error),
    TLSError(rustls::TLSError),
}
impl Into<PullError> for io::Error {
    fn into(self) -> PullError {
        PullError::IO(self)
    }
}
impl Into<PullError> for rustls::TLSError {
    fn into(self) -> PullError {
        PullError::TLSError(self)
    }
}

impl InformationLayer {
    #[inline]
    pub fn pull(
        &mut self,
        reader: &mut dyn io::Read,
        mut buffer: &mut [u8],
    ) -> Result<usize, PullError> {
        match self {
            InformationLayer::Buffered(_) => {
                utility::read_to_end(&mut buffer, reader, true).map_err(|err| err.into())
            }
            InformationLayer::TLS(session) => {
                // Loop on read_tls
                loop {
                    match session.read_tls(reader) {
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => {
                            return Err(err.into());
                        }
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "TLS read zero bytes",
                            )
                            .into())
                        }
                        _ => {
                            match session.process_new_packets() {
                                Err(err) => return Err(err.into()),
                                Ok(()) => break,
                            };
                        }
                    };
                }
                utility::read_to_end(&mut buffer, session, false).map_err(|err| err.into())
            }
        }
    }
    #[inline]
    pub fn write(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        match self {
            InformationLayer::Buffered(buffered) => buffered.push(&mut bytes),
            InformationLayer::TLS(session) => session.write_all(bytes),
        }
    }
    #[inline]
    pub fn push(&mut self, writer: &mut dyn io::Write) -> Result<(), io::Error> {
        match self {
            InformationLayer::Buffered(buffered) => {
                writer.write_all(buffered.pull())?;
                buffered.clear();
                Ok(())
            }
            InformationLayer::TLS(session) => session.write_tls(writer).and(Ok(())),
        }
    }
    #[inline]
    pub fn notify_close(&mut self) {
        match self {
            InformationLayer::Buffered(_) => {}
            InformationLayer::TLS(session) => session.send_close_notify(),
        }
    }
    #[inline]
    pub fn clear(&mut self) {
        match self {
            InformationLayer::Buffered(buffered) => buffered.clear(),
            InformationLayer::TLS(session) => {
                let _ = session.write_tls(&mut io::sink());
            }
        }
    }

    #[inline]
    pub fn wants_read(&self) -> bool {
        match self {
            InformationLayer::Buffered(_) => true,
            InformationLayer::TLS(session) => session.wants_read(),
        }
    }
    #[inline]
    pub fn wants_write(&self) -> bool {
        match self {
            InformationLayer::Buffered(buffered) => !buffered.is_empty(),
            InformationLayer::TLS(session) => session.wants_write(),
        }
    }
}
impl io::Write for InformationLayer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Self::write(self, bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            InformationLayer::Buffered(_) => Ok(()),
            InformationLayer::TLS(session) => session.flush(),
        }
    }
}
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub enum ConnectionScheme {
    HTTP1,
    HTTP1S,
    WS,
    WSS,
    HTTP2,
    HTTP3,
}
pub enum EncryptionType<'a> {
    NonSecure,
    Secure(&'a Arc<ServerConfig>),
    HTTP2,
    HTTP3,
}
impl<'a> fmt::Debug for EncryptionType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EncryptionType::NonSecure => "NonSecure",
                EncryptionType::Secure(_) => "Secure(&Arc { data: internal rustls::ServerConfig })",
                EncryptionType::HTTP2 => "HTTP2",
                EncryptionType::HTTP3 => "HTTP3",
            }
        )
    }
}
pub struct ConnectionSecurity {
    scheme: ConnectionScheme,
    tls_config: Option<Arc<ServerConfig>>,
}
impl ConnectionSecurity {
    pub fn http1s(config: Arc<ServerConfig>) -> Self {
        Self {
            scheme: ConnectionScheme::HTTP1S,
            tls_config: Some(config),
        }
    }
    pub fn http1() -> Self {
        Self {
            scheme: ConnectionScheme::HTTP1,
            tls_config: None,
        }
    }

    pub fn get_config(&self) -> EncryptionType {
        match self.tls_config.as_ref() {
            Some(config) => EncryptionType::Secure(config),
            None => EncryptionType::NonSecure,
        }
    }
    pub fn get_scheme(&self) -> &ConnectionScheme {
        &self.scheme
    }
}
impl Clone for ConnectionSecurity {
    fn clone(&self) -> Self {
        Self {
            scheme: self.scheme,
            tls_config: self
                .tls_config
                .as_ref()
                .map(|to_clone| Arc::clone(&to_clone)),
        }
    }
}
impl fmt::Debug for ConnectionSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConnectionSecurity {{ scheme: {:?}, tls_config: {} }}",
            self.scheme,
            match self.tls_config {
                Some(_) => "Some(rustls::ServerConfig)",
                None => "None",
            }
        )
    }
}

#[derive(Debug)]
pub struct Connection {
    socket: TcpStream,
    address: SocketAddr,
    token: mio::Token,
    layer: InformationLayer,
    closing: bool,
    _scheme: ConnectionScheme,
}
impl Connection {
    fn _new(
        socket: TcpStream,
        address: SocketAddr,
        token: mio::Token,
        layer: InformationLayer,
        scheme: ConnectionScheme,
    ) -> Self {
        Self {
            socket,
            address: address,
            token,
            layer,
            closing: false,
            _scheme: scheme,
        }
    }
    pub fn new(
        socket: TcpStream,
        address: SocketAddr,
        token: mio::Token,
        connection: ConnectionSecurity,
    ) -> Option<Self> {
        match connection.get_config() {
            EncryptionType::NonSecure => Some(Self::_new(
                socket,
                address,
                token,
                InformationLayer::Buffered(BufferedLayer::new()),
                *connection.get_scheme(),
            )),
            EncryptionType::Secure(config) => Some(Self::_new(
                socket,
                address,
                token,
                InformationLayer::TLS(ServerSession::new(config)),
                *connection.get_scheme(),
            )),
            _ => {
                // Shut down socket if not supported!
                let _ = socket.shutdown(Shutdown::Both);
                drop(socket);
                return None;
            }
        }
    }

    pub fn ready(
        &mut self,
        registry: &mio::Registry,
        event: &MioEvent,
        storage: &mut Storage,
        extensions: &mut extensions::ExtensionMap,
    ) {
        // If socket is readable, read from socket to session
        if event.readable() && !event.hint_read_closed() {
            // Read request from session to buffer
            let (request, request_len) = {
                let mut buffer = [0; 16_384_usize];
                let len = match self.layer.pull(&mut self.socket, &mut buffer) {
                    Ok(len) => len,
                    Err(err) => match err {
                        PullError::IO(err) if err.kind() == io::ErrorKind::ConnectionReset => {
                            self.close();
                            0
                        }
                        PullError::IO(_err) => {
                            #[cfg(feature = "error-log")]
                            eprintln!("Failed with IO: {}", _err);
                            self.close();
                            0
                        }
                        PullError::TLSError(_err) => {
                            #[cfg(feature = "error-log")]
                            eprintln!("Failed to process packets {}", _err);
                            self.close();
                            0
                        }
                    },
                };
                (buffer, len)
            };

            // If not empty, parse and process it!
            if request_len > 0 {
                let mut close = ConnectionHeader::KeepAlive;
                if request_len == request.len() {
                    #[cfg(feature = "error-log")]
                    eprintln!("Request too large!");
                    let _ = utility::default_error(413, &close, Some(storage.get_fs()))
                        .write_all(&mut self.layer);
                } else {
                    match parse::parse_request(&request[..request_len]) {
                        Ok(parsed) => {
                            // Get close header
                            close = ConnectionHeader::from_close({
                                match parsed.headers().get("connection") {
                                    Some(connection) => {
                                        connection
                                            == http::header::HeaderValue::from_static("close")
                                    }
                                    None => false,
                                }
                            });

                            match parsed.version() {
                                http::Version::HTTP_11 => {
                                    if let Err(err) = crate::process_request(
                                        &mut self.layer,
                                        &self.address,
                                        parsed,
                                        &request[..],
                                        &close,
                                        storage,
                                        extensions,
                                    ) {
                                        #[cfg(feature = "error-log")]
                                        eprintln!("Failed to write output to layer! {:?}", err);
                                    };
                                    // Flush all contents, important for compression
                                    let _ = self.layer.flush();
                                }
                                _ => {
                                    // Unsupported HTTP version!
                                    let _ =
                                        utility::default_error(505, &close, Some(storage.get_fs()))
                                            .write_all(&mut self.layer);
                                }
                            }
                        }
                        Err(err) => {
                            #[cfg(feature = "error-log")]
                            eprintln!(
                                "Failed to parse request, write something as a response? Err: {:?}",
                                err,
                            );
                            let _ = utility::default_error(400, &close, Some(storage.get_fs()))
                                .write_all(&mut self.layer);
                        }
                    };
                }

                if close.close() {
                    self.layer.notify_close();
                };
            }
        }
        if event.writable() && !event.hint_write_closed() {
            match self.layer.push(&mut self.socket) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    // If the whole message couldn't be transmitted in one round, do nothing to allow connection to reregister
                }
                Err(err) => {
                    #[cfg(feature = "error-log")]
                    eprintln!("Error writing to socket! {:?}", err);
                    self.close();
                }
                // Do nothing!
                Ok(_) => {}
            };
        }

        if self.closing || event.hint_both_closed() {
            #[cfg(feature = "info-log")]
            println!("Closing connection!");
            let _ = self.socket.shutdown(Shutdown::Both);
            self.deregister(registry);
        } else {
            self.reregister(registry);
        };
    }

    #[inline]
    pub fn get_addr(&self) -> &SocketAddr {
        &self.address
    }
    #[cfg(feature = "limiting")]
    #[inline]
    pub fn too_many_requests(&mut self) -> io::Result<()> {
        // Have to clear, since old data will maybe be laying around, since not all MIO events are write, and a write could be interrupted.
        self.layer.clear();
        self.layer.write(limiting::TOO_MANY_REQUESTS)?;
        let _ = self.layer.push(&mut self.socket);
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
        let rd = self.layer.wants_read();
        let wr = self.layer.wants_write();

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
    pub fn close(&mut self) {
        self.closing = true;
    }
}

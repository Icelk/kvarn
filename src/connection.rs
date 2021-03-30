use crate::prelude::{fs::*, rustls_prelude::*, *};

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
}
impl<'a> Debug for EncryptionType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EncryptionType::NonSecure => "NonSecure",
                EncryptionType::Secure(_) => "Secure(&Arc { data: internal rustls::ServerConfig })",
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
            tls_config: self.tls_config.as_ref().map(Arc::clone),
        }
    }
}
impl Debug for ConnectionSecurity {
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

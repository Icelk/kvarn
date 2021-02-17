use tokio::io::{AsyncRead, AsyncReadExt};

use crate::prelude::*;

pub enum Proto {
    TCP,
    QUIC,
}
impl Proto {
    /// ToDo: Convert this to a thing implementing [`AsyncRead`]
    pub async fn to_buffer<R: AsyncRead + Unpin>(self, reader: R) -> io::Result<Vec<u8>> {
        match self {
            Proto::TCP => read_tcp(reader).await,
            Proto::QUIC => unimplemented!("no HTTP/3 support yet"),
        }
    }
}

async fn read_tcp<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(1024 * 16);
    unsafe { buffer.set_len(buffer.capacity()) };
    let r = match reader.read(&mut buffer[..]).await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to read: {:?}", e);
            return Err(e);
        }
    };
    unsafe { buffer.set_len(r) };
    Ok(buffer)
}

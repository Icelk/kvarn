use crate::prelude::*;
pub fn decrypt(
    bytes: Vec<u8>,
    security: &ConnectionSecurity,
) -> Result<Vec<u8>, crate::connection::PullError> {
    use connection::EncryptionType;
    use rustls::Session;

    match security.get_config() {
        EncryptionType::NonSecure => Ok(bytes),
        EncryptionType::Secure(config) => {
            let mut buffer = Vec::with_capacity(1024 * 16);
            unsafe { buffer.set_len(buffer.capacity()) };

            let mut session = rustls::ServerSession::new(config);

            let read = match session.read_tls(&mut &*bytes) {
                Err(err) => return Err(err.into()),
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "TLS read zero bytes",
                    )
                    .into())
                }
                _ => match session.process_new_packets() {
                    Err(err) => return Err(err.into()),
                    // Everything succeeded
                    Ok(()) => utility::read_to_end(&mut buffer, &mut session, false)
                        .map_err(|err| err.into())?,
                },
            };
            unsafe { buffer.set_len(read) };
            Ok(buffer)
        }
        _ => unimplemented!(),
    }
}

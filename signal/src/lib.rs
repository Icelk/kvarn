#[cfg(unix)]
pub mod unix {
    use log::{error, warn};
    use std::io;
    use std::ops::Deref;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    pub enum UnixResponse<T> {
        /// The socket wasn't found, or had no listener.
        NotFound,
        /// An error occured in reading or writing.
        Error,
        /// Successful transmission.
        Data(T),
    }
    impl<D: ?Sized, T: Deref<Target = D>> UnixResponse<T> {
        /// Turns `&UnixResponse<T>` to `UnixResponse<&D>`
        /// where `T: Deref<Target = D>`.
        /// For example, `UnixResponse<Vec<u8>>.as_deref() == &UnixResponse<&[u8]>`
        pub fn as_deref(&self) -> UnixResponse<&D> {
            match self {
                Self::NotFound => UnixResponse::NotFound,
                Self::Error => UnixResponse::Error,
                Self::Data(t) => UnixResponse::Data(&**t),
            }
        }
    }

    /// Sends `data` to a [`UnixListener`] at `path`.
    pub async fn send_to(data: &[u8], path: impl AsRef<Path>) -> UnixResponse<Vec<u8>> {
        let path = path.as_ref();
        match UnixStream::connect(path).await {
            Err(err) => match err.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                    UnixResponse::NotFound
                }
                _ => {
                    error!("Got error when trying to shut down previous instance of Kvarn: {:?}\nTrying to start server anyway.", err);
                    UnixResponse::Error
                }
            },
            Ok(mut connection) => {
                if let Err(err) = connection.write_all(data).await {
                    error!("Failed to send message! {:?}", err);
                    UnixResponse::Error
                } else {
                    // Flushes the data.
                    connection.shutdown().await.unwrap();

                    let mut buf = Vec::new();
                    if let Err(err) = connection.read_to_end(&mut buf).await {
                        error!("Failed to receive message. {:?}", err);
                        UnixResponse::Error
                    } else {
                        UnixResponse::Data(buf)
                    }
                }
            }
        }
    }
    /// Starts an [`UnixListener`] at `path` with `handler` receiving messages.
    ///
    /// This starts a new task, and so the future resolves quickly.
    ///
    /// The `handler` gets the data from the request, and should return whether to close the
    /// listener and the data to send back.
    pub async fn start_at(
        handler: impl Fn(&[u8]) -> (bool, Vec<u8>) + Send + 'static,
        path: impl AsRef<Path>,
    ) {
        let path = path.as_ref();
        if tokio::fs::remove_file(path).await.is_ok() {
            warn!("Removed old Kvarn socket.");
        }
        match UnixListener::bind(path) {
            Err(err) => error!(
                "Failed to listen on {:?}. Handover will not work! {:?}",
                path, err
            ),
            Ok(listener) => {
                tokio::spawn(async move {
                    while let Ok((mut connection, _addr)) = listener.accept().await {
                        let mut data = Vec::new();
                        if let Err(err) = connection.read_to_end(&mut data).await {
                            warn!("Failed on reading request: {err:?}");
                            continue;
                        }
                        let (close, data) = handler(&data);
                        if let Err(err) = connection.write_all(&data).await {
                            warn!("Failed to write response: {err:?}");
                            continue;
                        }
                        if let Err(err) = connection.shutdown().await {
                            error!("Failed to flush content. {:?}", err);
                        }
                        if close {
                            break;
                        }
                    }
                });
            }
        }
    }
}

//! Inter process signalling library used by `kvarnctl` to communicate with Kvarn.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

#[cfg(unix)]
pub mod unix {
    use log::{error, warn};
    use std::io;
    use std::ops::Deref;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    pub enum Response<T> {
        /// The socket wasn't found, or had no listener.
        NotFound,
        /// An error occurred in reading or writing.
        Error,
        /// Successful transmission.
        Data(T),
    }
    impl<D: ?Sized, T: Deref<Target = D>> Response<T> {
        /// Turns `&UnixResponse<T>` to `UnixResponse<&D>`
        /// where `T: Deref<Target = D>`.
        /// For example, `UnixResponse<Vec<u8>>.as_deref() == &UnixResponse<&[u8]>`
        pub fn as_deref(&self) -> Response<&D> {
            match self {
                Self::NotFound => Response::NotFound,
                Self::Error => Response::Error,
                Self::Data(t) => Response::Data(&**t),
            }
        }
    }

    /// Sends `data` to a [`UnixListener`] at `path`.
    pub async fn send_to(data: &[u8], path: impl AsRef<Path>) -> Response<Vec<u8>> {
        let path = path.as_ref();
        match UnixStream::connect(path).await {
            Err(err) => match err.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => Response::NotFound,
                _ => {
                    error!("Got error when trying to shut down previous instance of Kvarn: {:?}\nTrying to start server anyway.", err);
                    Response::Error
                }
            },
            Ok(mut connection) => {
                if let Err(err) = connection.write_all(data).await {
                    error!("Failed to send message! {:?}", err);
                    Response::Error
                } else {
                    // Flushes the data.
                    connection.shutdown().await.unwrap();

                    let mut buf = Vec::new();
                    if let Err(err) = connection.read_to_end(&mut buf).await {
                        error!("Failed to receive message. {:?}", err);
                        Response::Error
                    } else {
                        Response::Data(buf)
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
    ///
    /// # Return value
    ///
    /// Returns `true` if we removed an existing socket, `false` otherwise.
    /// The removed socket might be live or a leftover from a previous call to this (or any other
    /// UNIX socket creation).
    pub async fn start_at(
        handler: impl Fn(&[u8]) -> (bool, Vec<u8>) + Send + Sync + 'static,
        path: impl AsRef<Path>,
    ) -> bool {
        let path = path.as_ref();
        let overridden = tokio::fs::remove_file(path).await.is_ok();

        match UnixListener::bind(path) {
            Err(err) => error!(
                "Failed to listen on {:?}. Handover will not work! {:?}",
                path, err
            ),
            Ok(listener) => {
                tokio::spawn(async move {
                    let handler = Arc::new(handler);
                    while let Ok((mut connection, _addr)) = listener.accept().await {
                        let mut data = Vec::new();
                        if let Err(err) = connection.read_to_end(&mut data).await {
                            warn!("Failed on reading request: {err:?}");
                            continue;
                        }
                        let handler = Arc::clone(&handler);
                        let (close, data) = tokio::task::spawn_blocking(move || handler(&data))
                            .await
                            .unwrap();
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
        overridden
    }
}

//! Inter process signalling library used by `kvarnctl` to communicate with Kvarn.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

#[cfg(unix)]
pub mod unix {
    use futures_util::FutureExt;
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

    pub struct HandlerResponse {
        /// The response body.
        pub data: Vec<u8>,
        /// If the communication should be closed.
        pub close: bool,
        /// A function to run after sending the response.
        pub post_send: Option<Box<dyn FnOnce() + Send + Sync>>,
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
    /// `handler` is guaranteed to be inside a Tokio context - you can use e.g. [`tokio::spawn`].
    ///
    /// # Return value
    ///
    /// Returns `true` if we removed an existing socket, `false` otherwise.
    /// The removed socket might be live or a leftover from a previous call to this (or any other
    /// UNIX socket creation).
    pub async fn start_at(
        handler: impl Fn(&[u8]) -> HandlerResponse + Send + Sync + 'static,
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
                    // use a sender to poll both the listen loop and the receiver, which receives
                    // when the listen loop wants to break.
                    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

                    let listen_loop = Box::pin(async move {
                        while let Ok((mut connection, _addr)) = listener.accept().await {
                            let handler = Arc::clone(&handler);
                            let sender = sender.clone();

                            // spawn here so the listening isn't blocked.
                            tokio::spawn(async move {
                                let mut data = Vec::new();
                                if let Err(err) = connection.read_to_end(&mut data).await {
                                    warn!("Failed on reading request: {err:?}");
                                    return;
                                }
                                let handler = Arc::clone(&handler);

                                // enter the runtime below to be able to spawn tokio tasks inside
                                // the handler.
                                let runtime = tokio::runtime::Handle::current();
                                let HandlerResponse {
                                    data,
                                    close,
                                    post_send,
                                } = tokio::task::spawn_blocking(move || {
                                    let _rt = runtime.enter();
                                    handler(&data)
                                })
                                .await
                                .unwrap();

                                if let Err(err) = connection.write_all(&data).await {
                                    warn!("Failed to write response: {err:?}");
                                    return;
                                }
                                if let Err(err) = connection.shutdown().await {
                                    warn!("Failed to flush content. {:?}", err);
                                }
                                if let Some(post_send) = post_send {
                                    (post_send)();
                                }
                                if close {
                                    sender.send(()).await.unwrap();
                                }
                            });
                        }
                    });
                    let mut break_recv = Box::pin(receiver.recv().fuse());
                    futures_util::select! {
                        _ = listen_loop.fuse() => (),
                        _ = break_recv => (),
                    };
                });
            }
        }
        overridden
    }
}

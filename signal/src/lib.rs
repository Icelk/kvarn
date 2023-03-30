//! Inter process signalling library used by `kvarnctl` to communicate with Kvarn.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

#[cfg(unix)]
pub mod unix {
    use log::{debug, error, info, warn};
    use notify::Watcher;
    use std::future::Future;
    use std::io;
    use std::ops::Deref;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::Arc;
    #[cfg(not(feature = "uring"))]
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };
    #[cfg(feature = "uring")]
    use tokio_uring::net::{UnixListener, UnixStream};

    #[cfg(feature = "uring")]
    fn spawn<T: 'static>(f: impl Future<Output = T> + 'static) -> impl Future<Output = T> {
        let handle = tokio_uring::spawn(f);
        async move { handle.await.unwrap() }
    }
    #[cfg(not(feature = "uring"))]
    fn spawn<T: 'static + Send>(
        f: impl Future<Output = T> + 'static + Send,
    ) -> impl Future<Output = T> {
        let handle = tokio::spawn(f);
        async move { handle.await.unwrap() }
    }

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
    pub async fn send_to(data: impl Into<Vec<u8>>, path: impl AsRef<Path>) -> Response<Vec<u8>> {
        let path = path.as_ref();
        match UnixStream::connect(path).await {
            Err(err) => match err.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => Response::NotFound,
                _ => Response::Error,
            },
            #[allow(unused_mut)]
            Ok(mut connection) => {
                debug!("Connected to {path:?}");

                #[cfg(feature = "uring")]
                let (r, mut buf): (_, Vec<u8>) = connection.write_all(data.into()).await;

                #[cfg(not(feature = "uring"))]
                let r = connection.write_all(&data.into()).await;
                #[cfg(not(feature = "uring"))]
                // flush
                let r = connection.shutdown().await.and(r);

                if let Err(err) = r {
                    error!("Failed to send message! {:?}", err);
                    Response::Error
                } else {
                    debug!("Wrote to {path:?}");

                    #[cfg(feature = "uring")]
                    {
                        // max 2 kiB size
                        buf.reserve(1024 * 2);
                        #[allow(clippy::uninit_vec)] // we set beck the length after
                        unsafe {
                            buf.set_len(buf.capacity());
                        }
                    }
                    #[cfg(not(feature = "uring"))]
                    let mut buf = vec![];

                    debug!("Try to read from {path:?}");

                    #[cfg(not(feature = "uring"))]
                    let r = connection.read_to_end(&mut buf).await;
                    #[cfg(feature = "uring")]
                    let (r, mut buf) = connection.read(buf).await;
                    match r {
                        Err(err) => {
                            error!("Failed to receive message. {:?}", err);
                            Response::Error
                        }
                        #[cfg(feature = "uring")]
                        Ok(len) => {
                            unsafe { buf.set_len(len) };
                            debug!("Read from {path:?}");
                            Response::Data(buf)
                        }
                        #[cfg(not(feature = "uring"))]
                        Ok(_) => {
                            debug!("Read from {path:?}");
                            Response::Data(buf)
                        }
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
    /// `handler` is guaranteed to be inside an async Tokio context - you can use e.g. [`tokio::spawn`].
    ///
    /// # Return value
    ///
    /// Returns `true` if we removed an existing socket, `false` otherwise.
    /// The removed socket might be live or a leftover from a previous call to this (or any other
    /// UNIX socket creation).
    ///
    /// The sender can be used to signal we need to close (if `true` is sent)
    #[allow(clippy::too_many_lines)]
    pub async fn start_at(
        #[cfg(feature = "uring")] handler: impl Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = HandlerResponse>>>
            + 'static,
        #[cfg(not(feature = "uring"))] handler: impl Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = HandlerResponse> + Send + Sync>>
            + Send
            + Sync
            + 'static,
        path: impl AsRef<Path> + Send + Sync + 'static,
    ) -> (bool, tokio::sync::mpsc::UnboundedSender<bool>) {
        #[cfg(feature = "uring")]
        let overridden = tokio_uring::fs::remove_file(path.as_ref()).await.is_ok();
        #[cfg(not(feature = "uring"))]
        let overridden = tokio::fs::remove_file(path.as_ref()).await.is_ok();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let returned_sender = sender.clone();
        let _task = spawn(async move {
            let path = path.as_ref();
            let sender = Arc::new(sender);
            let handler = Arc::new(handler);

            let reload_sender = Arc::clone(&sender);
            let watcher_path = path.to_path_buf();
            let mut watcher =
                notify::recommended_watcher(move |ev: Result<notify::Event, notify::Error>| {
                    if let Ok(ev) = ev {
                        // for some reason, a metadata event is triggered when the actual file is
                        // deleted. A Delete event is triggered when all file descriptors are
                        // dropped (when we stop listening to the socket)
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        if let notify::EventKind::Modify(notify::event::ModifyKind::Metadata(_)) =
                            ev.kind
                        {
                            let meta = std::fs::metadata(&watcher_path);
                            if meta.is_err() {
                                drop(reload_sender.send(false));
                            }
                        }
                    }
                })
                .ok();
            if watcher.is_none() {
                warn!("Failed to watch socket for deletion");
            }

            // loop to not recurse function & recurse Arc<handler>
            'outer: loop {
                match UnixListener::bind(path) {
                    Err(err) => {
                        error!("Failed to bind signal socket: {err}");
                        return;
                    }
                    Ok(listener) => {
                        if let Some(watcher) = &mut watcher {
                            if watcher
                                .watch(path, notify::RecursiveMode::NonRecursive)
                                .is_err()
                            {
                                warn!("Failed to watch socket for deletion");
                            }
                        }

                        debug!("Bound");
                        debug!("In tokio task");
                        // use a sender to poll both the listen loop and the receiver, which receives
                        // when the listen loop wants to break.

                        let sender = Arc::clone(&sender);
                        let handler = Arc::clone(&handler);
                        loop {
                            let r = tokio::select! {
                                r = listener.accept() => r,
                                Some(close) = receiver.recv() => if close
                                    {break 'outer}
                                    else
                                    {
                                        // just being explicit
                                        // this causes a Delete event at `path`
                                        drop(listener);
                                        warn!("Re-listening because socket file got deleted");
                                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                        while let Ok(close) = receiver.try_recv() {
                                            if close {
                                                break 'outer;
                                            }
                                        }
                                        continue 'outer;
                                    },
                                else => {
                                    error!("Stopping because close stream was closed!");
                                    break 'outer;
                                },
                            };
                            match r {
                                Ok(connection) => {
                                    #[cfg(not(feature = "uring"))]
                                    let (mut connection, _addr) = connection;

                                    let handler = Arc::clone(&handler);
                                    let sender = sender.clone();
                                    debug!("accepted connection");

                                    // spawn here so the listening isn't blocked.
                                    let _task = spawn(async move {
                                        debug!("In tokio task, handling message");
                                        let mut data = Vec::with_capacity(4 * 1024);
                                        #[allow(clippy::uninit_vec)] // we set back the length after
                                        unsafe {
                                            data.set_len(data.capacity());
                                        }

                                        #[cfg(not(feature = "uring"))]
                                        let r = connection.read_to_end(&mut data).await;
                                        #[cfg(feature = "uring")]
                                        let (r, mut data) = connection.read(data).await;
                                        match r {
                                            Err(err) => {
                                                warn!("Failed on reading request: {err:?}");
                                                return;
                                            }
                                            #[cfg(feature = "uring")]
                                            Ok(len) => unsafe { data.set_len(len) },
                                            #[cfg(not(feature = "uring"))]
                                            Ok(_) => {}
                                        }
                                        debug!(
                                            "Read {} from remote",
                                            String::from_utf8_lossy(&data)
                                        );
                                        let handler = Arc::clone(&handler);

                                        let HandlerResponse {
                                            data,
                                            close,
                                            post_send,
                                        } = handler(data).await;

                                        if close {
                                            info!("Closing");
                                            drop(sender.send(true));
                                            debug!("Closed");
                                        }

                                        debug!("Write response");

                                        #[cfg(feature = "uring")]
                                        if let (Err(err), _) = connection.write_all(data).await {
                                            warn!("Failed to write response: {err:?}");
                                            return;
                                        }
                                        #[cfg(not(feature = "uring"))]
                                        if let Err(err) = connection.write_all(&data).await {
                                            warn!("Failed to write response: {err:?}");
                                            return;
                                        }

                                        debug!("Wrote response");
                                        if let Some(post_send) = post_send {
                                            (post_send)();
                                        }
                                        debug!("Handled post send");
                                    });
                                }
                                Err(err) => {
                                    warn!("Signal listener got an error: {err:?}");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        (overridden, returned_sender)
    }
}

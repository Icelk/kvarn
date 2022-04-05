//! Control the Kvarn server from the outside.
//!
//! [`Plugin`]s can be added using [`RunConfig::add_plugin`].
use crate::prelude::*;

/// The arguments passed by `kvarnctl` to a [`Plugin`].
#[derive(Debug, Clone)]
pub struct Arguments {
    name: String,
    args: Vec<String>,
}
/// The kind of response to send back to `kvarnctl`.
#[derive(Debug, Clone)]
pub enum PluginResponseKind {
    /// The request was executed without errors.
    Ok {
        /// The optional response data.
        data: Option<Vec<u8>>,
    },
    /// The request failed to execute.
    Error {
        /// The optional response data.
        data: Option<Vec<u8>>,
    },
}
/// A response in reply to the [request](Arguments) `kvarnctl` sent.
pub struct PluginResponse {
    /// The kind of response.
    pub kind: PluginResponseKind,
    /// If the socket should be closed. Should ONLY be used when we are immediately shutting down.
    pub close: bool,
    /// A function to run after sending the response.
    pub post_send: Option<Box<dyn FnOnce() + Send + Sync>>,
}
impl PluginResponse {
    /// Crates a new response which doesn't close the connection.
    #[must_use]
    pub fn new(kind: PluginResponseKind) -> Self {
        Self {
            kind,
            close: false,
            post_send: None,
        }
    }
    /// Close the ctl socket after this is returned.
    /// Use this only is you shut Kvarn down immediately in your plugin.
    #[must_use]
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }
    /// Add a callback to fun after the response is sent.
    #[must_use]
    pub fn post_send(mut self, f: impl FnOnce() + Send + Sync + 'static) -> Self {
        self.post_send = Some(Box::new(f));
        self
    }
}
impl Debug for PluginResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct(utils::ident_str!(PluginResponse));
        utils::fmt_fields!(
            s,
            (self.kind),
            (self.close),
            (
                self.post_send,
                &self.post_send.as_ref().map(|_| "[fn]".as_clean())
            )
        );
        s.finish()
    }
}
/// These are ran on separate threads, so they can block.
///
/// They are ran within a tokio context, so you can use e.g. [`tokio::spawn`].
pub type Plugin = Box<
    dyn Fn(Arguments, &Vec<PortDescriptor>, &shutdown::Manager) -> PluginResponse + Send + Sync,
>;

/// Check if `args` has no arguments. If that's the case, an error with the appropriate
/// [`PluginResponse`] is returned. Use the `if let Err()` pattern to easily return.
#[allow(clippy::missing_errors_doc)]
pub fn check_no_arguments(args: &Arguments) -> Result<(), PluginResponse> {
    if args.args.is_empty() {
        Ok(())
    } else {
        Err(PluginResponse {
            kind: PluginResponseKind::Error {
                data: Some("no arguments were expected".into()),
            },
            close: false,
            post_send: None,
        })
    }
}

pub(crate) struct Plugins {
    plugins: HashMap<String, Plugin>,
    // remember to add fields to debug implementation
}
impl Debug for Plugins {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let name = utils::ident_str!(Plugins);
        let mut s = f.debug_struct(name);
        utils::fmt_fields!(
            s,
            (
                self.plugins,
                &self
                    .plugins
                    .iter()
                    .map(|(key, _)| (key, "[ opaque plugin ]".as_clean()))
                    .collect::<HashMap<_, _>>()
            )
        );
        s.finish()
    }
}
impl Plugins {
    pub(crate) fn new() -> Self {
        let mut me = Self::empty();
        #[cfg(feature = "graceful-shutdown")]
        me.add_plugin(
            "shutdown",
            Box::new(|args, _, shutdown| {
                if let Err(r) = check_no_arguments(&args) {
                    return r;
                }
                tokio::runtime::Handle::current().block_on(async move {
                    // we register (with the call to `wait_for_pre_shutdown`),
                    // then shut down, then wait.
                    // If we shut down before registering, we could hang forever
                    let sender = shutdown.wait_for_pre_shutdown();
                    shutdown.shutdown();
                    let sender = sender.await;

                    PluginResponse::new(PluginResponseKind::Ok {
                        data: Some("'Successfully completed a graceful shutdown.'".into()),
                    })
                    .close()
                    .post_send(move || {
                        sender.send(()).expect("failed to shut down");
                    })
                })
            }),
        );
        me.add_plugin(
            "ping",
            Box::new(|args, _, _| {
                let mut data = args.args.iter().fold(String::new(), |mut acc, arg| {
                    acc.push(' ');
                    utils::encode_quoted_str(arg, &mut acc);
                    acc
                });
                // remove first space
                if !data.is_empty() {
                    data.remove(0);
                }
                PluginResponse::new(PluginResponseKind::Ok {
                    data: Some(data.into_bytes()),
                })
            }),
        );
        me
    }
    pub(crate) fn add_plugin(&mut self, name: impl AsRef<str>, plugin: Plugin) -> &mut Self {
        self.plugins.insert(name.as_ref().to_owned(), plugin);
        self
    }
    pub(crate) fn empty() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }
}
impl Default for Plugins {
    fn default() -> Self {
        Self::new()
    }
}

/// Default message path.
pub(crate) const SOCKET_PATH: &str = "/tmp/kvarn.sock";

/// Initiates the handover from a old instance to the one currently running, if the
/// `graceful-shutdown` feature is enabled. Else, just opens the socket at `path`.
/// [`SOCKET_PATH`] is the fallback.
///
/// This sends a `shutdown` message, waits for a reply, and then starts listening.
///
/// This doesn't resolve until the last instance was shut down.
pub(crate) async fn listen(
    plugins: Plugins,
    ports: Arc<Vec<PortDescriptor>>,
    shutdown: Arc<shutdown::Manager>,
    path: Option<impl AsRef<Path>>,
) {
    #[cfg(unix)]
    {
        let path = path.map_or_else(|| PathBuf::from(SOCKET_PATH), |p| p.as_ref().to_path_buf());

        #[cfg(feature = "graceful-shutdown")]
        {
            assert_eq!(
                shutdown.handover_socket_path, None,
                "Cannot call `initiate_handover` twice!"
            );

            // This is OK, we only write once, and atomics aren't needed as
            // accessing isn't important to be timely after value change.
            unsafe {
                *utils::ref_to_mut(&shutdown.handover_socket_path) = Some(path.clone());
            }
        }

        let supports_shutdown = plugins.plugins.contains_key("shutdown");

        if supports_shutdown {
            match kvarn_signal::unix::send_to(b"shutdown", &path)
                .await
                .as_deref()
            {
                // continue normally
                kvarn_signal::unix::Response::Data(data) if data.starts_with(b"ok") => {}
                kvarn_signal::unix::Response::NotFound => {}

                kvarn_signal::unix::Response::Data(data) => {
                    error!(
                        "Got unexpected reply from previous Kvarn instance: {:?}. \
                    Will not be listening for kvarnctl messages.",
                        str::from_utf8(data).unwrap_or("[binary]")
                    );
                    return;
                }
                kvarn_signal::unix::Response::Error => {
                    error!(
                        "Failed to message previous Kvarn instance. \
                    It might still be running. Will not be listening for kvarnctl messages."
                    );
                    return;
                }
            };
        }

        let overriden = kvarn_signal::unix::start_at(
            move |data| {
                let data = if let Ok(s) = str::from_utf8(data) {
                    s
                } else {
                    return kvarn_signal::unix::HandlerResponse {
                        data: "error Received binary content. Requests have to be UTF-8.".into(),
                        close: false,
                        post_send: None,
                    };
                };
                let mut iter = utils::quoted_str_split(data);
                let name = iter.next().unwrap_or_default();
                let args = iter.collect();
                let arguments = Arguments { name, args };

                if let Some(plugin) = plugins.plugins.get(&arguments.name) {
                    let response = (plugin)(arguments, &ports, &shutdown);
                    let (data, prepend) = match response.kind {
                        PluginResponseKind::Error { data } => {
                            if let Some(data) = data.as_deref() {
                                warn!(
                                    "Encountered error on kvarnctl socket: {:?}",
                                    String::from_utf8_lossy(data)
                                );
                            } else {
                                warn!("Encountered error on kvarnctl socket.");
                            }
                            (data, "error")
                        }
                        PluginResponseKind::Ok { data } => (data, "ok"),
                    };
                    let mut data = data.unwrap_or_default();
                    let len = prepend.len() + if data.is_empty() { 0 } else { 1 };
                    (0..len).for_each(|_| data.insert(0, b' '));
                    data[..prepend.len()].copy_from_slice(prepend.as_bytes());

                    kvarn_signal::unix::HandlerResponse {
                        data,
                        close: response.close,
                        post_send: response.post_send,
                    }
                } else {
                    warn!("Got unexpected message on socket: {:?}", data,);
                    kvarn_signal::unix::HandlerResponse {
                        data: Vec::from("error 'Command not found.'"),
                        close: false,
                        post_send: None,
                    }
                }
            },
            &path,
        )
        .await;

        if overriden {
            if supports_shutdown {
                info!("Removed old kvarnctl socket.");
            } else {
                warn!("Removed old kvarnctl socket. The other instance might still be running. \
                      Consider adding a `shutdown` plugin or enabling the `graceful-shutdown` cargo feature.");
            }
        }
    }
    #[cfg(windows)]
    {
        warn!("Trying to listen for kvarnctl messages on an unsupported platform. Currently, UNIX is supported.");
    }
}

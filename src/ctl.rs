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
    dyn for<'a> Fn(
            Arguments,
            &'a Vec<PortDescriptor>,
            &'a shutdown::Manager,
            &'a Plugins,
        ) -> Pin<Box<dyn Future<Output = PluginResponse> + Send + Sync + 'a>>
        + Send
        + Sync,
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

/// The plugins this Kvarn instance supports.
///
/// All plugins added by [`RunConfig::add_plugin`] are available to [`Plugin`]s in runtime.
///
/// # Defaults
///
/// More info can be found at [kvarn.org](https://kvarn.org/ctl/).
///
/// ## `shutdown`
///
/// If the feature `graceful-shutdown` is enabled, a plugin with the name `shutdown` is
/// added. It's functionality can be changed by adding a new plugin with the same name.
///
/// ## `ping`
///
/// The `ping` plugin sends back all the args we received.
///
/// ## `reload`
///
/// Starts a new instance of Kvarn which takes control.
/// Requires a `shutdown` plugin to be present and
/// [handover support](https://kvarn.org/shutdown-handover.#handover).
///
/// If handover isn't supported, there will be a few milliseconds where no one's listening
/// on the port.
///
/// ## `wait`
///
/// Waits for the Kvarn instance to shut down.
pub struct Plugins {
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
    // constructors
    pub(crate) fn new() -> Self {
        let mut me = Self::empty();
        #[cfg(feature = "graceful-shutdown")]
        me.with_shutdown();
        me.with_ping().with_reload().with_wait();
        me
    }
    pub(crate) fn empty() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    // add plugins
    pub(crate) fn add_plugin(&mut self, name: impl AsRef<str>, plugin: Plugin) -> &mut Self {
        self.plugins.insert(name.as_ref().to_owned(), plugin);
        self
    }
    pub(crate) fn _add_plugin(&mut self, name: String, plugin: Plugin) -> &mut Self {
        self.plugins.insert(name, plugin);
        self
    }
    #[cfg(feature = "graceful-shutdown")]
    pub(crate) fn with_shutdown(&mut self) -> &mut Self {
        self.add_plugin(
            "shutdown",
            plugin!(|args, _, shutdown, _| {
                if let Err(r) = check_no_arguments(&args) {
                    return r;
                }
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
            }),
        );
        self
    }
    pub(crate) fn with_ping(&mut self) -> &mut Self {
        self.add_plugin(
            "ping",
            plugin!(|args, _, _, _| {
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
        self
    }
    pub(crate) fn with_reload(&mut self) -> &mut Self {
        self.add_plugin(
            "reload",
            plugin!(|args, _, shutdown, plugins| {
                if let Err(r) = check_no_arguments(&args) {
                    return r;
                }
                if !plugins.contains_plugin("shutdown") {
                    return PluginResponse::new(PluginResponseKind::Error {
                        data: Some(
                            "No shutdown plugin was found. It is required for reload.".into(),
                        ),
                    });
                }

                let executable = std::env::current_exe()
                    .map(PathBuf::into_os_string)
                    .or_else(|_| {
                        std::env::args_os().next().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "executable not found")
                        })
                    });
                let program = match executable {
                    Ok(p) => p,
                    Err(err) => {
                        error!("Could not reload - arg0 isn't found: {err}");
                        return PluginResponse::new(PluginResponseKind::Error {
                            data: Some(format!("arg0 isn't found: {err}").into()),
                        });
                    }
                };
                let mut command = std::process::Command::new(program);
                command
                    .args(std::env::args_os().skip(1))
                    .stdin(std::process::Stdio::inherit());

                if let Ok(cwd) = std::env::current_dir() {
                    command.current_dir(cwd);
                }

                let mut _child = match command.spawn() {
                    Ok(c) => c,
                    Err(err) => {
                        error!("Failed to spawn child when reloading: {err}");
                        return PluginResponse::new(PluginResponseKind::Error {
                            data: Some(format!("failed to spawn child: {err}").into()),
                        });
                    }
                };

                let sender = shutdown.wait_for_pre_shutdown().await;

                PluginResponse::new(PluginResponseKind::Ok {
                    data: Some("successfully reloaded Kvarn".into()),
                })
                .post_send(move || sender.send(()).unwrap())
            }),
        );
        self
    }
    pub(crate) fn with_wait(&mut self) -> &mut Self {
        self.add_plugin(
            "wait",
            plugin!(|args, _, shutdown, _| {
                if let Err(r) = check_no_arguments(&args) {
                    return r;
                }
                let sender = shutdown.wait_for_pre_shutdown().await;
                sender.send(()).unwrap();
                PluginResponse::new(PluginResponseKind::Ok { data: None })
            }),
        );
        self
    }

    // public getters
    /// Check if plugin with `name` is present.
    /// This means it can be called from `kvarnctl`.
    #[must_use]
    pub fn contains_plugin(&self, name: impl AsRef<str>) -> bool {
        self.plugins.contains_key(name.as_ref())
    }
    /// Get an iterator of all the plugins attached to this instance.
    /// All of the returned names are commands which can be called from `kvarnctl`.
    pub fn iter(&self) -> impl Iterator<Item = &str> + Send + Sync + '_ {
        self.plugins.iter().map(|(key, _)| key.as_str())
    }
}
impl Default for Plugins {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a [`Plugin`].
///
/// # Examples
///
/// ```
/// # use kvarn::prelude::*;
/// use ctl::*;
/// let mut config = RunConfig::new();
/// config.add_plugin(
///     "wait",
///     plugin!(|args, _, shutdown, _| {
///         if let Err(r) = check_no_arguments(&args) {
///             return r;
///         }
///         shutdown.wait().await;
///         PluginResponse::new(PluginResponseKind::Ok { data: None })
///     })
/// );
#[macro_export]
macro_rules! plugin {
    (|$args:tt, $ports:tt, $shutdown:tt, $plugins:tt $(,)?|  $code:block ) => {{
        Box::new(|$args, $ports, $shutdown, $plugins| {
            Box::pin(async move { $code }) as $crate::extensions::RetSyncFut<'_, _>
        })
    }};
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

        let plugins = Arc::new(plugins);
        let overriden = kvarn_signal::unix::start_at(
            move |data| {
                let plugins = Arc::clone(&plugins);
                let shutdown = Arc::clone(&shutdown);
                let ports = Arc::clone(&ports);

                Box::pin(async move {
                    let data = &data;
                    let data = if let Ok(s) = str::from_utf8(data) {
                        s
                    } else {
                        return kvarn_signal::unix::HandlerResponse {
                            data: "error Received binary content. Requests have to be UTF-8."
                                .into(),
                            close: false,
                            post_send: None,
                        };
                    };
                    let mut iter = utils::quoted_str_split(data);
                    let name = iter.next().unwrap_or_default();
                    let args = iter.collect();
                    let arguments = Arguments { name, args };

                    if let Some(plugin) = plugins.plugins.get(&arguments.name) {
                        let response = (plugin)(arguments, &ports, &shutdown, &plugins).await;
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
                }) as RetSyncFut<'_, kvarn_signal::unix::HandlerResponse>
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

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
impl Arguments {
    /// Get a reference to the name of this request.
    /// This will be the same as your plugin's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Get a reference to the arguments.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.args.iter().map(String::as_str)
    }
}
/// The kind of response to send back to `kvarnctl`.
/// See [`PluginResponse`] for more details.
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
    /// Creates a new response which doesn't close the connection.
    #[must_use]
    pub fn new(kind: PluginResponseKind) -> Self {
        Self {
            kind,
            close: false,
            post_send: None,
        }
    }
    /// Creates a new OK response with content.
    #[must_use]
    pub fn ok(data: impl Into<Vec<u8>>) -> Self {
        Self::new(PluginResponseKind::Ok {
            data: Some(data.into()),
        })
    }
    /// Creates a new OK response without content.
    #[must_use]
    pub fn ok_empty() -> Self {
        Self::new(PluginResponseKind::Ok { data: None })
    }
    /// Creates a new response signalling an error, with content.
    #[must_use]
    pub fn error(data: impl Into<Vec<u8>>) -> Self {
        Self::new(PluginResponseKind::Error {
            data: Some(data.into()),
        })
    }
    /// Creates a new response signalling an error, without content.
    #[must_use]
    pub fn error_empty() -> Self {
        Self::new(PluginResponseKind::Error { data: None })
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
/// A plugin, similar to the [`extensions`].
/// One can easily be constructed using the [`plugin!`] macro.
///
/// # Examples
///
/// ```
/// # use kvarn::prelude::*;
/// let mut config = RunConfig::new();
/// let plugin: ctl::Plugin = Box::new(|args, _port_descriptors, _shutdown_manager, _plugins| {
///     Box::pin(async move {
///         let mut s = args.name().to_owned();
///         for arg in args.iter() {
///             s.push(' ');
///             s.push_str(arg);
///         }
///         ctl::PluginResponse::ok(s)
///     }) as extensions::RetSyncFut<'_, _>
/// });
/// config = config.add_plugin("my-plugin", plugin);
/// ```
pub type Plugin = Box<
    dyn for<'a> Fn(
            Arguments,
            &'a Vec<PortDescriptor>,
            &'a shutdown::Manager,
            &'a Plugins,
        ) -> RetSyncFut<'a, PluginResponse>
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
/// If the [feature](https://kvarn.org/cargo-features.) `graceful-shutdown` is enabled, a plugin with the name `shutdown` is
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
///
/// ## `clear`
///
/// Format: `kvarnctl clear <method> (<host> <file/URI>)`
///
/// Clears caches. Methods available are `all`, `files`, `responses`,
/// and two which clear a specific resource, `file` and `response`.
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
                    .keys()
                    .map(|key| (key, "[ opaque plugin ]".as_clean()))
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
        me.with_ping().with_reload().with_wait().with_clear();
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
    #[cfg(feature = "graceful-shutdown")]
    pub(crate) fn with_shutdown(&mut self) -> &mut Self {
        self.add_plugin(
            "shutdown",
            plugin!(|args, _, shutdown, _| {
                let mut iter = args.iter();
                let arg = iter.next();
                let no_wait;
                match arg {
                    Some("no-wait") => no_wait = true,
                    None => no_wait = false,
                    Some(arg) => {
                        return PluginResponse::error(format!("unexpected argument: {arg:?}"))
                    }
                }
                if iter.next().is_some() {
                    return PluginResponse::error("unexpected argument");
                }
                // we register (with the call to `wait_for_pre_shutdown`),
                // then shut down, then wait.
                // If we shut down before registering, we could hang forever
                let sender = if no_wait {
                    None
                } else {
                    Some(shutdown.wait_for_pre_shutdown())
                };
                shutdown.shutdown();
                let sender = if let Some(sender) = sender {
                    Some(sender.await)
                } else {
                    None
                };

                PluginResponse::ok("'Successfully completed a graceful shutdown.'")
                    .close()
                    .post_send(move || {
                        if let Some(sender) = sender {
                            sender.send(()).expect("failed to shut down");
                        }
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
                PluginResponse::ok(data)
            }),
        );
        self
    }
    pub(crate) fn with_reload(&mut self) -> &mut Self {
        self.add_plugin(
            "reload",
            plugin!(|args, _, shutdown, plugins| {
                let mut arg_iter = args.iter();
                let wait = arg_iter.next() == Some("wait") && arg_iter.next().is_none();
                if !wait {
                    if let Err(r) = check_no_arguments(&args) {
                        return r;
                    }
                }
                if !plugins.contains_plugin("shutdown") {
                    return PluginResponse::error(
                        "No shutdown plugin was found. It is required for reload.",
                    );
                }

                let executable = std::env::args_os()
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "executable not found"));
                let program = match executable {
                    Ok(p) => p,
                    Err(err) => {
                        error!("Could not reload - arg0 isn't found: {err}");
                        return PluginResponse::error(format!("arg0 isn't found: {err}"));
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
                        return PluginResponse::error(format!("failed to spawn child: {err}"));
                    }
                };

                let sender = if wait {
                    Some(shutdown.wait_for_pre_shutdown().await)
                } else {
                    None
                };

                PluginResponse::ok("successfully reloaded Kvarn").post_send(move || {
                    if let Some(s) = sender {
                        s.send(()).unwrap();
                    }
                })
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
                PluginResponse::ok_empty()
            }),
        );
        self
    }
    pub(crate) fn with_clear(&mut self) -> &mut Self {
        self.add_plugin(
            "clear",
            plugin!(|args, ports, _, _| {
                let mut args = args.iter();
                let msg = match args.next() {
                    Some("all") => {
                        let host = args.next();
                        for hosts in ports.iter().map(PortDescriptor::hosts) {
                            hosts.clear_response_caches(host).await;
                            hosts.clear_file_caches(host).await;
                        }
                        if let Some(host) = host {
                            format!("cleared the caches on {host}")
                        } else {
                            "cleared all caches".to_owned()
                        }
                    }
                    Some("files") => {
                        let host = args.next();
                        for hosts in ports.iter().map(PortDescriptor::hosts) {
                            hosts.clear_file_caches(host).await;
                        }
                        if let Some(host) = host {
                            format!("cleared the file cache on {host}")
                        } else {
                            "cleared all file caches".to_owned()
                        }
                    }
                    Some("responses") => {
                        let host = args.next();
                        for hosts in ports.iter().map(PortDescriptor::hosts) {
                            hosts.clear_response_caches(host).await;
                        }
                        if let Some(host) = host {
                            format!("cleared the response cache on {host}")
                        } else {
                            "cleared all response caches".to_owned()
                        }
                    }
                    Some("file") => {
                        let host = if let Some(a) = args.next() {
                            a
                        } else {
                            return PluginResponse::error(
                                "please supply the host you want to clear the response from",
                            );
                        };
                        let path = if let Some(a) = args.next() {
                            a
                        } else {
                            return PluginResponse::error(
                                "please supply response you want to clear after the host",
                            );
                        };
                        let mut cleared = false;
                        let mut found = false;
                        for hosts in ports.iter().map(PortDescriptor::hosts) {
                            let (f, c) = hosts.clear_file(host, path);
                            cleared = cleared || c;
                            found = found || f;
                        }

                        if !found {
                            // \\' so it isn't removed by the shell parsing
                            return PluginResponse::error(
                                "didn't find the target host. \
                                Use \\'default\\' for the default host",
                            );
                        } else if !cleared {
                            return PluginResponse::error("target file isn\\'t in the cache");
                        }
                        format!("cleared {path:?} from {host:?}")
                    }
                    Some("response") => {
                        let host = if let Some(a) = args.next() {
                            a
                        } else {
                            return PluginResponse::error(
                                "please supply the host you want to clear the response from",
                            );
                        };
                        let response = if let Some(a) = args.next() {
                            a
                        } else {
                            return PluginResponse::error(
                                "please supply response you want to clear after the host",
                            );
                        };
                        let uri = match Uri::builder().path_and_query(response).build() {
                            Ok(uri) => uri,
                            Err(..) => {
                                return PluginResponse::error("failed to format target response");
                            }
                        };
                        let mut cleared = false;
                        let mut found = false;
                        for hosts in ports.iter().map(PortDescriptor::hosts) {
                            let (f, c) = hosts.clear_page(host, &uri);
                            cleared = cleared || c;
                            found = found || f;
                        }

                        if !found {
                            return PluginResponse::error(
                                "didn't find the target host. Use 'default' for the default host",
                            );
                        } else if !cleared {
                            return PluginResponse::error("target response isn't in the cache");
                        }
                        format!("cleared {response:?} from {host:?}")
                    }
                    Some(_) => return PluginResponse::error("clear method invalid"),
                    None => return PluginResponse::error("you must specify what to clear"),
                };

                if args.next().is_some() {
                    return PluginResponse::error("unexpected argument");
                }

                PluginResponse::ok(msg)
            }),
        )
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
        self.plugins.keys().map(String::as_str)
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
///         PluginResponse::ok_empty()
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
#[allow(unused_assignments)]
pub(crate) fn socket_path() -> PathBuf {
    let mut p = Path::new("/run").to_path_buf();
    #[cfg(all(unix, target_os = "macos"))]
    {
        p = std::env::var_os("HOME")
            .map_or_else(|| Path::new("/Library/Caches").to_path_buf(), Into::into);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let user: u32 = unsafe { libc::getuid() };
        if user != 0 {
            p.push("user");
            p.push(user.to_string());
        }
    }
    p.push("kvarn.sock");
    p
}

/// Initiates the handover from a old instance to the one currently running, if the
/// `graceful-shutdown` feature is enabled. Else, just opens the socket at `path`.
/// [`socket_path`] is the fallback.
///
/// This sends a `shutdown` message, waits for a reply, and then starts listening.
///
/// This doesn't resolve until the last instance was shut down.
#[cfg_attr(windows, allow(unused_variables))]
pub(crate) async fn listen(
    plugins: Plugins,
    ports: Arc<Vec<PortDescriptor>>,
    shutdown: Arc<shutdown::Manager>,
    path: impl Into<PathBuf>,
) {
    #[cfg(unix)]
    {
        let path = path.into();

        let supports_shutdown = plugins.plugins.contains_key("shutdown");

        info!("try send shutdown to previous instance");
        if supports_shutdown {
            match kvarn_signal::unix::send_to(b"shutdown no-wait".to_vec(), &path)
                .await
                .as_deref()
            {
                // continue normally
                kvarn_signal::unix::Response::Data(data) if data.starts_with(b"ok") => {
                    info!("Old instance is shutting down");
                }
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
                        It might still be running or \
                        you don't have sufficient privileges to remove leftovers from previous instance. \
                        Will not be listening for kvarnctl messages."
                    );
                    return;
                }
            };
        }

        let plugins = Arc::new(plugins);
        #[cfg(feature = "graceful-shutdown")]
        let sd = shutdown.clone();
        #[allow(unused_variables)]
        let (overriden, close_ctl) = kvarn_signal::unix::start_at(
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

                    if let Some(plugin) = plugins.plugins.get(arguments.name()) {
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
                        let len = prepend.len() + usize::from(!data.is_empty());
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
            path,
        )
        .await;

        #[cfg(feature = "graceful-shutdown")]
        let _task = spawn(async move {
            drop(sd.get_initate_shutdown_watcher().changed().await);
            info!("Send close to ctl socket, because we started shutting down.");
            let _ = close_ctl.send(true);
        })
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

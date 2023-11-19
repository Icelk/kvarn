//! Graceful shutdown for Kvarn.
//!
//! This is handled through a [`Manager`] and several helper structs.
//! The `Manager` is returned from [`RunConfig::execute`] and can be awaited
//! to pause execution till the server is shut down.
//! It is also used to trigger a shutdown.
#[cfg_attr(not(feature = "graceful-shutdown"), allow(unused_imports))]
use crate::prelude::{threading::*, *};
#[cfg(feature = "graceful-shutdown")]
use atomic::{AtomicBool, AtomicIsize};
#[cfg(feature = "graceful-shutdown")]
use std::cell::UnsafeCell;
#[cfg(feature = "graceful-shutdown")]
use tokio::sync::watch::{
    channel as watch_channel, Receiver as WatchReceiver, Sender as WatchSender,
};

/// Index of [`Waker`] in [`WakerList`].
///
/// Opaque type to safely access the [`UnsafeCell`] of `WakerList`.
#[derive(Debug, Clone, Copy)]
#[cfg(feature = "graceful-shutdown")]
#[repr(transparent)]
pub(crate) struct WakerIndex(usize);

/// Wrapper type for `UnsafeCell<Vec<Option<Waker>>>` to enable sharing across threads.
/// This is safe because of the promises [`WakerIndex`] and the use of this struct below.
#[derive(Debug)]
#[cfg(feature = "graceful-shutdown")]
#[repr(transparent)]
pub(crate) struct WakerList(UnsafeCell<Vec<Option<Waker>>>);
#[cfg(feature = "graceful-shutdown")]
impl WakerList {
    pub(crate) fn new(capacity: usize) -> Self {
        Self(UnsafeCell::new(Vec::with_capacity(capacity)))
    }
    pub(crate) fn get_mut(&mut self) -> &mut Vec<Option<Waker>> {
        self.0.get_mut()
    }
    pub(crate) fn get(&self) -> *mut Vec<Option<Waker>> {
        self.0.get()
    }
    /// Notifies all watchers, clearing the list in the process.
    /// This is ok since they are called, and register themselves again.
    pub(crate) fn notify(&self) {
        // See [`Manager::set_waker`] below for safety.
        let wakers = unsafe { &mut *self.get() };
        for waker in wakers.iter_mut().filter_map(Option::take) {
            waker.wake();
        }
    }
}
#[cfg(feature = "graceful-shutdown")]
unsafe impl Sync for WakerList {}
#[cfg(feature = "graceful-shutdown")]
unsafe impl Send for WakerList {}

/// Shutdown manager.
/// Contains a counter of connections and a shutdown flag
/// to determine when to initiate a shutdown.
///
/// This will wait for all current connections to close, but immediately closes listeners.
///
/// Waiting on shutdown is handled using [`tokio::sync::watch`].
#[derive(Debug)]
#[must_use]
pub struct Manager {
    #[cfg(feature = "graceful-shutdown")]
    shutdown: AtomicBool,
    #[cfg(feature = "graceful-shutdown")]
    shutting_down: AtomicBool,
    #[cfg(feature = "graceful-shutdown")]
    connections: AtomicIsize,
    #[cfg(feature = "graceful-shutdown")]
    received: AtomicBool,

    #[cfg(feature = "graceful-shutdown")]
    wakers: std::cell::UnsafeCell<std::sync::Mutex<WakerList>>,

    #[cfg(feature = "graceful-shutdown")]
    inititate_channel: (WatchSender<()>, WatchReceiver<()>),
    #[cfg(feature = "graceful-shutdown")]
    finished_channel: (Arc<WatchSender<()>>, WatchReceiver<()>),
    #[cfg(feature = "graceful-shutdown")]
    pre_shutdown_channel: (
        Arc<WatchSender<tokio::sync::mpsc::UnboundedSender<()>>>,
        WatchReceiver<tokio::sync::mpsc::UnboundedSender<()>>,
    ),
    #[cfg(feature = "graceful-shutdown")]
    pre_shutdown_count: Arc<atomic::AtomicUsize>,

    #[cfg(feature = "graceful-shutdown")]
    pub(crate) handover_socket_path: Option<PathBuf>,
}
unsafe impl Send for Manager {}
unsafe impl Sync for Manager {}
impl Manager {
    /// Creates a new shutdown manager with the capacity of the list of wakers set to `_capacity`.
    ///
    /// # Safety
    ///
    /// `_capacity >= number of add_listener calls`
    pub unsafe fn new(_capacity: usize) -> Self {
        #[cfg(feature = "graceful-shutdown")]
        {
            let channel = watch_channel(());
            let pre_shutdown_channel = watch_channel(tokio::sync::mpsc::unbounded_channel().0);
            Self {
                shutdown: AtomicBool::new(false),
                shutting_down: AtomicBool::new(false),
                connections: AtomicIsize::new(0),
                received: AtomicBool::new(false),

                wakers: std::cell::UnsafeCell::new(std::sync::Mutex::new(WakerList::new(
                    _capacity,
                ))),

                inititate_channel: watch_channel(()),
                finished_channel: (Arc::new(channel.0), channel.1),
                pre_shutdown_channel: (Arc::new(pre_shutdown_channel.0), pre_shutdown_channel.1),
                pre_shutdown_count: Arc::new(atomic::AtomicUsize::new(0)),

                handover_socket_path: None,
            }
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        {
            Self {}
        }
    }
    /// Adds a listener to this manager.
    ///
    /// This is used so the `accept` future resolves immediately when the shutdown is triggered.
    pub(crate) fn add_listener(&self, listener: Listener) -> AcceptManager {
        AcceptManager {
            #[cfg(feature = "graceful-shutdown")]
            index: {
                let mut lock = unsafe { &*self.wakers.get() }.lock().unwrap();
                let wakers = lock.get_mut();
                let len = wakers.len();
                wakers.push(None);
                WakerIndex(len)
            },
            listener,
        }
    }
    /// Gets a watcher for when the shutdown is initiated
    #[cfg(feature = "graceful-shutdown")]
    pub fn get_initate_shutdown_watcher(&self) -> WatchReceiver<()> {
        self.inititate_channel.1.clone()
    }
    /// Adds to the count of connections.
    /// When this connection is closed, you must call [`Manager::remove_connection`]
    /// or a logic error will occur and a shutdown will never happen.
    pub fn add_connection(&self) {
        #[cfg(feature = "graceful-shutdown")]
        {
            self.connections.fetch_add(1, Ordering::Release);
            debug!(
                "Current connections: {}",
                self.connections.load(Ordering::Acquire)
            );
        }
    }
    /// Removes from the count of connections.
    /// If the count reaches 0 and the internal shutdown flag is enabled,
    /// it will initiate a graceful shutdown.
    pub fn remove_connection(&self) {
        #[cfg(feature = "graceful-shutdown")]
        {
            // - 1 at the end because fetch returns the old value.
            let connections = self.connections.fetch_sub(1, Ordering::AcqRel) - 1;
            if connections < 0 {
                warn!(
                    "Connection count is less than 0. \
                    This might be an issue if you didn't explicitly \
                    call `ShutdownManager::remove_connection` in your code."
                );
            }
            if connections <= 0 {
                let shutdown = self.shutdown.load(Ordering::Acquire);
                if shutdown {
                    debug!("There are no connections. Shutting down.");
                    self._shutdown();
                }
            }
            debug!(
                "Current connections: {}",
                self.connections.load(Ordering::Acquire)
            );
        }
    }
    /// Retrieves the number of current connections.
    /// Returns `0` if the feature `graceful-shutdown is disabled`.
    #[must_use]
    pub fn get_connecions(&self) -> isize {
        #[cfg(feature = "graceful-shutdown")]
        {
            self.connections.load(Ordering::Acquire)
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        {
            0
        }
    }
    /// Gets the value of the internal shutdown flag. This signals a graceful shutdown is underway.
    #[cfg(feature = "graceful-shutdown")]
    pub fn get_shutdown(&self, order: Ordering) -> bool {
        self.shutdown.load(order)
    }
    /// # Safety
    ///
    /// We know no other will have mutable access to self by taking `&self`.
    /// We only write to a value in memory. If another thread also does so,
    /// it does not matter which comes first. Also, only one thread should write to this
    /// with the same `index`; this is not a problem since only the Kvarn crate has access to this.
    /// This is also upheld by [`WakerIndex`].
    ///
    /// Also, the list never decreases in length, so the index will always be valid.
    /// Unless it's extended when this is running. But since we initiate with the necessary
    /// capacity (and not less), it **should** never expand.
    #[cfg(all(feature = "graceful-shutdown", feature = "async-networking"))]
    pub(crate) fn set_waker(&self, index: WakerIndex, waker: Waker) {
        let inner = unsafe { &mut *self.wakers.get() };
        let inner = inner.get_mut().unwrap();
        let wakers = unsafe { &mut *inner.get() };
        wakers[index.0] = Some(waker);
    }
    /// # Safety
    ///
    /// See [`Self::set_waker`].
    #[cfg(all(feature = "graceful-shutdown", feature = "async-networking"))]
    pub(crate) fn remove_waker(&self, index: WakerIndex) {
        let inner = unsafe { &mut *self.wakers.get() };
        let inner = inner.get_mut().unwrap();
        let wakers = unsafe { &mut *inner.get() };
        wakers[index.0] = None;
    }

    /// Wraps [`Self`] in a [`Arc`] to use across [`tokio::task`]s.
    #[must_use]
    pub fn build(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Makes Kvarn perform a graceful shutdown.
    ///
    /// This requires you to be on a thread with a
    /// [Tokio runtime](https://docs.rs/tokio/latest/tokio/runtime/struct.Runtime.html).
    /// If you create new `std` threads, you can use
    /// [`Handle::current()`](https://docs.rs/tokio/latest/tokio/runtime/struct.Handle.html#method.current)
    /// to get a movable handle of your runtime. Then call
    /// [`Handle::enter`](https://docs.rs/tokio/latest/tokio/runtime/struct.Handle.html#method.enter)
    /// at the start of your thread's execution and bind it to a shadow variable
    /// (e.g. `let _runtime = runtime_handle.enter()`). That keeps the reference alive during the
    /// thread's whole lifespan.
    #[cfg(feature = "graceful-shutdown")]
    pub fn shutdown(&self) {
        info!(
            "Initiating shutdown. Handover path: {:?}",
            self.handover_socket_path
        );
        self.shutdown.store(true, Ordering::Release);
        self.inititate_channel
            .0
            .send(())
            .expect("we own one receiver");

        #[cfg(unix)]
        if let Some(path) = &self.handover_socket_path {
            std::fs::remove_file(path).ok();
        }

        if self.connections.load(Ordering::Acquire) <= 0 {
            self._shutdown();
        }
        debug!(
            "Current connections: {}",
            self.connections.load(Ordering::Acquire)
        );

        // we stop listening immediately
        info!("Notifying wakers.");
        unsafe { &*self.wakers.get() }.lock().unwrap().notify();
    }
    #[cfg(feature = "graceful-shutdown")]
    fn _shutdown(&self) {
        info!("No connections left. Shutting down.");
        if self.shutting_down.swap(true, Ordering::AcqRel) {
            return;
        }
        let channel = self.finished_channel.0.clone();
        let pre_channel = self.pre_shutdown_channel.0.clone();
        let count = Arc::clone(&self.pre_shutdown_count);
        tokio::spawn(async move {
            let mut confirmation_channel = tokio::sync::mpsc::unbounded_channel();
            // UNWRAP: `self` will always have 1 instance,
            // and `self` doesn't get dropped before we tell `channel` to shutdown.
            pre_channel.send(confirmation_channel.0).unwrap();
            let mut recieved = 0;
            let wanted = count.load(Ordering::Acquire);
            loop {
                if recieved >= wanted {
                    break;
                }
                confirmation_channel.1.recv().await;
                recieved += 1;
            }
            info!("Sending shutdown signal");
            let _ = channel.send(());
        });
    }
    /// Waits for Kvarn to enter the `shutdown` state.
    ///
    /// This is ran after the [`Self::wait_for_pre_shutdown`] hook, which enables you to do work
    /// before this is resolved.
    ///
    /// If the feature `graceful-shutdown` is disabled, this blocks forever.
    pub async fn wait(&self) {
        #[cfg(feature = "graceful-shutdown")]
        {
            let mut receiver = WatchReceiver::clone(&self.finished_channel.1);
            drop(receiver.changed().await);
            if !self.received.swap(true, Ordering::SeqCst) {
                info!("Received shutdown signal");
            }
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        {
            std::future::pending::<()>().await;
        }
    }
    /// Hooks into the stage before Kvarn signals it's [shutdown](Self::wait).
    /// **Use with care.** See comment below.
    ///
    /// You MUST send `()` to the returned sender ONCE when you are done shutting down.
    /// Abuse of this guarantee leads to unwanted timing of shutdown, or none.
    ///
    /// You can call [`Self::shutdown`] before awaiting the returned future.
    ///
    /// If the feature `graceful-shutdown` is disabled, this blocks forever.
    #[allow(clippy::manual_async_fn)] // cfg
    pub fn wait_for_pre_shutdown(
        &self,
    ) -> impl Future<Output = tokio::sync::mpsc::UnboundedSender<()>> + '_ {
        #[cfg(feature = "graceful-shutdown")]
        {
            let mut receiver = WatchReceiver::clone(&self.pre_shutdown_channel.1);
            // we MUST add this before the user can call shutdown, else, it'll load this before the
            // future is ran
            self.pre_shutdown_count.fetch_add(1, Ordering::SeqCst);
            async move {
                drop(receiver.changed().await);
                info!("Client received pre shutdown signal");
                let borrow = receiver.borrow();
                (*borrow).clone()
            }
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        async {
            std::future::pending::<()>().await;
            unreachable!()
        }
    }
}

/// The result of [`AcceptManager::accept`].
/// Can either be a new connection or a shutdown signal.
/// The listener should be dropped right after the shutdown signal is received.
#[must_use]
pub(crate) enum AcceptAction {
    /// Shutdown signal; immediately drop this struct.
    #[allow(dead_code)]
    Shutdown,
    /// Accept a new connection or handle a IO error.
    AcceptTcp(io::Result<(TcpStream, SocketAddr)>),
    /// Accept a new connection or handle a IO error.
    #[cfg(feature = "http3")]
    AcceptUdp(io::Result<h3_quinn::quinn::Connection>),
}
impl Debug for AcceptAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shutdown => write!(f, "Shutdown"),
            Self::AcceptTcp(arg0) => f
                .debug_tuple("Accept")
                .field(&arg0.as_ref().map(|(_, addr)| addr))
                .finish(),
            #[cfg(feature = "http3")]
            Self::AcceptUdp(arg0) => f
                .debug_tuple("Accept")
                .field(
                    &arg0
                        .as_ref()
                        .map(h3_quinn::quinn::Connection::remote_address),
                )
                .finish(),
        }
    }
}
pub(crate) enum Listener {
    Tcp(TcpListener),
    #[cfg(feature = "http3")]
    Udp(h3_quinn::Endpoint),
}
impl Listener {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        match self {
            Listener::Tcp(tcp) => tcp.local_addr(),
            #[cfg(feature = "http3")]
            Listener::Udp(udp) => udp.local_addr(),
        }
        .unwrap_or_else(|_| SocketAddr::V4(net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0)))
    }
}
/// A wrapper around [`TcpListener`] (and `UdpListener` when HTTP/3 comes around)
/// which waits for a new connection **or** a shutdown signal.
#[must_use]
pub(crate) struct AcceptManager {
    #[cfg(feature = "graceful-shutdown")]
    index: WakerIndex,
    listener: Listener,
}
// SAFETY: TcpListener is just an FD, and can be sent across threads.
unsafe impl Send for AcceptManager {}

impl Debug for AcceptManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct(utils::ident_str!(AcceptManager));

        utils::fmt_fields!(
            s,
            #[cfg(feature = "graceful-shutdown")]
            (self.index),
            (self.listener, &"[TcpListener]".as_clean()),
        );

        s.finish()
    }
}
impl AcceptManager {
    /// Waits for a new connection or a shutdown signal.
    ///
    /// Please increase the count of connections on [`Manager`] when this connection is accepted
    /// and decrease it when the connection dies.
    #[allow(clippy::let_and_return)] // cfg
    pub(crate) async fn accept(&mut self, _manager: &Manager) -> AcceptAction {
        #[cfg(feature = "async-networking")]
        {
            let action = AcceptFuture {
                #[cfg(feature = "graceful-shutdown")]
                manager: _manager,
                #[cfg(feature = "graceful-shutdown")]
                index: self.index,
                listener: &mut self.listener,
            }
            .accept()
            .await;
            #[cfg(feature = "graceful-shutdown")]
            _manager.remove_waker(self.index);
            action
        }
        #[cfg(not(feature = "async-networking"))]
        {
            match &mut self.listener {
                Listener::Tcp(tcp) => AcceptAction::AcceptTcp(tcp.accept()),
            }
        }
    }
    /// Returns a reference to the inner listener.
    #[must_use]
    pub(crate) fn inner(&self) -> &Listener {
        &self.listener
    }
}
#[cfg(feature = "async-networking")]
struct AcceptFuture<'a> {
    #[cfg(feature = "graceful-shutdown")]
    manager: &'a Manager,
    #[cfg(feature = "graceful-shutdown")]
    index: WakerIndex,
    listener: &'a mut Listener,
}
#[cfg(all(feature = "async-networking", feature = "http3"))]
async fn accept_udp(endpoint: &mut h3_quinn::Endpoint) -> io::Result<h3_quinn::quinn::Connection> {
    if let Some(s) = endpoint.accept().await {
        s.await.map_err(io::Error::from)
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "accept socket finished",
        ))
    }
}
#[cfg(feature = "async-networking")]
impl<'a> AcceptFuture<'a> {
    async fn accept(self) -> AcceptAction {
        #[cfg(feature = "graceful-shutdown")]
        {
            trace!(
                "Shutting down? {}",
                self.manager.shutdown.load(Ordering::Acquire)
            );
            let shutdown_fut = std::future::poll_fn(|cx| {
                if self.manager.shutdown.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                self.manager.set_waker(self.index, Waker::clone(cx.waker()));
                Poll::Pending
            });
            match self.listener {
                Listener::Tcp(tcp) => {
                    let listener_fut = tcp.accept();
                    tokio::pin!(shutdown_fut);
                    #[cfg(feature = "uring")]
                    tokio::select! {
                        () = shutdown_fut => AcceptAction::Shutdown,
                        r = listener_fut => AcceptAction::AcceptTcp(r.map(|(stream, addr)| (TcpStream::new(stream), addr))),
                    }
                    #[cfg(not(feature = "uring"))]
                    tokio::select! {
                        () = shutdown_fut => AcceptAction::Shutdown,
                        r = listener_fut => AcceptAction::AcceptTcp(r),

                    }
                }
                #[cfg(feature = "http3")]
                Listener::Udp(udp) => {
                    let listener_fut = accept_udp(udp);
                    tokio::pin!(shutdown_fut);
                    tokio::select! {
                        () = shutdown_fut => AcceptAction::Shutdown,
                        r = listener_fut => AcceptAction::AcceptUdp(r),

                    }
                }
            }
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        {
            #[cfg(feature = "uring")]
            {
                match self.listener {
                    Listener::Tcp(s) => AcceptAction::AcceptTcp(
                        s.accept()
                            .await
                            .map(|(stream, addr)| (TcpStream::new(stream), addr)),
                    ),
                    #[cfg(feature = "http3")]
                    Listener::Udp(udp) => AcceptAction::AcceptUdp(accept_udp(udp).await),
                }
            }
            #[cfg(not(feature = "uring"))]
            {
                match self.listener {
                    Listener::Tcp(s) => AcceptAction::AcceptTcp(s.accept().await),
                    #[cfg(feature = "http3")]
                    Listener::Udp(udp) => AcceptAction::AcceptUdp(accept_udp(udp).await),
                }
            }
        }
    }
}

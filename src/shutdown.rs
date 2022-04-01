//! Graceful shutdown for Kvarn.
//!
//! This is handled through a [`Manager`] and several helper structs.
//! The `Manager` is returned from [`RunConfig::execute`] and can be awaited
//! to pause execution till the server is shut down.
//! It is also used to trigger a shutdown.
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
    connections: AtomicIsize,

    #[cfg(feature = "graceful-shutdown")]
    wakers: WakerList,

    #[cfg(feature = "graceful-shutdown")]
    channel: (WatchSender<()>, WatchReceiver<()>),

    #[cfg(feature = "graceful-shutdown")]
    pub(crate) handover_socket_path: Option<PathBuf>,
}
impl Manager {
    /// Creates a new shutdown manager with the capacity of the list of wakers set to `_capacity`.
    pub fn new(_capacity: usize) -> Self {
        #[cfg(feature = "graceful-shutdown")]
        {
            Self {
                shutdown: AtomicBool::new(false),
                connections: AtomicIsize::new(0),

                wakers: WakerList::new(_capacity),

                channel: watch_channel(()),

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
    pub fn add_listener(&mut self, listener: TcpListener) -> AcceptManager {
        AcceptManager {
            #[cfg(feature = "graceful-shutdown")]
            index: {
                let wakers = self.wakers.get_mut();
                let len = wakers.len();
                wakers.push(None);
                WakerIndex(len)
            },
            listener,
        }
    }
    /// Adds to the count of connections.
    /// When this connection is closed, you must call [`Manager::remove_connection`]
    /// or a logic error will occur and a shutdown will never happen.
    pub fn add_connection(&self) {
        #[cfg(feature = "graceful-shutdown")]
        {
            self.connections.fetch_add(1, Ordering::Release);
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
                error!("Connection count is less than 0. Please report this error.");
            }
            if connections <= 0 {
                debug!("Connection count is 0.");
                let shutdown = self.shutdown.load(Ordering::Acquire);
                if shutdown {
                    info!("Sending shutdown signal");
                    drop(self.channel.0.send(()));
                }
            }
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
    #[cfg(feature = "graceful-shutdown")]
    pub(crate) fn set_waker(&self, index: WakerIndex, waker: Waker) {
        let wakers = unsafe { &mut *self.wakers.get() };
        wakers[index.0] = Some(waker);
    }
    /// # Safety
    ///
    /// See [`Self::set_waker`].
    #[cfg(feature = "graceful-shutdown")]
    pub(crate) fn remove_waker(&self, index: WakerIndex) {
        let wakers = unsafe { &mut *self.wakers.get() };
        wakers[index.0] = None;
    }

    /// Wraps [`Self`] in a [`Arc`] to use across [`tokio::task`]s.
    #[must_use]
    pub fn build(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Makes Kvarn perform a graceful shutdown.
    #[cfg(feature = "graceful-shutdown")]
    pub fn shutdown(&self) {
        info!(
            "Initiating shutdown. Handover path: {:?}",
            self.handover_socket_path
        );
        self.shutdown.store(true, Ordering::Release);

        #[cfg(unix)]
        if let Some(path) = &self.handover_socket_path {
            std::fs::remove_file(&path).ok();
        }

        if self.connections.load(Ordering::Acquire) == 0 {
            drop(self.channel.0.send(()));
        }

        // we stop listening immediately
        self.wakers.notify();
    }
    /// Waits for Kvarn to enter the `shutdown` state.
    /// When the feature `graceful-shutdown` has been disabled, this blocks forever.
    pub async fn wait(&self) {
        #[cfg(feature = "graceful-shutdown")]
        {
            let mut receiver = WatchReceiver::clone(&self.channel.1);
            drop(receiver.changed().await);
            info!("Received shutdown signal");
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        {
            std::future::pending::<()>().await;
        }
    }
}

/// The result of [`AcceptManager::accept`].
/// Can either be a new connection or a shutdown signal.
/// The listener should be dropped right after the shutdown signal is received.
#[derive(Debug)]
#[must_use]
pub enum AcceptAction {
    /// Shutdown signal; immediately drop this struct.
    Shutdown,
    /// Accept a new connection or handle a IO error.
    Accept(io::Result<(TcpStream, SocketAddr)>),
}
/// A wrapper around [`TcpListener`] (and `UdpListener` when HTTP/3 comes around)
/// which waits for a new connection **or** a shutdown signal.
#[derive(Debug)]
#[must_use]
pub struct AcceptManager {
    #[cfg(feature = "graceful-shutdown")]
    index: WakerIndex,
    listener: TcpListener,
}
impl AcceptManager {
    /// Waits for a new connection or a shutdown signal.
    ///
    /// Please increase the count of connections on [`Manager`] when this connection is accepted
    /// and decrease it when the connection dies.
    pub async fn accept(&mut self, _manager: &Manager) -> AcceptAction {
        let action = AcceptFuture {
            #[cfg(feature = "graceful-shutdown")]
            manager: _manager,
            #[cfg(feature = "graceful-shutdown")]
            index: self.index,
            listener: &mut self.listener,
        }
        .await;
        #[cfg(feature = "graceful-shutdown")]
        _manager.remove_waker(self.index);
        action
    }
    /// Returns a reference to the inner listener.
    pub fn get_inner(&self) -> &TcpListener {
        &self.listener
    }
}
struct AcceptFuture<'a> {
    #[cfg(feature = "graceful-shutdown")]
    manager: &'a Manager,
    #[cfg(feature = "graceful-shutdown")]
    index: WakerIndex,
    listener: &'a mut TcpListener,
}
impl<'a> Future for AcceptFuture<'a> {
    type Output = AcceptAction;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();

        #[cfg(feature = "graceful-shutdown")]
        {
            if me.manager.shutdown.load(Ordering::Acquire) {
                Poll::Ready(AcceptAction::Shutdown)
            } else {
                me.manager.set_waker(me.index, Waker::clone(cx.waker()));
                let poll = me.listener.poll_accept(cx);

                poll.map(AcceptAction::Accept)
            }
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        {
            me.listener.poll_accept(cx).map(AcceptAction::Accept)
        }
    }
}

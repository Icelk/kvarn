//! Graceful shutdown for Kvarn.
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
        // See [`Manager::set_waker`] bellow for safety.
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
}
impl Manager {
    pub fn new(_capacity: usize) -> Self {
        #[cfg(feature = "graceful-shutdown")]
        {
            Self {
                shutdown: AtomicBool::new(false),
                connections: AtomicIsize::new(0),

                wakers: WakerList::new(_capacity),

                channel: watch_channel(()),
            }
        }
        #[cfg(not(feature = "graceful-shutdown"))]
        {
            Self {}
        }
    }
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
    pub fn add_connection(&self) {
        #[cfg(feature = "graceful-shutdown")]
        {
            self.connections.fetch_add(1, Ordering::Release);
        }
    }
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
                    self.wakers.notify();
                    drop(self.channel.0.send(()));
                }
            }
        }
    }
    #[cfg(feature = "graceful-shutdown")]
    pub fn get_shutdown(&self, order: Ordering) -> bool {
        self.shutdown.load(order)
    }
    /// # Safety
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
    ///
    /// # Errors
    ///
    /// Passes errors from [`WatchSender::send`].
    #[cfg(feature = "graceful-shutdown")]
    pub async fn shutdown(&self) {
        info!("Initiating shutdown.");
        self.shutdown.store(true, Ordering::Release);

        if self.connections.load(Ordering::Acquire) == 0 {
            self.wakers.notify();

            drop(self.channel.0.send(()))
        }
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
#[derive(Debug)]
#[must_use]
pub enum AcceptAction {
    Shutdown,
    Accept(io::Result<(TcpStream, SocketAddr)>),
}
#[derive(Debug)]
#[must_use]
pub struct AcceptManager {
    #[cfg(feature = "graceful-shutdown")]
    index: WakerIndex,
    listener: TcpListener,
}
impl AcceptManager {
    /// Please increase the count of connections on [`Manager`] when this connection is accepted
    /// and decrease it when the connection dies.
    pub async fn accept(&mut self, _manager: &Manager) -> AcceptAction {
        // self.listener.poll_accept(cx)
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

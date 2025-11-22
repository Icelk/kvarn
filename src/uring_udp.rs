#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

//---------------------
// A bunch of this file is straight up copied from
// https://github.com/quinn-rs/quinn/blob/main/quinn-udp/src/unix.rs
// and https://github.com/quinn-rs/quinn/blob/main/quinn-udp/src/cmsg.rs
// cross platform support is removed, since uring is only available on Linux
//
// Contains some slight modifications to simplify & make compatible.
//
// Mostly copied from the cfg(macos), since
// that code was simpler than the Linux code,
// and sufficient, since we don't have `sendmmesg`.
//
// Most comments are removed, so please see the original file for reference
//
// --------------------

use std::cell::RefCell;
use std::mem;
use std::os::fd::AsRawFd;
use std::ptr;

use futures_util::FutureExt;
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};

use crate::prelude::*;

type RecvFut = Pin<
    Box<
        dyn Future<
            Output = (
                io::Result<(usize, SocketAddr, Option<Vec<u8>>)>,
                Vec<Vec<u8>>,
            ),
        >,
    >,
>;
type SendFut =
    Pin<Box<dyn Future<Output = (io::Result<usize>, Vec<&'static [u8]>, Option<Vec<u8>>)>>>;
struct SendData {
    completed: bool,
    fut: SendFut,
}
type ReusedBuffers = (Vec<&'static [u8]>, Vec<u8>);
struct Inner {
    // store futures until completion, since `tokio-uring` doesn't have a poll interface.
    send_fut: Option<SendData>,
    recv_fut: Option<RecvFut>,

    reused_vecs: Option<ReusedBuffers>,

    socket: tokio_uring::net::UdpSocket,

    last_send_error: Instant,
    max_gso_segments: usize,
    gro_segments: usize,
    may_fragment: bool,

    sendmsg_einval: bool,
}
pub(crate) struct UringUdpSocket {
    inner: RefCell<Inner>,
}
impl Debug for UringUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let me = self.inner.borrow();
        f.debug_struct("UringUdpSocket")
            .field("send_fut", &"[send_fut]".as_clean())
            .field("recv_fut", &"[recv_fut]".as_clean())
            .field("reused_vecs", &"[buffer for reused vecs]".as_clean())
            .field("socket", &"[internal socket]".as_clean())
            .field("last_send_error", &me.last_send_error)
            .field("max_gso_segments", &me.max_gso_segments)
            .field("gro_segments", &me.gro_segments)
            .field("may_fragment", &me.may_fragment)
            .field("sendmsg_einval", &me.sendmsg_einval)
            .finish()
    }
}
impl UringUdpSocket {
    pub(crate) fn new(io: tokio_uring::net::UdpSocket, is_ipv4: bool) -> io::Result<Self> {
        let mut cmsg_platform_space = 0;
        cmsg_platform_space +=
            unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as _) as usize };

        assert!(
            CMSG_LEN
                >= unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) as usize }
                    + cmsg_platform_space
        );
        assert!(
            mem::align_of::<libc::cmsghdr>() <= mem::align_of::<cmsg::Aligned<[u8; 0]>>(),
            "control message buffers will be misaligned"
        );

        if let Err(err) = set_socket_option(&io, libc::IPPROTO_IP, libc::IP_RECVTOS, OPTION_ON) {
            debug!("Ignoring error setting IP_RECVTOS on socket: {err:?}",);
        }

        let mut may_fragment = false;
        {
            // opportunistically try to enable GRO. See gro::gro_segments().
            let _ = set_socket_option(&io, libc::SOL_UDP, libc::UDP_GRO, OPTION_ON);

            // Forbid IPv4 fragmentation. Set even for IPv6 to account for IPv6 mapped IPv4 addresses.
            // Set `may_fragment` to `true` if this option is not supported on the platform.
            may_fragment |= !set_socket_option_supported(
                &io,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )?;

            if is_ipv4 {
                set_socket_option(&io, libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON)?;
            } else {
                // Set `may_fragment` to `true` if this option is not supported on the platform.
                may_fragment |= !set_socket_option_supported(
                    &io,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IP_PMTUDISC_PROBE,
                )?;
            }
        }
        // Options standardized in RFC 3542
        if !is_ipv4 {
            set_socket_option(&io, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, OPTION_ON)?;
            set_socket_option(&io, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, OPTION_ON)?;
            may_fragment |= !set_socket_option_supported(
                &io,
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                OPTION_ON,
            )?;
        }

        let now = Instant::now();

        Ok(Self {
            inner: RefCell::new(Inner {
                send_fut: None,
                recv_fut: None,

                reused_vecs: Some((Vec::with_capacity(1), Vec::new())),

                socket: io,

                last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),

                max_gso_segments: gso::max_gso_segments(),
                gro_segments: gro::gro_segments(),
                may_fragment,
                sendmsg_einval: false,
            }),
        })
    }
}

// `tokio-uring` is a single-threaded runtime, therefore this will never be sent, anyway
unsafe impl Send for UringUdpSocket {}
unsafe impl Sync for UringUdpSocket {}

const CMSG_LEN: usize = 88;
type IpTosTy = libc::c_int;
/// Log at most 1 IO error per minute
const IO_ERROR_LOG_INTERVAL: Duration = std::time::Duration::from_secs(60);
const OPTION_ON: libc::c_int = 1;

#[derive(Debug)]
struct UdpPoller {
    socket: Arc<UringUdpSocket>,
}
impl quinn::UdpPoller for UdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut me = self.socket.inner.borrow_mut();
        let result = if let Some(fut) = &mut me.send_fut {
            let poll = fut.fut.poll_unpin(cx);
            if poll.is_ready() {
                fut.completed = true;
            }
            poll
        } else {
            // assume we're ready to write
            return Poll::Ready(Ok(()));
            // return Poll::Ready(Err(io::Error::new(
            //     io::ErrorKind::InvalidInput,
            //     "try_send hasn't been called!",
            // )));
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready((result, mut msg_vec, ctrl_vec)) => {
                msg_vec.clear();
                let mut ctrl_vec = ctrl_vec.unwrap();
                ctrl_vec.clear();
                me.reused_vecs = Some((msg_vec, ctrl_vec));

                if let Err(e) = &result {
                    if let Some(libc::EIO | libc::EINVAL) = e.raw_os_error() {
                        // Prevent new transmits from being scheduled using GSO. Existing GSO transmits
                        // may already be in the pipeline, so we need to tolerate additional failures.
                        if me.max_gso_segments > 1 {
                            error!(
                                "Your network card doesn't support \
                                certain optimizations (GSO or GRO)."
                            );
                            me.max_gso_segments = 1;
                        }

                        // as if this didn't happen. Parent will retry
                        me.send_fut = None;
                    } else if e.raw_os_error() == Some(libc::EINVAL) {
                        // Some arguments to `sendmsg` are not supported.
                        // Switch to fallback mode.
                        me.sendmsg_einval = true;

                        error!(
                            "Your network card doesn't support \
                            certain optimizations (FEC / sendmsg)."
                        );

                        // as if this didn't happen. Parent will retry
                        me.send_fut = None;
                    } else if e.raw_os_error() != Some(libc::EMSGSIZE) {
                        log_sendmsg_error(&mut me.last_send_error, e);
                    }
                }
                Poll::Ready(result.map(|_| ()))
            }
        }
    }
}
impl quinn::AsyncUdpSocket for UringUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(UdpPoller { socket: self })
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit) -> Result<(), io::Error> {
        let mut me = self.inner.borrow_mut();
        if let Some(fut) = &me.send_fut {
            if fut.completed {
                me.send_fut = None;
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        } else {
            // we copy this from `quinn-udp/cmsg.rs` since we have to extract the `ctrl` later.
            let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
            let mut iov: libc::iovec = unsafe { mem::zeroed() };
            let mut ctrl = cmsg::Aligned([0u8; CMSG_LEN]);

            let addr = socket2::SockAddr::from(transmit.destination);
            prepare_msg(
                transmit,
                &addr,
                &mut hdr,
                &mut iov,
                &mut ctrl,
                me.sendmsg_einval,
            );
            let t = unsafe { transmit_to_static_lifetime(transmit) };

            let (mut msgs, mut ctrl_vec) = me
                .reused_vecs
                .take()
                .expect("multiple sends at the same time");
            msgs.push(t.contents);

            ctrl_vec.extend_from_slice(&ctrl.0[..hdr.msg_controllen]);

            // https://docs.rs/kvarn-tokio-uring/latest/kvarn_tokio_uring/net/struct.UdpSocket.html#method.sendmsg_zc
            let fut: Pin<Box<dyn Future<Output = _>>> = if transmit.contents.len() > 10_000 {
                Box::pin(
                    me.socket
                        .sendmsg_zc(msgs, Some(transmit.destination), Some(ctrl_vec)),
                )
            } else {
                Box::pin(
                    me.socket
                        .sendmsg(msgs, Some(transmit.destination), Some(ctrl_vec)),
                )
            };

            // this is OK, since the lifetime in `fut` comes from `self.socket`. `self` owns both the
            // socket and the future. And `self` will never be dropped (assumed), so the `Drop` impl is
            // unimportant.
            let fut = unsafe { future_to_static_lifetime(fut) };
            me.send_fut = Some(SendData {
                fut,
                completed: false,
            });
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // in brackets so RefCell borrow doesn't leak into recursion
        {
            let mut me = self.inner.borrow_mut();
            // check stored future
            if let Some(fut) = &mut me.recv_fut {
                let poll = fut.poll_unpin(cx);
                if poll.is_ready() {
                    me.recv_fut = None;
                }
                if let Poll::Ready((mut r, mut buf)) = poll {
                    // we created the vecs even though we didn't own them, so let's just forget about
                    // them.
                    if let Ok((read, addr, msg_control)) = &mut r {
                        let msg_control = msg_control.as_deref_mut().unwrap();
                        // mimic `msghdr` we got back, since `tokio-uring` abstracts away that.
                        // `msg_name` doesn't seem to be needed, since we're only interested in `cmsg`.
                        // meta[0] = quinn::udp::RecvMeta {
                        //     addr: *addr,
                        //     len: *read,
                        //     ecn: None,
                        //     stride: *read,
                        //     dst_ip: None,
                        // };
                        let hdr = libc::msghdr {
                            msg_control: msg_control.as_mut_ptr().cast(),
                            msg_controllen: msg_control.len(),
                            msg_iov: buf.as_mut_ptr().cast(),
                            msg_iovlen: buf.len(),
                            msg_flags: 0,
                            msg_name: ptr::null_mut(),
                            msg_namelen: 0,
                        };
                        meta[0] = decode_recv(*addr, &hdr, *read);
                    }
                    buf.into_iter().for_each(mem::forget);
                    return Poll::Ready(r.map(|_| 1));
                }
                return Poll::Pending;
            }
            let fut = me.socket.recvmsg(
                // we know (hopefully) that `quinn` will keep `bufs` alive for the duration of this
                // future (all calls to `poll_recv` until we return `Poll::Ready`), so making a Vec &
                // assuming our ownership is OK. We also `mem::forget` the vecs later, so no
                // double-deallocation is done
                bufs.iter_mut()
                    .map(|buf| unsafe {
                        Vec::from_raw_parts(buf.as_mut_ptr(), buf.len(), buf.len())
                    })
                    .collect(),
                Some(vec![0; CMSG_LEN]),
            );
            // this is OK, since the lifetime in `fut` comes from `self.socket`. `self` owns both the
            // socket and the future. And `self` will never be dropped (assumed), so the `Drop` impl is
            // unimportant.
            let fut = unsafe { future_to_static_lifetime(Box::pin(fut)) };
            me.recv_fut = Some(fut);
            // make sure we actually poll the newly created future
        }
        self.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.borrow().socket.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.borrow().may_fragment
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.borrow().max_gso_segments
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.borrow().gro_segments
    }
}

unsafe fn future_to_static_lifetime<'a, T>(
    fut: Pin<Box<dyn Future<Output = T> + 'a>>,
) -> Pin<Box<dyn Future<Output = T> + 'static>> {
    mem::transmute(fut)
}
unsafe fn transmit_to_static_lifetime(transmit: &Transmit) -> &'static Transmit<'static> {
    mem::transmute(transmit)
}

fn prepare_msg(
    transmit: &Transmit,
    dst_addr: &socket2::SockAddr,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<[u8; CMSG_LEN]>,
    sendmsg_einval: bool,
) {
    iov.iov_base = transmit.contents.as_ptr() as *mut _;
    iov.iov_len = transmit.contents.len();

    // SAFETY: Casting the pointer to a mutable one is legal,
    // as sendmsg is guaranteed to not alter the mutable pointer
    // as per the POSIX spec. See the section on the sys/socket.h
    // header for details. The type is only mutable in the first
    // place because it is reused by recvmsg as well.
    let name = dst_addr.as_ptr() as *mut libc::c_void;
    let namelen = dst_addr.len();
    hdr.msg_name = name.cast();
    hdr.msg_namelen = namelen;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr().cast();
    hdr.msg_controllen = CMSG_LEN as _;
    let mut encoder = unsafe { cmsg::Encoder::new(hdr) };
    let ecn = transmit.ecn.map_or(0, |x| x as libc::c_int);
    if transmit.destination.is_ipv4() {
        if !sendmsg_einval {
            encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
        }
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    // apparently, setting this might cause the UDP to fail to send...

    if let Some(segment_size) = transmit.segment_size {
        gso::set_segment_size(&mut encoder, segment_size as u16);
    }

    if let Some(ip) = &transmit.src_ip {
        match ip {
            IpAddr::V4(v4) => {
                let pktinfo = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                encoder.push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo);
            }
            IpAddr::V6(v6) => {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                };
                encoder.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo);
            }
        }
    }

    encoder.finish();
}

fn decode_recv(addr: SocketAddr, hdr: &libc::msghdr, len: usize) -> RecvMeta {
    let mut ecn_bits = 0;
    let mut dst_ip = None;
    let mut stride = len;

    let cmsg_iter = unsafe { cmsg::Iter::new(hdr) };
    for cmsg in cmsg_iter {
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            // FreeBSD uses IP_RECVTOS here, and we can be liberal because cmsgs are opt-in.
            (libc::IPPROTO_IP, libc::IP_TOS | libc::IP_RECVTOS) => unsafe {
                ecn_bits = cmsg::decode::<u8>(cmsg);
            },
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                ecn_bits = cmsg::decode::<libc::c_int>(cmsg) as u8;
            },
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                let pktinfo = unsafe { cmsg::decode::<libc::in_pktinfo>(cmsg) };
                dst_ip = Some(IpAddr::V4(net::Ipv4Addr::from(
                    pktinfo.ipi_addr.s_addr.to_ne_bytes(),
                )));
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                let pktinfo = unsafe { cmsg::decode::<libc::in6_pktinfo>(cmsg) };
                dst_ip = Some(IpAddr::V6(net::Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
            }
            (libc::SOL_UDP, libc::UDP_GRO) => unsafe {
                stride = cmsg::decode::<libc::c_int>(cmsg) as usize;
            },
            _ => {}
        }
    }

    RecvMeta {
        len,
        stride,
        addr,
        ecn: EcnCodepoint::from_bits(ecn_bits),
        dst_ip,
    }
}

fn set_socket_option(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> Result<(), io::Error> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            ptr::addr_of!(value).cast(),
            mem::size_of_val(&value) as _,
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn set_socket_option_supported(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> Result<bool, io::Error> {
    match set_socket_option(socket, level, name, value) {
        Ok(()) => Ok(true),
        Err(err) if err.raw_os_error() == Some(libc::ENOPROTOOPT) => Ok(false),
        Err(err) => Err(err),
    }
}
fn log_sendmsg_error(
    last_send_error: &mut Instant,
    err: impl core::fmt::Debug,
    // transmit: &Transmit,
) {
    let now = Instant::now();
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        warn!("sendmsg error: {err:?}",);
        // warn!(
        // "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, enc: {:?}, len: {:?}, segment_size: {:?} }}",
        //     err, transmit.destination, transmit.src_ip, transmit.ecn, transmit.contents.len(), transmit.segment_size);
    }
}

mod gso {
    use super::{cmsg, set_socket_option};

    /// Checks whether GSO support is available by setting the `UDP_SEGMENT`
    /// option on a socket
    pub(crate) fn max_gso_segments() -> usize {
        const GSO_SIZE: libc::c_int = 1500;

        let Ok(socket) = std::net::UdpSocket::bind("[::]:0")
            .or_else(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
        else {
            return 1;
        };

        // As defined in linux/udp.h
        // #define UDP_MAX_SEGMENTS        (1 << 6UL)
        match set_socket_option(&socket, libc::SOL_UDP, libc::UDP_SEGMENT, GSO_SIZE) {
            Ok(()) => 64,
            Err(_) => 1,
        }
    }
    pub(crate) fn set_segment_size(encoder: &mut cmsg::Encoder, segment_size: u16) {
        encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size);
    }
}
mod gro {
    use super::{set_socket_option, OPTION_ON};

    pub(crate) fn gro_segments() -> usize {
        let Ok(socket) = std::net::UdpSocket::bind("[::]:0")
            .or_else(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
        else {
            return 1;
        };

        match set_socket_option(&socket, libc::SOL_UDP, libc::UDP_GRO, OPTION_ON) {
            Ok(()) => 64,
            Err(_) => 1,
        }
    }
}

mod cmsg {
    use std::{mem, ptr};

    #[derive(Copy, Clone)]
    #[repr(align(8))] // Conservative bound for align_of<cmsghdr>
    pub(crate) struct Aligned<T>(pub(crate) T);

    /// Helper to encode a series of control messages ("cmsgs") to a buffer for use in `sendmsg`.
    ///
    /// The operation must be "finished" for the msghdr to be usable, either by calling `finish`
    /// explicitly or by dropping the `Encoder`.
    pub(crate) struct Encoder<'a> {
        hdr: &'a mut libc::msghdr,
        cmsg: Option<&'a mut libc::cmsghdr>,
        len: usize,
    }

    impl<'a> Encoder<'a> {
        /// # Safety
        /// - `hdr.msg_control` must be a suitably aligned pointer to `hdr.msg_controllen` bytes that
        ///   can be safely written
        /// - The `Encoder` must be dropped before `hdr` is passed to a system call, and must not be leaked.
        pub(crate) unsafe fn new(hdr: &'a mut libc::msghdr) -> Self {
            Self {
                cmsg: libc::CMSG_FIRSTHDR(hdr).as_mut(),
                hdr,
                len: 0,
            }
        }

        /// Append a control message to the buffer.
        ///
        /// # Panics
        /// - If insufficient buffer space remains.
        /// - If `T` has stricter alignment requirements than `cmsghdr`
        pub(crate) fn push<T>(&mut self, level: libc::c_int, ty: libc::c_int, value: T) {
            assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
            let space = unsafe { libc::CMSG_SPACE(mem::size_of_val(&value) as _) as usize };
            {
                assert!(
                    self.hdr.msg_controllen >= self.len + space,
                    "control message buffer too small. Required: {}, Available: {}",
                    self.len + space,
                    self.hdr.msg_controllen
                );
            }
            let cmsg = self.cmsg.take().expect("no control buffer space remaining");
            cmsg.cmsg_level = level;
            cmsg.cmsg_type = ty;
            cmsg.cmsg_len = unsafe { libc::CMSG_LEN(mem::size_of_val(&value) as _) } as _;
            unsafe {
                ptr::write((libc::CMSG_DATA(cmsg) as *const T).cast_mut(), value);
            }
            self.len += space;
            self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, cmsg).as_mut() };
        }

        /// Finishes appending control messages to the buffer
        pub(crate) fn finish(self) {
            // Delegates to the `Drop` impl
        }
    }

    // Statically guarantees that the encoding operation is "finished" before the control buffer is read
    // by `sendmsg`.
    impl Drop for Encoder<'_> {
        fn drop(&mut self) {
            self.hdr.msg_controllen = self.len as _;
        }
    }

    /// # Safety
    ///
    /// `cmsg` must refer to a cmsg containing a payload of type `T`
    pub(crate) unsafe fn decode<T: Copy>(cmsg: &libc::cmsghdr) -> T {
        assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
        {
            debug_assert_eq!(
                cmsg.cmsg_len,
                libc::CMSG_LEN(mem::size_of::<T>() as _) as usize
            );
        }
        ptr::read(libc::CMSG_DATA(cmsg) as *const T)
    }

    pub(crate) struct Iter<'a> {
        hdr: &'a libc::msghdr,
        cmsg: Option<&'a libc::cmsghdr>,
    }

    impl<'a> Iter<'a> {
        /// # Safety
        ///
        /// `hdr.msg_control` must point to memory outliving `'a` which can be soundly read for the
        /// lifetime of the constructed `Iter` and contains a buffer of cmsgs, i.e. is aligned for
        /// `cmsghdr`, is fully initialized, and has correct internal links.
        pub(crate) unsafe fn new(hdr: &'a libc::msghdr) -> Self {
            Self {
                hdr,
                cmsg: libc::CMSG_FIRSTHDR(hdr).as_ref(),
            }
        }
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = &'a libc::cmsghdr;
        fn next(&mut self) -> Option<&'a libc::cmsghdr> {
            let current = self.cmsg.take()?;
            self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, current).as_ref() };
            Some(current)
        }
    }
}

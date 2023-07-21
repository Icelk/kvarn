#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::cell::RefCell;
use std::mem;
use std::os::fd::AsRawFd;
use std::ptr;

use futures_util::FutureExt;
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};

use crate::prelude::*;

#[allow(clippy::type_complexity)]
pub(crate) struct UringUdpSocket {
    // store futures until completion, since `tokio-uring` doesn't have a poll interface.
    send_fut:
        RefCell<Vec<Pin<Box<dyn Future<Output = (io::Result<usize>, Vec<Bytes>, Option<Bytes>)>>>>>,
    sent: RefCell<usize>,
    recv_fut: RefCell<
        Option<
            Pin<
                Box<
                    dyn Future<
                        Output = (
                            io::Result<(usize, SocketAddr, Option<Vec<u8>>)>,
                            Vec<Vec<u8>>,
                        ),
                    >,
                >,
            >,
        >,
    >,

    socket: tokio_uring::net::UdpSocket,
}
impl Debug for UringUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UringUdpSocket")
            .field("send_fut", &"[send_fut]".as_clean())
            .field("sent", &*self.sent.borrow())
            .field("recv_fut", &"[recv_fut]".as_clean())
            .field("socket", &"[internal socket]".as_clean())
            .finish()
    }
}
impl UringUdpSocket {
    pub(crate) fn new(socket: tokio_uring::net::UdpSocket, is_ipv4: bool) -> io::Result<Self> {
        const OPTION_ON: libc::c_int = 1;
        if let Err(err) = set_socket_option(&socket, libc::IPPROTO_IP, libc::IP_RECVTOS, OPTION_ON)
        {
            info!("Ignoring error setting IP_RECVTOS on socket: {err:?}");
        }

        {
            // opportunistically try to enable GRO. See gro::gro_segments().
            let _ = set_socket_option(&socket, libc::SOL_UDP, libc::UDP_GRO, OPTION_ON);

            // Forbid IPv4 fragmentation. Set even for IPv6 to account for IPv6 mapped IPv4 addresses.
            set_socket_option(
                &socket,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )?;

            if is_ipv4 {
                set_socket_option(&socket, libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON)?;
            } else {
                set_socket_option(
                    &socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IP_PMTUDISC_PROBE,
                )?;
            }
        }
        // Options standardized in RFC 3542
        if !is_ipv4 {
            set_socket_option(
                &socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                OPTION_ON,
            )?;
            set_socket_option(
                &socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                OPTION_ON,
            )?;
            // Linux's IP_PMTUDISC_PROBE allows us to operate under interface MTU rather than the
            // kernel's path MTU guess, but actually disabling fragmentation requires this too. See
            // __ip6_append_data in ip6_output.c.
            set_socket_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, OPTION_ON)?;
        }

        Ok(Self {
            send_fut: RefCell::new(Vec::new()),
            sent: RefCell::new(0),
            recv_fut: RefCell::new(None),
            socket,
        })
    }
}

// `tokio-uring` is a single-threaded runtime, therefore this will never be sent, anyway
unsafe impl Send for UringUdpSocket {}

const CMSG_LEN: usize = 88;
type IpTosTy = libc::c_int;

impl quinn::AsyncUdpSocket for UringUdpSocket {
    fn poll_send(
        &self,
        _state: &quinn::udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn::udp::Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        // in brackets so RefCell borrow doesn't leak into recursion
        {
            // check stored futures
            let mut vec = self.send_fut.borrow_mut();
            let vec = &mut *vec;
            let empty = vec.is_empty();
            // `TODO`: some prettier error handling?
            let mut error = None;
            vec.retain_mut(|fut| {
                let poll = fut.poll_unpin(cx);
                let is_pending = poll.is_pending();
                if let Poll::Ready((Err(err), _, _)) = poll {
                    error = Some(err);
                }
                is_pending
            });
            if !empty {
                if let Some(err) = error {
                    return Poll::Ready(Err(err));
                }
                // became empty, everything is complete
                if vec.is_empty() {
                    return Poll::Ready(Ok(*self.sent.borrow()));
                }
                return Poll::Pending;
            }

            // we copy this from `quinn-udp/cmsg.rs` since we have to extract the `ctrl` later.
            let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
            let mut iov: libc::iovec = unsafe { mem::zeroed() };
            let mut ctrl = cmsg::Aligned([0u8; CMSG_LEN]);
            let mut sent = 0;

            while sent < transmits.len() {
                let addr = socket2::SockAddr::from(transmits[sent].destination);
                prepare_msg(&transmits[sent], &addr, &mut hdr, &mut iov, &mut ctrl);
                let fut = self.socket.sendmsg(
                    vec![transmits[sent].contents.clone()],
                    Some(transmits[sent].destination),
                    Some(Bytes::copy_from_slice(&ctrl.0[..hdr.msg_controllen])),
                );
                // this is OK, since the lifetime in `fut` comes from `self.socket`. `self` owns both the
                // socket and the future. And `self` will never be dropped (assumed), so the `Drop` impl is
                // unimportant.
                let fut = unsafe { future_to_static_lifetime(Box::pin(fut)) };
                vec.push(fut);
                sent += 1;
            }
            *self.sent.borrow_mut() = sent;
        }
        // make sure we actually poll the newly created future
        self.poll_send(_state, cx, transmits)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // in brackets so RefCell borrow doesn't leak into recursion
        {
            // check stored future
            let mut fut = self.recv_fut.borrow_mut();
            let fut_opt = &mut *fut;
            if let Some(fut) = fut_opt {
                let poll = fut.poll_unpin(cx);
                if poll.is_ready() {
                    *fut_opt = None;
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
            let fut = self.socket.recvmsg(
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
            *fut_opt = Some(fut);
            // make sure we actually poll the newly created future
        }
        self.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

unsafe fn future_to_static_lifetime<'a, T>(
    fut: Pin<Box<dyn Future<Output = T> + 'a>>,
) -> Pin<Box<dyn Future<Output = T> + 'static>> {
    mem::transmute(fut)
}

//---------------------
// The rest of this
// code is copied from
// https://github.com/quinn-rs/quinn/blob/main/quinn-udp/src/unix.rs
// and https://github.com/quinn-rs/quinn/blob/main/quinn-udp/src/cmsg.rs
// cross platform support is negligible, since uring is only available on Linux
//
// Contains some slight modifications to simplify & make compatible.
//
// Mostly copied from the cfg(macos), since
// that code was simpler than the Linux code,
// and sufficient, since we don't have `sendmmesg`.
//
// --------------------

fn prepare_msg(
    transmit: &Transmit,
    dst_addr: &socket2::SockAddr,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<[u8; CMSG_LEN]>,
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
        // if !sendmsg_einval {
        // `TODO`: maybe breaks things
        // see https://github.com/quinn-rs/quinn/issues/1609
        encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
        // }
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    // apparently, setting this might cause the UDP to fail to send...

    // if let Some(segment_size) = transmit.segment_size {
    //     gso::set_segment_size(&mut encoder, segment_size as u16);
    // }

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

mod gso {
    use super::{cmsg, set_socket_option};

    /// Checks whether GSO support is available by setting the `UDP_SEGMENT`
    /// option on a socket
    #[allow(dead_code)] // see https://github.com/quinn-rs/quinn/issues/1609
    pub(crate) fn max_gso_segments() -> usize {
        const GSO_SIZE: libc::c_int = 1500;

        let socket = match std::net::UdpSocket::bind("[::]:0")
            .or_else(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
        {
            Ok(socket) => socket,
            Err(_) => return 1,
        };

        // As defined in linux/udp.h
        // #define UDP_MAX_SEGMENTS        (1 << 6UL)
        match set_socket_option(&socket, libc::SOL_UDP, libc::UDP_SEGMENT, GSO_SIZE) {
            Ok(()) => 64,
            Err(_) => 1,
        }
    }
    #[allow(dead_code)]
    pub(crate) fn set_segment_size(encoder: &mut cmsg::Encoder, segment_size: u16) {
        encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size);
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
        pub(crate) fn push<T: Copy + ?Sized>(
            &mut self,
            level: libc::c_int,
            ty: libc::c_int,
            value: T,
        ) {
            assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
            let space = unsafe { libc::CMSG_SPACE(mem::size_of_val(&value) as _) as usize };
            #[allow(clippy::unnecessary_cast)] // hdr.msg_controllen defined as size_t
            {
                assert!(
                    self.hdr.msg_controllen as usize >= self.len + space,
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
                ptr::write(libc::CMSG_DATA(cmsg) as *const T as *mut T, value);
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
    impl<'a> Drop for Encoder<'a> {
        fn drop(&mut self) {
            self.hdr.msg_controllen = self.len as _;
        }
    }

    /// # Safety
    ///
    /// `cmsg` must refer to a cmsg containing a payload of type `T`
    pub(crate) unsafe fn decode<T: Copy>(cmsg: &libc::cmsghdr) -> T {
        assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
        #[allow(clippy::unnecessary_cast)] // cmsg.cmsg_len defined as size_t
        {
            debug_assert_eq!(
                cmsg.cmsg_len as usize,
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

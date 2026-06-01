//! This module defines [`QuicSocket`], which allows selecting between kernel UDP and AF_XDP-backed
//! QUIC socket configurations.
use {
    agave_xdp::{
        ecn_codepoint::EcnCodepoint as XdpEcnCodepoint,
        transmitter::{BytesTxPacket, XdpSender},
    },
    bytes::Bytes,
    crossbeam_channel::TrySendError,
    nix::ifaddrs::getifaddrs,
    quinn::{
        AsyncUdpSocket, Runtime, TokioRuntime, UdpSender,
        udp::{EcnCodepoint as QuinnEcnCodepoint, RecvMeta, Transmit},
    },
    std::{
        fmt::{self, Debug},
        io::{self, IoSliceMut},
        net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    },
};

/// [`QuicSocket`] is an enum for selecting between a kernel UDP socket and an AF_XDP-backed
/// socket for QUIC communication.
#[derive(Debug)]
pub enum QuicSocket {
    /// A QUIC socket that uses AF_XDP for sending and a kernel UDP socket for receiving.
    Xdp(QuicXdpSocketParts),
    /// A QUIC socket that uses kernel UDP socket for both sending and receiving.
    Kernel(std::net::UdpSocket),
}

impl From<std::net::UdpSocket> for QuicSocket {
    fn from(socket: std::net::UdpSocket) -> Self {
        QuicSocket::Kernel(socket)
    }
}

impl QuicSocket {
    pub fn with_xdp(
        socket: std::net::UdpSocket,
        fallback_src_ip: Ipv4Addr,
        xdp_sender: XdpSender,
    ) -> Self {
        Self::Xdp(QuicXdpSocketParts {
            socket,
            fallback_src_ip,
            xdp_sender,
        })
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            QuicSocket::Xdp(parts) => parts.socket.local_addr(),
            QuicSocket::Kernel(socket) => socket.local_addr(),
        }
    }
}

/// [`QuicXdpSocketParts`] wraps the resources required to construct an AF_XDP-backed QUIC socket.
///
/// It carries both an [`XdpSender`] and a [`std::net::UdpSocket`], rather than constructing an
/// [`QuicXdpTxSocket`] directly, because the underlying sockets can only be created when a Tokio
/// runtime is present. `fallback_src_ip` is used when the local address of `socket` is a
/// wildcard address.
pub struct QuicXdpSocketParts {
    pub socket: std::net::UdpSocket,
    pub fallback_src_ip: Ipv4Addr,
    pub xdp_sender: XdpSender,
}

impl Debug for QuicXdpSocketParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicXdpSocketParts")
            .field("socket", &self.socket)
            .finish()
    }
}

/// [`QuicXdpTxSocket`] uses AF_XDP for egress traffic and `UdpSocket` for ingress traffic.
///
/// For egress traffic, it employs an underlying `QuicXdpSender` for non-local destinations. For
/// destinations owned by the local host (routed via `lo`, including loopback and local interface
/// IPs), it falls back to a kernel `UdpSocket`.
pub(crate) struct QuicXdpTxSocket {
    udp_socket: Box<dyn AsyncUdpSocket>,
    xdp_sender: Arc<QuicXdpSender>,
    local_ips: Arc<[Ipv4Addr]>,
}

impl QuicXdpTxSocket {
    pub(crate) fn new(
        socket: std::net::UdpSocket,
        fallback_src_ip: Ipv4Addr,
        xdp_sender: XdpSender,
    ) -> io::Result<Self> {
        let src_addr = socket.local_addr()?;
        let SocketAddr::V4(src_addr) = src_addr else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Only IPv4 addresses are supported",
            ));
        };
        // if local address is wildcard, override it with fallback_src_ip.
        let src_addr = if src_addr.ip().is_unspecified() {
            SocketAddrV4::new(fallback_src_ip, src_addr.port())
        } else {
            src_addr
        };

        // Collect local interface IPs once at construction time. We do not refresh them if
        // interface addresses change later. This is a low-risk tradeoff because local-destination
        // egress is expected to be rare: only RPC sendTransaction traffic or local testing.
        let local_ips = collect_local_ipv4_ips()?;

        Ok(Self {
            udp_socket: TokioRuntime.wrap_udp_socket(socket)?,
            xdp_sender: Arc::new(QuicXdpSender::new(xdp_sender, src_addr)),
            local_ips: local_ips.into(),
        })
    }
}

impl fmt::Debug for QuicXdpTxSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicXdpTxSocket")
            .field("local_addr", &self.udp_socket.local_addr())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for QuicXdpTxSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        // Quinn constructs one sender per task. The kernel sender (used for local destinations) is
        // derived from the wrapped UDP socket, while the AF_XDP sender is shared so its round-robin
        // index and underlying channels stay consistent across all senders.
        Box::pin(QuicXdpUdpSender {
            kernel_sender: self.udp_socket.create_sender(),
            xdp_sender: self.xdp_sender.clone(),
            local_ips: self.local_ips.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.udp_socket.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp_socket.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.udp_socket.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// [`QuicXdpUdpSender`] is the [`UdpSender`] half of [`QuicXdpTxSocket`].
///
/// For non-local destinations it uses AF_XDP via a shared [`QuicXdpSender`]; for destinations owned
/// by the local host (loopback or local interface IPs) it falls back to the kernel UDP sender.
struct QuicXdpUdpSender {
    kernel_sender: Pin<Box<dyn UdpSender>>,
    xdp_sender: Arc<QuicXdpSender>,
    local_ips: Arc<[Ipv4Addr]>,
}

impl Debug for QuicXdpUdpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicXdpUdpSender").finish_non_exhaustive()
    }
}

impl UdpSender for QuicXdpUdpSender {
    /// Attempts to send the given [`Transmit`].
    ///
    /// For non-local destinations uses AF_XDP, otherwise the kernel UDP sender.
    ///
    /// When the AF_XDP channel is full this returns [`Poll::Pending`] after scheduling an immediate
    /// re-poll, mirroring the previous `try_send`/`WouldBlock` retry loop. Returning an error
    /// instead would be treated by Quinn as a fatal connection error. This therefore assumes the
    /// AF_XDP channel is rarely (ideally never) full.
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let destination = transmit.destination;
        if is_local_destination(&this.local_ips, destination) {
            return this.kernel_sender.as_mut().poll_send(transmit, cx);
        }
        if destination.is_ipv6() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 destination addresses are not supported for AF_XDP sends",
            )));
        }
        let src_ip = match transmit.src_ip {
            Some(IpAddr::V4(ip)) => Some(ip),
            Some(IpAddr::V6(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 source addresses are not supported",
                )));
            }
            None => None,
        };

        debug_assert!(
            transmit.segment_size.is_none(),
            "GSO segmentation is disabled for AF_XDP sends, but segment_size is {:?}",
            transmit.segment_size
        );

        let payload = Bytes::copy_from_slice(transmit.contents);
        match this
            .xdp_sender
            .try_send(src_ip, destination, transmit.ecn, payload)
        {
            Ok(()) => Poll::Ready(Ok(())),
            Err(TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(TrySendError::Disconnected(_)) => {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
    }

    fn max_transmit_segments(&self) -> usize {
        // no GSO batches, so each transmit describes exactly one datagram
        1
    }
}

/// Returns true when `dst` is owned by the local host (loopback or a local interface IP) and should
/// therefore be routed through the kernel UDP sender rather than AF_XDP.
fn is_local_destination(local_ips: &[Ipv4Addr], dst: SocketAddr) -> bool {
    dst.ip().is_loopback() || matches!(dst.ip(), IpAddr::V4(ip) if local_ips.contains(&ip))
}

/// [`QuicXdpSender`] wraps [`XdpSender`] and provides round-robin sender selection.
///
/// This wrapper provides a simple round-robin sender index for each packet sent. It is required
/// because `AsyncUdpSocket::try_send` does not provide a way to specify the sender index. If the
/// `XdpSender` has only one sender, the index is always 0.
struct QuicXdpSender {
    xdp_sender: XdpSender,
    src_addr: SocketAddrV4,
    next_sender_index: AtomicUsize,
}

impl QuicXdpSender {
    fn new(xdp_sender: XdpSender, src_addr: SocketAddrV4) -> Self {
        let next_sender_index = AtomicUsize::new(0);
        Self {
            xdp_sender,
            src_addr,
            next_sender_index,
        }
    }

    fn try_send(
        &self,
        src_ip: Option<Ipv4Addr>,
        destination: SocketAddr,
        ecn: Option<QuinnEcnCodepoint>,
        payload: Bytes,
    ) -> Result<(), TrySendError<BytesTxPacket>> {
        let sender_idx = self.next_sender_index.fetch_add(1, Ordering::Relaxed);

        let src_ip = src_ip.unwrap_or(*self.src_addr.ip());
        // Respect Quinn's per-packet source IP, used for wildcard-bound sockets, while
        // keeping the port from `self.src_addr`.
        let src_addr = SocketAddrV4::new(src_ip, self.src_addr.port());
        let ecn = ecn.map(quinn_ecn_to_xdp);

        let mut packet = BytesTxPacket::new(src_addr, destination, ecn, payload);
        packet.set_allow_mtu_overflow(true);
        self.xdp_sender.try_send(sender_idx, packet)
    }
}

/// Collects IPv4 addresses assigned to local network interfaces.
fn collect_local_ipv4_ips() -> io::Result<Vec<Ipv4Addr>> {
    let mut ips = Vec::new();
    for ifa in getifaddrs().map_err(io::Error::other)? {
        let Some(addr) = ifa.address else { continue };
        if let Some(v4) = addr.as_sockaddr_in() {
            let ip = v4.ip();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    Ok(ips)
}

#[inline]
const fn quinn_ecn_to_xdp(ecn: QuinnEcnCodepoint) -> XdpEcnCodepoint {
    match ecn {
        QuinnEcnCodepoint::Ect0 => XdpEcnCodepoint::Ect0,
        QuinnEcnCodepoint::Ect1 => XdpEcnCodepoint::Ect1,
        QuinnEcnCodepoint::Ce => XdpEcnCodepoint::Ce,
    }
}

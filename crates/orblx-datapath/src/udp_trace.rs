//! A QUIC UDP socket that writes the time of each send and receive to the packet trace (W25-41).
//!
//! The node uses this socket only when the packet trace is on (see `pkt_trace`).
//! Each call goes to the normal socket of the runtime. The trace holds the byte count
//! and the datagram count only.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::pkt_trace::trace_udp;

#[derive(Debug)]
pub(crate) struct TracedUdp(pub(crate) Arc<dyn AsyncUdpSocket>);

impl AsyncUdpSocket for TracedUdp {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.0).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let result = self.0.try_send(transmit);
        if result.is_ok() {
            let size = transmit.contents.len();
            let count = transmit
                .segment_size
                .filter(|segment| *segment > 0)
                .map_or(1, |segment| size.div_ceil(segment));
            trace_udp("udp_send", size, count);
        }
        result
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let result = self.0.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = &result {
            for one in meta.iter().take(*count) {
                let datagrams = if one.stride > 0 {
                    one.len.div_ceil(one.stride)
                } else {
                    1
                };
                trace_udp("udp_recv", one.len, datagrams);
            }
        }
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.0.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.0.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.0.may_fragment()
    }
}

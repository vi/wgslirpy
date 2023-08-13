//! Helper module to create `smoltcp` devices that use single slot for received packet and a tokio::mpsc channel to transmit packets.

#![allow(missing_docs)]

use bytes::BytesMut;
use smoltcp::phy::{Device,RxToken,TxToken, Checksum};
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::TEAR_OF_ALLOCATION_SIZE;

pub struct ChannelizedDevice {
    pub tx : Sender<BytesMut>,

    /// Put a packet to be handled by smoltcp here. Channelized device would take it from here.
    pub rx: Option<BytesMut>,

    /// Moderately big allocation to snip away pieces from it when we need to transmit packets into [`tx`].
    /// 
    /// When remaining capacity falls below some threshold, the buffer gets allocated again.
    /// 
    /// Idea is to reduce number of allocations at the expense of the size of allocated block.
    pub tear_off_buffer: BytesMut,

    pub mtu : usize,
}

impl ChannelizedDevice {
    /// Create the device using given queue for transmitting packets, retuning given `mtu` as MTU.
    /// 
    /// Checksumming is enabled, menium is "IP".
    pub fn new(tx: Sender<BytesMut>, mtu: usize) -> Self {
        ChannelizedDevice {
            tx,
            rx: None,
            tear_off_buffer: BytesMut::with_capacity(TEAR_OF_ALLOCATION_SIZE),
            mtu,
        }
    }
}

pub struct RxTokenWrap(pub BytesMut);

impl<'b> Device for ChannelizedDevice {
    type RxToken<'a>
     = RxTokenWrap where Self: 'a;

    type TxToken<'a>
     = &'a mut ChannelizedDevice where Self: 'a;

    fn receive(&mut self, _timestamp: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(x) = self.rx.take() {
            //warn!("Received len={} {:?}", x.len(), x);
            Some((RxTokenWrap(x), self))
        } else {
            //warn!("Nothing to receive yet");
            None
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        if self.tx.capacity() == 0 {
            warn!("No capacity to transmit");
            return None
        }
        Some(self)
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.icmpv6 = Checksum::Tx;
        caps
    }
}

impl RxToken for RxTokenWrap {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R {
        f(&mut self.0[..])
    }
}
impl<'a> TxToken for &'a mut ChannelizedDevice {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R {
        self.tear_off_buffer.resize(len, 0);
        let ret = f(&mut self.tear_off_buffer[..]);
        let chunk = self.tear_off_buffer.split();
        //warn!("Transmitting {chunk:?}");
        if self.tx.try_send(chunk).is_err() {
            warn!("Failed to transmit into a ChannelizedDevice");
        }
        if self.tear_off_buffer.capacity() < 2048 {
            self.tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION_SIZE);
        }
        ret
    }
}

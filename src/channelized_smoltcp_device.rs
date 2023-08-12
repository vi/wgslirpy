

use bytes::BytesMut;
use smoltcp::phy::{Device,RxToken,TxToken, Checksum};
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::TEAR_OF_ALLOCATION;

pub struct ChannelizedDevice {
    pub tx : Sender<BytesMut>,
    pub rx: Option<BytesMut>,
    pub tear_off_buffer: BytesMut,
    pub mtu : usize,
}

impl ChannelizedDevice {
    pub fn new(tx: Sender<BytesMut>, mtu: usize) -> Self {
        ChannelizedDevice {
            tx,
            rx: None,
            tear_off_buffer: BytesMut::with_capacity(TEAR_OF_ALLOCATION),
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
            self.tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION);
        }
        ret
    }
}

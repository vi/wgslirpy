use std::cell::RefCell;

use bytes::BytesMut;
use smoltcp::phy::{Device,RxToken,TxToken};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::warn;

pub struct ChannelizedDevice {
    pub tx : Sender<BytesMut>,
    pub rx: Option<BytesMut>,
}

pub struct RxTokenWrap(pub BytesMut);

impl<'b> Device for ChannelizedDevice {
    type RxToken<'a>
     = RxTokenWrap where Self: 'a;

    type TxToken<'a>
     = &'a ChannelizedDevice where Self: 'a;

    fn receive(&mut self, _timestamp: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(x) = self.rx.take() {
            //warn!("Received something");
            Some((RxTokenWrap(x), &*self))
        } else {
            //warn!("Nothing to receive from here yet");
            None
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        if self.tx.capacity() == self.tx.max_capacity() {
            warn!("No capacity to transmit");
            return None
        }
        Some(&*self)
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = 1024;
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
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
impl<'a> TxToken for &'a ChannelizedDevice {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R {
        let mut b = BytesMut::zeroed(len);
        let ret = f(&mut b[..]);
        if self.tx.try_send(b).is_err() {
            warn!("Failed to transmit into a ChannelizedDevice");
        }
        ret
    }
}

use std::time::Duration;

use bytes::BytesMut;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{trace, warn};

use crate::channelized_smoltcp_device::ChannelizedDevice;

const DANGLE_TIME_SECONDS: u64 = 10;

pub async fn pingable(
    tx_to_wg: Sender<BytesMut>,
    mut rx_from_wg: Receiver<BytesMut>,
    external_addr: IpAddress,
    _client_addr: IpAddress,
    mtu: usize,
) -> anyhow::Result<()> {
  
    let mut dev = ChannelizedDevice::new(tx_to_wg, mtu);

    let ic = Config::new(HardwareAddress::Ip);
    let mut ii = Interface::new(ic, &mut dev, Instant::now());
    ii.update_ip_addrs(|aa| {
        let _ = aa.push(IpCidr::new(external_addr, 0));
    });

    #[derive(Debug)]
    enum SelectOutcome {
        TimePassed,
        PacketFromWg(Option<BytesMut>),
        /// No timeout was active, we need to calculate a new one
        Noop,
        /// Global deadline reached
        Deadline,
    }

    macro_rules! loop_with_deadline {
        ($loop_label:lifetime, $deadline:ident, $sockets:ident, $code:block) => {
            let mut sleeper: Option<tokio::time::Sleep> = None;
            $loop_label: loop {
                $code

                let ret: SelectOutcome = if let Some(tmo) = sleeper.take() {
                    //trace!("Selecting with a sleeper");
                    tokio::select! {
                        biased;
                        x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                        _ = tmo => SelectOutcome::TimePassed,
                        _ = &mut $deadline => SelectOutcome::Deadline,
                    }
                } else {
                    //trace!("Selecting without a sleeper");
                    tokio::select! {
                        biased;
                        x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                        _ = std::future::ready(()) => SelectOutcome::Noop,
                        _ = &mut $deadline => SelectOutcome::Deadline,
                    }
                };
                match ret {
                    SelectOutcome::TimePassed => {
                        trace!("Time passed");
                        ii.poll(Instant::now(), &mut dev, &mut $sockets);
                    }
                    SelectOutcome::PacketFromWg(Some(from_wg)) => {
                        trace!("Packet from wg of len {}", from_wg.len());
                        dev.rx = Some(from_wg);
                        ii.poll(Instant::now(), &mut dev, &mut $sockets);
                    }
                    SelectOutcome::Noop => {
                        let t = ii.poll_delay(Instant::now(), &mut $sockets);
                        let t = t.map(|x|Duration::from_micros(x.total_micros())).unwrap_or(Duration::from_secs(60));
                        trace!("Setup timeout: {t:?}");
                        sleeper = Some(tokio::time::sleep(t));
                        continue;
                    }
                    SelectOutcome::PacketFromWg(None) => {
                        warn!("Everything is shutting down, exiting");
                        return Ok(());
                    }
                    SelectOutcome::Deadline => {
                        break $loop_label;
                    }
                }
                sleeper = None;
            }
        }
    }


    let deadline = tokio::time::sleep(Duration::from_secs(DANGLE_TIME_SECONDS));
    tokio::pin!(deadline);
    let mut sockets = SocketSet::new([]);
    loop_with_deadline!('main_loop, deadline, sockets, {

    });

    Ok::<_, anyhow::Error>(())
}

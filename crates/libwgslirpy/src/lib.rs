const TEAR_OF_ALLOCATION_SIZE : usize = 65536;

pub mod wg;
pub mod router;
pub mod channelized_smoltcp_device;

use tracing::warn;

pub use wg::parsebase64_32;

pub async fn run(wireguard_options: wg::Opts, router_options: router::Opts, transmit_queue_capacity: usize) -> anyhow::Result<()> { 
    let (tx_towg, rx_towg) = tokio::sync::mpsc::channel(transmit_queue_capacity);
    let (tx_fromwg, rx_fromwg) = tokio::sync::mpsc::channel(4);
    let _jh = ArmedJoinHandle(tokio::spawn(async move {
        match wireguard_options.start(tx_fromwg, rx_towg).await {
            Ok(()) => warn!("Exited from Wireguard loop"),
            Err(e) => warn!("Exiten from Wireguard loop: {e}"),
        }
    }));

    router::run(rx_fromwg, tx_towg, router_options).await?;

    Ok(())
}
struct ArmedJoinHandle(tokio::task::JoinHandle<()>);

impl Drop for ArmedJoinHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

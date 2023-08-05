use std::net::SocketAddr;

use argh::FromArgs;

/// Expose internet access without root using Wireguard
#[derive(FromArgs)]
pub struct Opts {
    /// main private key of this Wireguard node
    #[argh(option,short='k')]
    pub private_key : String,

    /// peer's public key
    #[argh(option,short='K')]
    pub peer_key : String,

    /// address of the peer's UDP socket, where to send keepalives
    #[argh(option,short='p')]
    pub peer_endpoint : Option<SocketAddr>,

    /// keepalive interval, in seconds
    #[argh(option,short='a')]
    pub keepalive_interval : Option<u16>,

    /// where to bind our own UDP socket
    #[argh(option, short='b')]
    pub bind_ip_port: SocketAddr,
}

pub mod wg;
pub mod router;
mod channelized_smoltcp_device;

use wg::{Opts as WgOpts, parsebase64_32};

#[tokio::main(flavor="current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts : Opts = argh::from_env();
    let wgopts = WgOpts {
        private_key: parsebase64_32(&opts.private_key)?.into(),
        peer_key: parsebase64_32(&opts.peer_key)?.into(),
        peer_endpoint: opts.peer_endpoint,
        keepalive_interval: opts.keepalive_interval,
        bind_ip_port: opts.bind_ip_port,
    };
    
    let (wg_tx, wg_rx) = wgopts.start().await?;

    router::run(wg_rx, wg_tx).await?;

    Ok(())
}

#![allow(unused_braces)]
use std::net::{SocketAddr, IpAddr};

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

    /// use UDP socket address as a simple A/AAAA-only DNS server
    #[argh(option, short='D')]
    pub dns: Option<SocketAddr>,

    /// reply to ICMP pings on this address
    #[argh(option, short='P')]
    pub pingable : Option<IpAddr>,
}


const TEAR_OF_ALLOCATION : usize = 65536;
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

    let r_opts = router::Opts {
        dns_addr: opts.dns,
        pingable: opts.pingable,
    };

    router::run(wg_rx, wg_tx, r_opts).await?;

    Ok(())
}

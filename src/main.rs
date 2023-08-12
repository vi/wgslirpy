#![allow(unused_braces)]
use std::{net::{SocketAddr, IpAddr}, path::PathBuf};

use argh::FromArgs;

/// Expose internet access without root using Wireguard
#[derive(FromArgs)]
pub struct Opts {
    /// main private key of this Wireguard node, base64-encoded
    #[argh(option,short='k')]
    pub private_key : Option<String>,

    /// main private key of this Wireguard node (content of a specified file), base64-encoded
    #[argh(option,short='f')]
    pub private_key_file: Option<PathBuf>,

    /// peer's public key
    #[argh(option,short='K')]
    pub peer_key : String,

    /// address of the peer's UDP socket, where to send keepalives
    #[argh(option,short='p')]
    pub peer_endpoint : Option<SocketAddr>,

    /// keepalive interval, in seconds
    #[argh(option,short='a')]
    pub keepalive_interval : Option<u16>,

    /// where to bind our own UDP socket for Wireguard connection
    #[argh(option, short='b')]
    pub bind_ip_port: SocketAddr,

    /// use this UDP socket address as a simple A/AAAA-only DNS server within Wireguard network
    #[argh(option, short='D')]
    pub dns: Option<SocketAddr>,

    /// reply to ICMP pings on this single address within Wireguard network
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
    #[cfg(feature="tracing-subscriber")]
    tracing_subscriber::fmt::init();
    let opts : Opts = argh::from_env();

    let privkey = match (opts.private_key, opts.private_key_file) {
        (None, Some(path)) => {
            std::fs::read_to_string(path)?
        }
        (Some(s), None) => s,
        _ => anyhow::bail!("Set exactly one of --private-key or --private-key-file")
    };

    let wgopts = WgOpts {
        private_key: parsebase64_32(&privkey)?.into(),
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

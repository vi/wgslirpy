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

    /// maximum transfer unit to use for TCP. Default is 1420.
    #[argh(option, default="1420")]
    pub mtu: usize,
    
    /// in-application socket TCP buffer size. Note that operating system socket buffer also applies.
    #[argh(option, default="65535")]
    pub tcp_buffer_size: usize,

    /// nubmer of outgoing (to wireguard) packets to hold in a queue
    #[argh(option, default="256")]
    pub transmit_queue_capacity: usize,

    /// forward this host UDP port into Wireguard network.
    /// You need to specify triplet of socket addresses: host, source (optional) and dest.
    /// Host address is address to bind operating system socket to.
    /// source and dest addreses are used within Wireguard network.
    /// Example: -u 0.0.0.0:1234,10.0.2.1:1234,10.0.2.15:1234
    #[argh(option, short='u', from_str_fn(parse_sa_pair))]
    pub incoming_udp: Vec<PortForward>,

    /// forward this host TCP port into Wireguard network.
    /// You need to specify triplet of socket addresses: host, source (optional) and dest.
    /// Host address is address to bind operating system socket to.
    /// source and dest addreses are used within Wireguard network.
    /// If source port is 0, roundrobin is used.
    /// Example: -t 0.0.0.0:1234,,10.0.2.15:1234
    #[argh(option, short='t', from_str_fn(parse_sa_pair))]
    pub incoming_tcp: Vec<PortForward>,
}

fn parse_sa_pair(x: &str) -> Result<PortForward, String> {
    let chunks = x.split(',').collect::<Vec<_>>();
    if chunks.len() != 3 {
        return Err("Argument to -u or -t must be comma-separated triplet of socket addresses".to_owned())
    }
    let Ok(sa1) : Result<SocketAddr,_> = chunks[0].parse() else {
        return Err(format!("Failed to parse {} as a socket address", chunks[0]))
    };
    let sa2 = if chunks[1].is_empty() {
        None
    } else {
        let Ok(sa2) : Result<SocketAddr,_> = chunks[1].parse() else {
            return Err(format!("Failed to parse {} as a socket address", chunks[1]))
        };
        Some(sa2)
    };
    let Ok(sa3) : Result<SocketAddr,_> = chunks[2].parse() else {
        return Err(format!("Failed to parse {} as a socket address", chunks[2]))
    };
    Ok(PortForward{host: sa1, src: sa2, dst:sa3})
}

use libwgslirpy::{parsebase64_32, router::{PortForward, self}, wg};

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

    let wgopts = wg::Opts {
        private_key: parsebase64_32(&privkey)?.into(),
        peer_key: parsebase64_32(&opts.peer_key)?.into(),
        peer_endpoint: opts.peer_endpoint,
        keepalive_interval: opts.keepalive_interval,
        bind_ip_port: opts.bind_ip_port,
    };

    let r_opts = router::Opts {
        dns_addr: opts.dns,
        pingable: opts.pingable,
        mtu: opts.mtu,
        tcp_buffer_size: opts.tcp_buffer_size,
        incoming_udp: opts.incoming_udp,
        incoming_tcp: opts.incoming_tcp,
    };

    libwgslirpy::run(wgopts, r_opts, opts.transmit_queue_capacity).await?;

    Ok(())
}

use std::net::{IpAddr, SocketAddr};

use bytes::BytesMut;
use hashbrown::HashMap;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
use smoltcp::wire::{IpEndpoint, IpVersion, TcpPacket};

use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NatKey {
    Tcp {
        client_side: IpEndpoint,
        external_side: IpEndpoint,
    },
    Udp {
        client_side: IpEndpoint,
    },
    Pingable {
        client_side: IpAddress,
        external_side: IpAddress,
    },
}

impl std::fmt::Display for NatKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatKey::Tcp {
                client_side,
                external_side,
            } => write!(f, "TCP {client_side} -> {external_side}"),
            NatKey::Udp { client_side } => write!(f, "UDP {client_side} -> *"),
            NatKey::Pingable {
                client_side,
                external_side,
            } => write!(f, "Pinger {client_side} -> {external_side}"),
        }
    }
}

pub struct Opts {
    pub dns_addr: Option<SocketAddr>,
    pub pingable: Option<IpAddr>,
    pub mtu: usize,
    pub tcp_buffer_size: usize,
    pub incoming_udp: Vec<PortForward>,
    pub incoming_tcp: Vec<PortForward>,
}

pub struct PortForward {
    pub host: SocketAddr,
    pub src: Option<SocketAddr>,
    pub dst: SocketAddr,
}

mod serve_dns;
mod serve_pingable;
mod serve_tcp;
mod serve_udp;

pub async fn run(
    mut rx_from_wg: Receiver<BytesMut>,
    tx_to_wg: Sender<BytesMut>,
    opts: Opts,
) -> anyhow::Result<()> {
    let mtu = opts.mtu;
    let tcp_buffer_size = opts.tcp_buffer_size;
    let mut table = HashMap::<NatKey, Sender<BytesMut>>::new();

    for PortForward { host, src, dst } in opts.incoming_udp {
        let tx_to_wg2 = tx_to_wg.clone();
        let (tx_persocket_fromwg, rx_persocket_fromwg) = channel(4);
        tokio::spawn(async move {
            if let Some(src) = src {
                info!(
                    "Permanent UDP forward from host {}: would send {} -> {}",
                    host, src, dst
                );
            } else {
                info!(
                    "Permanent UDP forward from host {}: would send * -> {}",
                    host, dst
                );
            }
            let ret = serve_udp::serve_udp(
                tx_to_wg2,
                rx_persocket_fromwg,
                dst.into(),
                Some(host),
                src.map(IpEndpoint::from),
            )
            .await;
            if let Err(e) = ret {
                warn!("Permanent UDP forward exited with error: {e}");
            }
        });
        let k = NatKey::Udp {
            client_side: dst.into(),
        };
        table.insert(k, tx_persocket_fromwg);
    }

    let (tx_closes, mut rx_closes): (Sender<NatKey>, Receiver<NatKey>) = channel(4);
    let (tx_opens, mut rx_opens): (
        Sender<(NatKey, Sender<BytesMut>)>,
        Receiver<(NatKey, Sender<BytesMut>)>,
    ) = channel(4);

    for PortForward { host, src, dst } in opts.incoming_tcp {
        let tx_to_wg2 = tx_to_wg.clone();
        let tcps = tokio::net::TcpListener::bind(host).await?;
        let tx_opens2 = tx_opens.clone();
        let tx_closes2 = tx_closes.clone();
        tokio::spawn(async move {
            if let Some(src) = src {
                info!(
                    "Permanent TCP forward from host {}: would connect {} -> {}",
                    host, src, dst
                );
            } else {
                info!(
                    "Permanent TCP forward from host {}: would connect * -> {}",
                    host, dst
                );
            }
            let mut counter : u16 = 1024;
            while let Ok((tcp, from)) = tcps.accept().await {
                let (tx_persocket_fromwg, rx_persocket_fromwg) = channel(4);

                let tx_to_wg3 = tx_to_wg2.clone();
                let tx_closes3 = tx_closes2.clone();
                let mut src = src.unwrap_or(from);
                if src.port() == 0 {
                    src.set_port(counter);
                    counter = counter.wrapping_add(1);
                    if counter == 0 { counter = 1024 }
                }
                let k = NatKey::Tcp {
                    client_side: dst.into(),
                    external_side: src.into(),
                };
                tokio::spawn(async move {
                    info!("Incoming TCP connection from {} to {} on host side. Connecting from {} to {} within Wireguard.", from, host, src, dst);

                    let ret = serve_tcp::serve_tcp(
                        tx_to_wg3,
                        rx_persocket_fromwg,
                        IpEndpoint::from(src),
                        serve_tcp::ServeTcpMode::Incoming { tcp, client_addr: IpEndpoint::from(dst) },
                        mtu,
                        tcp_buffer_size,
                    )
                    .await;

                    if let Err(e) = ret {
                        warn!("TCP back connection from {from} exited with error: {e}");
                    }

                    info!("  Finished serving {from}");
                    let _ = tx_closes3.send(k).await;
                });
                if tx_opens2.send((k, tx_persocket_fromwg)).await.is_err() {
                    break;
                }
            }
            warn!("Finished listening TCP {host}");
        });
    }

    enum SelectOutcome {
        PacketFromWg(Option<BytesMut>),
        ConnectionFinish(Option<NatKey>),
        IncomingTcpStart(Option<(NatKey, Sender<BytesMut>)>),
    }

    loop {
        let ret = tokio::select! {
            x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
            x = rx_closes.recv() => SelectOutcome::ConnectionFinish(x),
            x = rx_opens.recv() => SelectOutcome::IncomingTcpStart(x),
        };

        let buf = match ret {
            SelectOutcome::PacketFromWg(Some(x)) => x,
            SelectOutcome::ConnectionFinish(None)
            | SelectOutcome::PacketFromWg(None)
            | SelectOutcome::IncomingTcpStart(None) => break,
            SelectOutcome::ConnectionFinish(Some(k)) => {
                table.remove(&k);
                continue;
            }
            SelectOutcome::IncomingTcpStart(Some((k, sender))) => {
                if table.insert(k, sender).is_some() {
                    warn!("Incoming TCP connection's entry evicted another connection");
                }
                continue;
            }
        };

        let (src_addr, dst_addr, nextproto, payload): (IpAddress, IpAddress, IpProtocol, &[u8]) =
            match IpVersion::of_packet(&buf[..]) {
                Err(_e) => {
                    warn!("Malformed packet");
                    continue;
                }
                Ok(IpVersion::Ipv4) => {
                    let Ok(p) = Ipv4Packet::new_checked(&buf[..]) else {
                    error!("Dwarf packet");
                    continue;
                };
                    (
                        p.src_addr().into(),
                        p.dst_addr().into(),
                        p.next_header(),
                        p.payload(),
                    )
                }
                Ok(IpVersion::Ipv6) => {
                    let Ok(p) = Ipv6Packet::new_checked(&buf[..]) else {
                    error!("Dwarf packet");
                    continue;
                };
                    (
                        p.src_addr().into(),
                        p.dst_addr().into(),
                        p.next_header(),
                        p.payload(),
                    )
                }
            };

        let key = match nextproto {
            IpProtocol::Udp => match UdpPacket::new_checked(payload) {
                Ok(u) => {
                    if let Some(ref dns) = opts.dns_addr {
                        if dns.port() == u.dst_port() && dns.ip() == IpAddr::from(dst_addr) {
                            let tx_to_wg2 = tx_to_wg.clone();
                            tokio::spawn(async move {
                                if let Ok(reply) = serve_dns::dns(buf).await {
                                    debug!("Sending DNS reply");
                                    let _ = tx_to_wg2.send(reply).await;
                                } else {
                                    warn!("Failed to calculate DNS reply");
                                }
                            });

                            continue;
                        }
                    }
                    NatKey::Udp {
                        client_side: IpEndpoint {
                            addr: src_addr,
                            port: u.src_port(),
                        },
                    }
                }
                Err(_e) => {
                    warn!("Failed to parse UDP packet");
                    continue;
                }
            },
            IpProtocol::Tcp => match TcpPacket::new_checked(payload) {
                Ok(u) => NatKey::Tcp {
                    client_side: IpEndpoint {
                        addr: src_addr,
                        port: u.src_port(),
                    },
                    external_side: IpEndpoint {
                        addr: dst_addr,
                        port: u.dst_port(),
                    },
                },
                Err(_e) => {
                    warn!("Failed to parse TCP packet");
                    continue;
                }
            },
            IpProtocol::Icmp => {
                debug!("Icmp");
                if Some(IpAddr::from(dst_addr)) == opts.pingable {
                    NatKey::Pingable {
                        client_side: src_addr,
                        external_side: dst_addr,
                    }
                } else {
                    continue;
                }
            }
            IpProtocol::Icmpv6 => {
                debug!("Icmpv6");
                if Some(IpAddr::from(dst_addr)) == opts.pingable {
                    NatKey::Pingable {
                        client_side: src_addr,
                        external_side: dst_addr,
                    }
                } else {
                    continue;
                }
            }
            x => {
                warn!("Uknown protocol in IPv4 packet: {}", x);
                continue;
            }
        };
        let per_socket_sender: &mut Sender<BytesMut> = match table.entry(key) {
            hashbrown::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            hashbrown::hash_map::Entry::Vacant(entry) => {
                info!("Serving {}", key);
                let tx_to_wg2 = tx_to_wg.clone();
                let (tx_persocket_fromwg, rx_persocket_fromwg) = channel(4);
                let k = entry.key().clone();
                let tx_closes = tx_closes.clone();
                tokio::spawn(async move {
                    let ret = match k {
                        NatKey::Tcp {
                            external_side,
                            client_side: _,
                        } => {
                            serve_tcp::serve_tcp(
                                tx_to_wg2,
                                rx_persocket_fromwg,
                                external_side,
                                serve_tcp::ServeTcpMode::Outgoing,
                                mtu,
                                tcp_buffer_size,
                            )
                            .await
                        }
                        NatKey::Udp { client_side } => {
                            serve_udp::serve_udp(
                                tx_to_wg2,
                                rx_persocket_fromwg,
                                client_side,
                                None,
                                None,
                            )
                            .await
                        }
                        NatKey::Pingable {
                            client_side,
                            external_side,
                        } => {
                            serve_pingable::pingable(
                                tx_to_wg2,
                                rx_persocket_fromwg,
                                external_side,
                                client_side,
                                mtu,
                            )
                            .await
                        }
                    };
                    if let Err(e) = ret {
                        error!("  finished serving {k}: {e}");
                    } else {
                        info!("  Finished serving {k}");
                    }
                    let _ = tx_closes.send(k).await;
                });

                entry.insert(tx_persocket_fromwg)
            }
        };

        if per_socket_sender.send(buf).await.is_err() {
            error!("Failed to send to a per-socket interface");
        }
    }
    warn!("Routed stopped: no more incoming packets possible");
    Ok(())
}

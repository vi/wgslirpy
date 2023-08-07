

use bytes::{BytesMut};
use hashbrown::HashMap;


use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
use smoltcp::wire::{IpEndpoint, IpVersion, PrettyPrinter, TcpPacket};

use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, error, info, warn};



#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct NatKey {
    proto: Proto,
    client_side: IpEndpoint,
    external_side: IpEndpoint,
}

enum IpPacket<T: AsRef<[u8]>> {
    Ipv4(Ipv4Packet<T>),
    Ipv6(Ipv6Packet<T>),
}

mod serve_udp;

pub async fn tcp_outgoing_connection(
    _tx_to_wg: Sender<BytesMut>,
    _rx_from_wg: Receiver<BytesMut>,
    _external_addr: IpEndpoint,
    _client_addr: IpEndpoint,
) -> anyhow::Result<()> {
    todo!()
}

pub async fn run(
    mut rx_from_wg: Receiver<BytesMut>,
    tx_to_wg: Sender<BytesMut>,
) -> anyhow::Result<()> {
    let mut table = HashMap::<NatKey, Sender<BytesMut>>::new();

    while let Some(buf) = rx_from_wg.recv().await {
        let key = match IpVersion::of_packet(&buf[..]) {
            Err(_e) => {
                warn!("Malformed packet");
                continue;
            }
            Ok(IpVersion::Ipv4) => {
                println!("{}", PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &buf));
                let Ok(p) = Ipv4Packet::new_checked(&buf[..]) else {
                    error!("Dwarf packet"); continue;
                };
                let (src_addr, dst_addr) = (p.src_addr(), p.dst_addr());
                match p.next_header() {
                    IpProtocol::Udp => match UdpPacket::new_checked(p.payload()) {
                        Ok(u) => NatKey {
                            proto: Proto::Udp,
                            client_side: IpEndpoint {
                                addr: IpAddress::Ipv4(src_addr),
                                port: u.src_port(),
                            },
                            external_side: IpEndpoint {
                                addr: IpAddress::Ipv4(dst_addr),
                                port: u.dst_port(),
                            },
                        },
                        Err(_e) => {
                            warn!("Failed to parse UDP IPv4 packet");
                            continue;
                        }
                    },
                    IpProtocol::Tcp => match TcpPacket::new_checked(p.payload()) {
                        Ok(u) => NatKey {
                            proto: Proto::Udp,
                            client_side: IpEndpoint {
                                addr: IpAddress::Ipv4(src_addr),
                                port: u.src_port(),
                            },
                            external_side: IpEndpoint {
                                addr: IpAddress::Ipv4(dst_addr),
                                port: u.dst_port(),
                            },
                        },
                        Err(_e) => {
                            warn!("Failed to parse TCP IPv4 packet");
                            continue;
                        }
                    },
                    x => {
                        warn!("Uknown protocol in IPv4 packet: {}", x);
                        continue;
                    }
                }
            }
            Ok(IpVersion::Ipv6) => {
                warn!("IPv6 not impl");
                continue;
            }
        };
        let per_socket_sender : &mut Sender<BytesMut> = match table.entry(key) {
            hashbrown::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            hashbrown::hash_map::Entry::Vacant(entry) => {
                info!("New NAT entry for {:?}", key);
                let tx_to_wg2 = tx_to_wg.clone();
                let (tx_persocket_fromwg, rx_persocket_fromwg) = channel(4);
                let k = entry.key().clone();
                tokio::spawn(async move {
                    let ret = match k.proto {
                        Proto::Tcp => tcp_outgoing_connection(
                            tx_to_wg2,
                            rx_persocket_fromwg,
                            k.external_side,
                            k.client_side,
                        ).await,
                        Proto::Udp => serve_udp::udp_outgoing_connection(
                            tx_to_wg2,
                            rx_persocket_fromwg,
                            k.external_side,
                            k.client_side,
                        ).await,
                    };
                    if let Err(e) = ret {
                        error!("Finished serving {k:?}: {e}");
                    } else {
                        debug!("Finished serving {k:?}");
                    }
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

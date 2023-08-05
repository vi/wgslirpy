use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{Bytes, BytesMut};
use hashbrown::HashMap;
use smoltcp::iface::{Interface, Config, SocketSet};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use smoltcp::wire::{IpEndpoint, IpVersion, Ipv4Packet, PrettyPrinter, TcpPacket, UdpPacket};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, error, warn, info};

use crate::channelized_smoltcp_device::ChannelizedDevice;

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

pub fn udp_outgoing_connection(
    client: Sender<BytesMut>,
    endpoint: IpEndpoint,
) -> Sender<BytesMut> {
    let (mut tx, mut rx) = channel(1);
    let (mut tx2, mut rx2) = channel(1);


    let ua = match endpoint.addr {
        IpAddress::Ipv4(_) => SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),0),
        IpAddress::Ipv6(_) => SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),0),
    };
    
    let jh = tokio::spawn(async move {
        let udp = UdpSocket::bind(ua).await?;
        let mut dev = ChannelizedDevice {
            tx: client,
            rx: rx2,
        };

        let ic = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut ii = Interface::new(ic, &mut dev, smoltcp::time::Instant::now());
        ii.update_ip_addrs(|aa| {
            aa.push(IpCidr::new(endpoint.addr, 32));
        });

        let udp_rx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
            vec![0; 65535],
        );
        let udp_tx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
            vec![0; 65535],
        );
        let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);

        let stdendpoint : SocketAddr = match endpoint.addr {
            IpAddress::Ipv4(x) => SocketAddr::V4(SocketAddrV4::new(x.into(), endpoint.port)),
            IpAddress::Ipv6(x) => SocketAddr::V6(SocketAddrV6::new(x.into(), endpoint.port, 0, 0)),
        };

        let mut sockets = SocketSet::new(vec![]);
        let h = sockets.add(udp_socket);


        ii.poll(Instant::now(), &mut dev, &mut sockets);

        {
            let s = sockets.get_mut::<udp::Socket>(h);
            s.bind(endpoint)?;
        }

        while let Some(incoming) = rx.recv().await {
            warn!("QQQ");
            tx2.send(incoming).await?;

            loop {
                ii.poll(Instant::now(), &mut dev, &mut sockets);
                let s = sockets.get_mut::<udp::Socket>(h);
                match s.recv() {
                    Ok((b, _)) => {
                        warn!("EEE");
                        if udp.send_to(b, stdendpoint).await.is_err() {
                            warn!("Failed to sendto to real UDP socket");
                        }
                    }
                    Err(_) => {
                        warn!("WWW");
                        break;
                    }
                }
            }
        }
        warn!("RRR");

        Ok::<_, anyhow::Error>(())
    });
    tokio::spawn(async move {
        if let Err(e) = jh.await {
            error!("Failed from router task: {}", e);
        }
    });

    tx
}

pub fn tcp_outgoing_connection(
    client: Sender<BytesMut>,
    endpoint: IpEndpoint,
) -> Sender<BytesMut> {
    todo!()
}


pub async fn run(mut rx: Receiver<BytesMut>, tx: Sender<BytesMut>) -> anyhow::Result<()> {
    let mut table = HashMap::<NatKey, Sender<BytesMut>>::new();

    while let Some(buf) = rx.recv().await {
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
                    smoltcp::wire::IpProtocol::Udp => {
                        match UdpPacket::new_checked(p.payload()) {
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
                        }
                    }
                    smoltcp::wire::IpProtocol::Tcp => {
                        match TcpPacket::new_checked(p.payload()) {
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
                        }
                    }
                    x => {
                        warn!("Uknown protocol in IPv4 packet: {}", x);
                        continue;
                    }
                }
            }
            Ok(IpVersion::Ipv6) => {
                warn!("IPv6 not impl");
                continue
            }
        };
        let per_socket_sender = table.entry(key).or_insert_with_key(|k| {
            info!("New NAT entry for {:?}", key);
            match k.proto {
                Proto::Tcp => tcp_outgoing_connection(tx.clone(), k.external_side),
                Proto::Udp => udp_outgoing_connection(tx.clone(), k.external_side),
            }
        });
        if per_socket_sender.send(buf).await.is_err() {
            error!("Failed to send to a per-socket interface");
        }
    }
    warn!("Routed stopped: no more incoming packets possible");
    Ok(())
}

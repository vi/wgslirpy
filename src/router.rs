use std::cell::RefCell;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{Bytes, BytesMut};
use hashbrown::HashMap;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Checksum};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, IpProtocol, IpRepr, Ipv4Packet, UdpPacket, Ipv6Packet};
use smoltcp::wire::{IpEndpoint, IpVersion, PrettyPrinter, TcpPacket};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, error, info, warn};

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

enum IpPacket<T: AsRef<[u8]>> {
    Ipv4(Ipv4Packet<T>),
    Ipv6(Ipv6Packet<T>),
}

pub fn udp_outgoing_connection(
    client: Sender<BytesMut>,
    external: IpEndpoint,
    client_addr: IpEndpoint,
) -> Sender<BytesMut> {
    let (tx, mut rx) = channel(4);

    let ua = match external.addr {
        IpAddress::Ipv4(_) => {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        }
        IpAddress::Ipv6(_) => {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        }
    };

    let _jh = tokio::spawn(async move {
        let pkt_slot: Option<BytesMut> = None;
        let udp = UdpSocket::bind(ua).await?;
        let mut dev = ChannelizedDevice {
            tx: client,
            rx: pkt_slot,
        };

        let ic = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut ii = Interface::new(ic, &mut dev, smoltcp::time::Instant::now());
        ii.update_ip_addrs(|aa| {
            let _ = aa.push(IpCidr::new(external.addr, 0));
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
        let mut external_udp_buffer = [0; 2048];

        let stdendpoint: SocketAddr = match external.addr {
            IpAddress::Ipv4(x) => SocketAddr::V4(SocketAddrV4::new(x.into(), external.port)),
            IpAddress::Ipv6(x) => SocketAddr::V6(SocketAddrV6::new(x.into(), external.port, 0, 0)),
        };

        let mut sockets = SocketSet::new(vec![]);
        let h = sockets.add(udp_socket);

        ii.poll(Instant::now(), &mut dev, &mut sockets);

        {
            let s = sockets.get_mut::<udp::Socket>(h);
            s.bind(external)?;
        }

        let mut checksummer = ChecksumCapabilities::ignored();
        checksummer.udp = Checksum::Tx;
        checksummer.ipv4 = Checksum::Tx;
        checksummer.tcp = Checksum::Tx;

        'recv_from_wg: loop {
            tokio::select! {
                from_wg = rx.recv() => {
                    let Some(from_wg) = from_wg else {
                        break 'recv_from_wg
                    };
                    dev.rx = Some(from_wg);

                    loop {
                        ii.poll(Instant::now(), &mut dev, &mut sockets);
                        let s = sockets.get_mut::<udp::Socket>(h);
                        match s.recv() {
                            Ok((b, _)) => {
                                if udp.send_to(b, stdendpoint).await.is_err() {
                                    warn!("Failed to sendto to real UDP socket");
                                }
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
                from_ext = udp.recv_from(&mut external_udp_buffer) => {
                    if let Ok((n, from)) = from_ext {
                        warn!("WEW");
                        // ignore the smoltcp socket, use smoltcp wire directly to be able to fake sender address
                        let data = &external_udp_buffer[..n];

                        let mut buf = BytesMut::zeroed(4096);
                        let r = IpRepr::new(external.addr, client_addr.addr, IpProtocol::Udp, data.len() + 8, 64);
            
                        let len = r.buffer_len();
            
                        let r2 = smoltcp::wire::UdpRepr {
                            src_port: external.port,
                            dst_port: client_addr.port,
                        };

                        match r {
                            IpRepr::Ipv4(r) => {
                                let mut ippkt4 = Ipv4Packet::new_unchecked(buf);
                                r.emit(&mut ippkt4, &checksummer);
                                let mut udppkt = UdpPacket::new_unchecked(ippkt4.payload_mut());
                                r2.emit(
                                    &mut udppkt,
                                    &external.addr,
                                    &client_addr.addr,
                                    data.len(),
                                    |p| {
                                        p.copy_from_slice(data)
                                    },
                                    &checksummer,
                                );
                                buf = ippkt4.into_inner();
                            }
                            IpRepr::Ipv6(r) => {
                                let mut ippkt6 = Ipv6Packet::new_unchecked(buf);
                                r.emit(&mut ippkt6);
                                let mut udppkt = UdpPacket::new_unchecked(ippkt6.payload_mut());
                                r2.emit(
                                    &mut udppkt,
                                    &external.addr,
                                    &client_addr.addr,
                                    data.len(),
                                    |p| {
                                        p.copy_from_slice(data)
                                    },
                                    &checksummer,
                                );
                                buf = ippkt6.into_inner();
                            }
                        }
                        buf.resize(len, 0);
                        dev.tx.send(buf).await?;

                    } else {
                        warn!("Failure receiving from socket");
                    }
                }
            }
        }

        Ok::<_, anyhow::Error>(())
    });
    /*tokio::spawn(async move {
        if let Err(e) = jh.await {
            error!("Failed from router task: {}", e);
        }
    });*/

    tx
}

pub fn tcp_outgoing_connection(client: Sender<BytesMut>, endpoint: IpEndpoint) -> Sender<BytesMut> {
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
        let per_socket_sender = table.entry(key).or_insert_with_key(|k| {
            info!("New NAT entry for {:?}", key);
            match k.proto {
                Proto::Tcp => tcp_outgoing_connection(tx.clone(), k.external_side),
                Proto::Udp => udp_outgoing_connection(tx.clone(), k.external_side, k.client_side),
            }
        });
        if per_socket_sender.send(buf).await.is_err() {
            error!("Failed to send to a per-socket interface");
        }
    }
    warn!("Routed stopped: no more incoming packets possible");
    Ok(())
}

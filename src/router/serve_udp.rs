use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::BytesMut;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Checksum, ChecksumCapabilities},
    socket::udp,
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpRepr, Ipv4Packet,
        Ipv6Packet, UdpPacket,
    },
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender},
};
use tracing::warn;

use crate::channelized_smoltcp_device::ChannelizedDevice;

pub async fn udp_outgoing_connection(
    tx_to_wg: Sender<BytesMut>,
    mut rx_from_wg: Receiver<BytesMut>,
    external_addr: IpEndpoint,
    client_addr: IpEndpoint,
) -> anyhow::Result<()> {
    let ua = match external_addr.addr {
        IpAddress::Ipv4(_) => {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        }
        IpAddress::Ipv6(_) => {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        }
    };

    let pkt_slot: Option<BytesMut> = None;
    let udp = UdpSocket::bind(ua).await?;
    let mut dev = ChannelizedDevice {
        tx: tx_to_wg,
        rx: pkt_slot,
    };

    let ic = Config::new(HardwareAddress::Ip);
    let mut ii = Interface::new(ic, &mut dev, Instant::now());
    ii.update_ip_addrs(|aa| {
        let _ = aa.push(IpCidr::new(external_addr.addr, 0));
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

    let stdendpoint: SocketAddr = match external_addr.addr {
        IpAddress::Ipv4(x) => SocketAddr::V4(SocketAddrV4::new(x.into(), external_addr.port)),
        IpAddress::Ipv6(x) => {
            SocketAddr::V6(SocketAddrV6::new(x.into(), external_addr.port, 0, 0))
        }
    };

    let mut sockets = SocketSet::new(vec![]);
    let h = sockets.add(udp_socket);

    ii.poll(Instant::now(), &mut dev, &mut sockets);

    {
        let s = sockets.get_mut::<udp::Socket>(h);
        s.bind(external_addr)?;
    }

    let mut checksummer = ChecksumCapabilities::ignored();
    checksummer.udp = Checksum::Tx;
    checksummer.ipv4 = Checksum::Tx;
    checksummer.tcp = Checksum::Tx;

    'recv_from_wg: loop {
        tokio::select! {
            from_wg = rx_from_wg.recv() => {
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
                if let Ok((n, _from)) = from_ext {
                    warn!("WEW");
                    // ignore the smoltcp socket, use smoltcp wire directly to be able to fake sender address
                    let data = &external_udp_buffer[..n];

                    let mut buf = BytesMut::zeroed(4096);
                    let r = IpRepr::new(external_addr.addr, client_addr.addr, IpProtocol::Udp, data.len() + 8, 64);

                    let len = r.buffer_len();

                    let r2 = smoltcp::wire::UdpRepr {
                        src_port: external_addr.port,
                        dst_port: client_addr.port,
                    };

                    match r {
                        IpRepr::Ipv4(r) => {
                            let mut ippkt4 = Ipv4Packet::new_unchecked(buf);
                            r.emit(&mut ippkt4, &checksummer);
                            let mut udppkt = UdpPacket::new_unchecked(ippkt4.payload_mut());
                            r2.emit(
                                &mut udppkt,
                                &external_addr.addr,
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
                                &external_addr.addr,
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
}

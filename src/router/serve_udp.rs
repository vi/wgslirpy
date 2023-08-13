use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use smoltcp::{
    phy::{Checksum, ChecksumCapabilities},
    wire::{
        IpAddress, IpEndpoint, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet,
        UdpPacket, IpVersion,
    },
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender},
};
use tracing::{warn, debug};

use crate::TEAR_OF_ALLOCATION;

pub const UDP_CONNECTION_EXPIRATION_SECONDS : u64 = 92;

pub async fn udp_outgoing_connection(
    tx_to_wg: Sender<BytesMut>,
    mut rx_from_wg: Receiver<BytesMut>,
    client_addr: IpEndpoint,
    bind_addr: Option<SocketAddr>,
    force_srcaddr: Option<IpEndpoint>,
) -> anyhow::Result<()> {
    let ua = bind_addr.unwrap_or_else(||match client_addr.addr {
        IpAddress::Ipv4(_) => {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        }
        IpAddress::Ipv6(_) => {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        }
    });
    let upstream_socket = UdpSocket::bind(ua).await?;

    let mut external_udp_buffer = [0; 2048];

    /*
    let stdendpoint: SocketAddr = match external_addr.addr {
        IpAddress::Ipv4(x) => SocketAddr::V4(SocketAddrV4::new(x.into(), external_addr.port)),
        IpAddress::Ipv6(x) => {
            SocketAddr::V6(SocketAddrV6::new(x.into(), external_addr.port, 0, 0))
        }
    };
    */

    let mut checksummer = ChecksumCapabilities::ignored();
    checksummer.udp = Checksum::Tx;
    checksummer.ipv4 = Checksum::Tx;
    checksummer.tcp = Checksum::Tx;

    let mut tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION);

    enum SelectOutcome {
        FromWg(Option<BytesMut>),
        FromUdp(std::io::Result<(usize, SocketAddr)>),
        Timeout,
    }



    'recv_from_wg: loop {
        let deadline = tokio::time::sleep(Duration::from_secs(UDP_CONNECTION_EXPIRATION_SECONDS));

        let ret = tokio::select! {
            x = rx_from_wg.recv() => SelectOutcome::FromWg(x),
            x = upstream_socket.recv_from(&mut external_udp_buffer) => SelectOutcome::FromUdp(x),
            _ = deadline, if bind_addr.is_none() => SelectOutcome::Timeout,
        };
        match ret {
            SelectOutcome::FromWg(from_wg) => {
                let Some(from_wg) = from_wg else {
                    break 'recv_from_wg
                };

                let buf = &from_wg[..];
                let (src_addr, dst_addr, payload): (
                    IpAddress,
                    IpAddress,
                    &[u8],
                ) = match IpVersion::of_packet(&buf[..]) {
                    Err(_e) => {
                        continue;
                    }
                    Ok(IpVersion::Ipv4) => {
                        let Ok(p) = Ipv4Packet::new_checked(&buf[..]) else { continue; };
                        (
                            p.src_addr().into(),
                            p.dst_addr().into(),
                            p.payload(),
                        )
                    }
                    Ok(IpVersion::Ipv6) => {
                        let Ok(p) = Ipv6Packet::new_checked(&buf[..]) else { continue; };
                        (
                            p.src_addr().into(),
                            p.dst_addr().into(),
                            p.payload(),
                        )
                    }
                };

                let (payload, to) = match UdpPacket::new_checked(payload) {
                    Ok(u) => {
                        if ! u.verify_checksum(&src_addr, &dst_addr) {
                            warn!("Failed UDP checksum");
                            continue;
                        }
                        (u.payload(), IpEndpoint::new(dst_addr, u.dst_port()))
                    },
                    Err(_e) => {
                        continue
                    }
                };

                let to = SocketAddr::new(to.addr.into(), to.port);

                upstream_socket.send_to(payload, to).await?;
            }
            SelectOutcome::FromUdp(Err(e)) => {
                warn!("Failure receiving from upstream UDP socket: {e}");
            }
            SelectOutcome::FromUdp(Ok((n, from))) => {
                let external_addr = force_srcaddr.unwrap_or_else(||IpEndpoint::new(from.ip().into(), from.port()));

                let data = &external_udp_buffer[..n];

                tear_off_buffer.resize(4096 - 64, 0);
                let buf = &mut tear_off_buffer[..];
                let r = IpRepr::new(
                    external_addr.addr,
                    client_addr.addr,
                    IpProtocol::Udp,
                    data.len() + 8,
                    64,
                );

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
                            |p| p.copy_from_slice(data),
                            &checksummer,
                        );
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
                            |p| p.copy_from_slice(data),
                            &checksummer,
                        );
                    }
                }
                tear_off_buffer.resize(len, 0);
                let buf = tear_off_buffer.split();
                tx_to_wg.send(buf).await?;
                if tear_off_buffer.capacity() < 2048 {
                    tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION);
                }
            }
            SelectOutcome::Timeout => {
                debug!("Timed out a UDP connection");
                break;
            }
        }
    }

    Ok::<_, anyhow::Error>(())
}

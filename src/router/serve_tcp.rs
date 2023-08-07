use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::BytesMut;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Checksum, ChecksumCapabilities},
    
    socket::tcp,
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpRepr, Ipv4Packet,
        Ipv6Packet,
    },
};
use tokio::{
    net::{TcpStream},
    sync::mpsc::{Receiver, Sender}, io::AsyncWriteExt,
};
use tracing::warn;

use crate::channelized_smoltcp_device::ChannelizedDevice;

pub async fn tcp_outgoing_connection(
    tx_to_wg: Sender<BytesMut>,
    mut rx_from_wg: Receiver<BytesMut>,
    external_addr: IpEndpoint,
    client_addr: IpEndpoint,
) -> anyhow::Result<()> {
    let target_addr = match external_addr.addr {
        IpAddress::Ipv4(x) => {
            SocketAddr::new(std::net::IpAddr::V4(x.into()), external_addr.port)
        }
        IpAddress::Ipv6(x) => {
            SocketAddr::new(std::net::IpAddr::V6(x.into()), external_addr.port)
        }
    };

    let mut tcp = TcpStream::connect(target_addr).await?;

    let pkt_slot: Option<BytesMut> = None;
    let mut dev = ChannelizedDevice {
        tx: tx_to_wg,
        rx: pkt_slot,
    };

    let ic = Config::new(HardwareAddress::Ip);
    let mut ii = Interface::new(ic, &mut dev, Instant::now());
    ii.update_ip_addrs(|aa| {
        let _ = aa.push(IpCidr::new(external_addr.addr, 0));
    });

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut external_tcp_buffer = [0; 2048];

    let mut sockets = SocketSet::new(vec![]);
    let h = sockets.add(tcp_socket);

    ii.poll(Instant::now(), &mut dev, &mut sockets);

    {
        let s = sockets.get_mut::<tcp::Socket>(h);
        s.listen(external_addr)?;
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
                    let s = sockets.get_mut::<tcp::Socket>(h);
                    
                    if s.can_recv() {
                        if let Ok(b) = s.peek(65536) {
                            match tcp.write(b).await {
                                Ok(n) => {
                                    s.recv(|_|(n,()))?;
                                    continue;
                                }
                                Err(e) => {
                                    warn!("Failed to write to real TCP socket: {e}");
                                }
                            }
                        }
                    }

                    break;
                }
            }
            /*from_ext = udp.recv_from(&mut external_tcp_buffer) => {
                if let Ok((n, _from)) = from_ext {
                    warn!("WEW");
                    // ignore the smoltcp socket, use smoltcp wire directly to be able to fake sender address
                    let data = &external_tcp_buffer[..n];

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
            }*/
        }
    }

    Ok::<_, anyhow::Error>(())
}

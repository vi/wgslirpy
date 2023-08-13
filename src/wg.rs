use std::{net::SocketAddr, time::Duration};

use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::BytesMut;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use boringtun::noise::TunnResult;
use tracing::{error, warn};

use crate::TEAR_OF_ALLOCATION;

pub struct Opts {
    pub private_key: StaticSecret,
    pub peer_key: PublicKey,
    pub peer_endpoint: Option<SocketAddr>,
    pub keepalive_interval: Option<u16>,
    pub bind_ip_port: SocketAddr,
    pub transmit_queue_capacity: usize,
}

impl Opts {
    pub async fn start(&self) -> anyhow::Result<(Sender<BytesMut>, Receiver<BytesMut>)> {
        let mut wg = boringtun::noise::Tunn::new(
            self.private_key.clone(),
            self.peer_key,
            None,
            self.keepalive_interval,
            0,
            None,
        ).map_err(|e|anyhow::anyhow!(e))?;

        let (tx_towg, mut rx_towg) = channel(self.transmit_queue_capacity);
        let (tx_fromwg, rx_fromwg) = channel(4);

        let udp = tokio::net::UdpSocket::bind(self.bind_ip_port).await?;

        let mut current_peer_addr = self.peer_endpoint;
        let static_peer_addr = self.peer_endpoint;

        tokio::spawn(async move {
            let mut each_second = tokio::time::interval(Duration::from_secs(1));
            let mut udp_recv_buf = [0; 4096-32];
            let mut wg_scratch_buf = [0; 4096];
            let mut tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION);
            loop {
                let mut last_seen_recv_address = None;
                let mut tr : Option<TunnResult> = tokio::select! {
                    _instant = each_second.tick() => {
                        Some(wg.update_timers(&mut wg_scratch_buf))
                    }
                    ret = udp.recv_from(&mut udp_recv_buf[..]) => {
                        let ret = ret?;
                        let buf : &[u8] = &udp_recv_buf[0..(ret.0)];
                        let from : SocketAddr = ret.1;

                        last_seen_recv_address = Some(from);

                        Some(wg.decapsulate(None, buf, &mut wg_scratch_buf))
                    }
                    ret = rx_towg.recv() => {
                        let Some(incoming) : Option<BytesMut> = ret else {
                            warn!("Finished possible packets into wg");
                            break
                        };
                        Some(wg.encapsulate(&incoming[..], &mut wg_scratch_buf))
                    }
                };
                loop {
                    if let Some(tr_inner) = tr {
                        if ! matches! (tr_inner, TunnResult::Err(..)) {
                            if last_seen_recv_address.is_some() && current_peer_addr.is_none() && static_peer_addr.is_none() {
                                current_peer_addr = last_seen_recv_address;
                            }
                        }
                        match tr_inner {
                            TunnResult::Done => (),
                            TunnResult::Err(e) => {
                                error!("boringturn error: {:?}", e);
                            }
                            TunnResult::WriteToNetwork(b) => {
                                if let Some(cpa) = current_peer_addr {
                                    match udp.send_to(b, cpa).await {
                                        Ok(_n) => (),
                                        Err(e) => error!("Failed to send wiregaurd packet to peer: {e}"),
                                    }
                                    tr = Some(wg.decapsulate(None, b"", &mut wg_scratch_buf));
                                    continue;
                                } else {
                                    error!("Trying to send a wireguard packet without configured peer address");
                                }
                            }
                            TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                                tear_off_buffer.extend_from_slice(b);
                                tx_fromwg.send(tear_off_buffer.split()).await?;
                                if tear_off_buffer.capacity() < 2048 {
                                    tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION);
                                }
                            }
                        }
                    }
                    break;
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });

        Ok((tx_towg, rx_fromwg))
    }
}

pub fn parsebase64_32(x: &str) -> anyhow::Result<[u8; 32]> {
    let b = base64::engine::general_purpose::STANDARD.decode(x)?;
    Ok(b[..].try_into()?)
}

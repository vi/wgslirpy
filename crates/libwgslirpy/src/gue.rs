//! Module that has similar interface to `crate::wg`, but just sends and received UDP packets directly, without encryption.
//! Intended to be used as GUE / FOU.

use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{warn, error};

use crate::TEAR_OF_ALLOCATION_SIZE;

/// Options for being a GUE peer
pub struct Opts {
    /// Static socket address of GUE peer to sendto.
    ///
    /// If it is missing, it will reply to last seen incoming socket address.
    pub peer_endpoint: Option<SocketAddr>,

    /// How often to send empty UDP datagrams to the peer.
    pub keepalive_interval: Option<u16>,

    /// Socket address to bind local UDP port to.
    pub bind_ip_port: SocketAddr,
}

impl Opts {
    /// Start Wireguard implementation using this options set.
    ///
    /// Received IP packets would appear at `tx_fromwg`'s channel.
    /// IP packets to be sent to Wireguard tunnel is to be written to `rx_towg`'s channel.
    pub async fn start(
        &self,
        tx_fromwg: Sender<BytesMut>,
        mut rx_towg: Receiver<BytesMut>,
    ) -> anyhow::Result<()> {
        let mut timer = {
            let mut i = tokio::time::interval(Duration::from_secs(self.keepalive_interval.unwrap_or(1 /* unused*/) as u64));
            i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            i
        };

        
        let udp = tokio::net::UdpSocket::bind(self.bind_ip_port).await?;

        let mut udp_recv_buf = [0; 4096];

        let mut current_peer_addr = self.peer_endpoint;

        let mut tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION_SIZE);
        loop {
            tokio::select! {
                ret = udp.recv_from(&mut udp_recv_buf[..]) => {
                    let ret = ret?;
                    let buf : &[u8] = &udp_recv_buf[0..(ret.0)];
                    let from : SocketAddr = ret.1;

                    if self.peer_endpoint.is_none() {
                        current_peer_addr = Some(from);
                    }

                    tear_off_buffer.extend_from_slice(buf);
                    tx_fromwg.send(tear_off_buffer.split()).await?;
                    if tear_off_buffer.capacity() < 2048 {
                        tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION_SIZE);
                    }
                }
                ret = rx_towg.recv() => {
                    let Some(incoming) : Option<BytesMut> = ret else {
                        warn!("Finished possible packets into gue");
                        break
                    };
                    if let Some(cpa) = current_peer_addr {
                        match udp.send_to(&incoming[..], cpa).await {
                            Ok(_n) => (),
                            Err(e) => {
                                error!("Failed to send gue packet to peer: {e}")
                            }
                        }
                    } else {
                        error!("Trying to send a gue packet without configured peer address");
                    }
                }
                _ = timer.tick() , if self.keepalive_interval.is_some() => {
                    if let Some(cpa) = current_peer_addr {
                        match udp.send_to(b"", cpa).await {
                            Ok(_n) => (),
                            Err(e) => {
                                error!("Failed to send empty packet to peer: {e}")
                            }
                        }
                    } else {
                        error!("Keepalive interval set without destination address?");
                    }
                }
            };
        }
        Ok::<_, anyhow::Error>(())
    }
}

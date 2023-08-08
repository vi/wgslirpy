use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use bytes::BytesMut;
use smoltcp::{
    iface::{Config, Interface, SocketSet, SocketStorage},
    phy::{Checksum, ChecksumCapabilities},
    socket::tcp,
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet,
    },
};
use tokio::{
    io::{AsyncWriteExt, AsyncReadExt},
    net::TcpStream,
    sync::mpsc::{Receiver, Sender},
};
use tracing::{warn, trace};

use crate::channelized_smoltcp_device::ChannelizedDevice;

pub async fn tcp_outgoing_connection(
    tx_to_wg: Sender<BytesMut>,
    mut rx_from_wg: Receiver<BytesMut>,
    external_addr: IpEndpoint,
    _client_addr: IpEndpoint,
) -> anyhow::Result<()> {
    let target_addr = match external_addr.addr {
        IpAddress::Ipv4(x) => SocketAddr::new(std::net::IpAddr::V4(x.into()), external_addr.port),
        IpAddress::Ipv6(x) => SocketAddr::new(std::net::IpAddr::V6(x.into()), external_addr.port),
    };

    let mut tcp = TcpStream::connect(target_addr).await?;
    let (mut tcp_r, mut tcp_w) = tcp.split();

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

    let mut external_tcp_buffer = [0; 32768];

    let mut sockets = SocketSet::new([SocketStorage::EMPTY]);
    let h = sockets.add(tcp_socket);

    let mut sleeper: Option<tokio::time::Sleep> = None;

    ii.poll(Instant::now(), &mut dev, &mut sockets);

    {
        let s = sockets.get_mut::<tcp::Socket>(h);
        s.listen(external_addr)?;
    }

    let mut checksummer = ChecksumCapabilities::ignored();
    checksummer.udp = Checksum::Tx;
    checksummer.ipv4 = Checksum::Tx;
    checksummer.tcp = Checksum::Tx;

    /// To enable avoid un-rust-analyzer-able big content of tokio::select.
    #[derive(Debug)]
    enum SelectOutcome {
        TimePassed,
        PacketFromWg(Option<BytesMut>),
        WrittenToRealTcpSocket(Result<usize, std::io::Error>),
        ReadFromRealTcpSocket(Result<usize, std::io::Error>),
        /// No timeout was active, we need to calculate a new one
        Noop,
    }

    'main_loop: loop {
        let s = sockets.get_mut::<tcp::Socket>(h);

        let number_of_bytes_can_be_sent_to_client = if s.can_send() {
            s.send_capacity() - s.send_queue()
        } else {
            0
        };

        let data_to_send_to_external_socket: Option<&[u8]> = if s.can_recv() {
            if let Ok(b) = s.peek(65536) {
                Some(b)
            } else {
                None
            }
        } else {
            None
        };


        let dtstes = data_to_send_to_external_socket;
        let nbsend = number_of_bytes_can_be_sent_to_client;
        let ret: SelectOutcome = if let Some(tmo) = sleeper.take() {
            trace!("Selecting with a sleeper");
            tokio::select! {
                biased;
                x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                x = tcp_w.write(dtstes.unwrap_or(b"")), if dtstes.is_some() => SelectOutcome::WrittenToRealTcpSocket(x),
                x = tcp_r.read(&mut external_tcp_buffer[..]), if nbsend > 0 => SelectOutcome::ReadFromRealTcpSocket(x),
                _ = tmo => SelectOutcome::TimePassed,
            }
        } else {
            trace!("Selecting without a sleeper");
            tokio::select! {
                biased;
                x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                x = tcp_w.write(dtstes.unwrap_or(b"")), if dtstes.is_some() => SelectOutcome::WrittenToRealTcpSocket(x),
                x = tcp_r.read(&mut external_tcp_buffer[..]), if nbsend > 0 => SelectOutcome::ReadFromRealTcpSocket(x),
                _ = std::future::ready(()) => SelectOutcome::Noop,
            }
        };
        match ret {
            SelectOutcome::TimePassed => {
                trace!("Time passed");
                ii.poll(Instant::now(), &mut dev, &mut sockets);
            }
            SelectOutcome::PacketFromWg(Some(from_wg)) => {
                trace!("Packet from wg");
                dev.rx = Some(from_wg);
                ii.poll(Instant::now(), &mut dev, &mut sockets);
            }
            SelectOutcome::WrittenToRealTcpSocket(Ok(n_bytes)) => {
                trace!("Written to real TCP socket");
                // mark this part of data as really received (not just peeked)
                s.recv(|_| (n_bytes, ()))?;
            }
            SelectOutcome::ReadFromRealTcpSocket(Ok(0)) => {
                warn!("EOF");
                break 'main_loop;
            }
            SelectOutcome::ReadFromRealTcpSocket(Ok(n_bytes)) => {
                trace!("Read from real TCP socket");
                let ret = s.send_slice(&external_tcp_buffer[..n_bytes]);
                assert_eq!(ret, Ok(n_bytes));
            }
            SelectOutcome::Noop => {
                let t = ii.poll_delay(Instant::now(), &mut sockets);
                let t = t.map(|x|Duration::from_micros(x.total_micros())).unwrap_or(Duration::from_secs(60));
                trace!("Setup timeout: {t:?}");
                sleeper = Some(tokio::time::sleep(t));
                continue;
            }
            SelectOutcome::PacketFromWg(None) => {
                warn!("Everything is shutting down, exiting");
                break 'main_loop;
            }
            SelectOutcome::WrittenToRealTcpSocket(Err(e)) => {
                warn!("Error writing to real TCP socket: {e}");
                break 'main_loop;
            }

            SelectOutcome::ReadFromRealTcpSocket(Err(e)) => {
                warn!("Error reading from real TCP socket: {e}");
                break 'main_loop;
            }
        }
        sleeper = None;
    }

    Ok::<_, anyhow::Error>(())
}

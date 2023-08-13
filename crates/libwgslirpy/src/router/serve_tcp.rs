use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use smoltcp::{
    iface::{Config, Interface, SocketSet, SocketStorage},
    socket::tcp::{self, State},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::{Receiver, Sender},
};
use tracing::{debug, trace, warn};

use crate::channelized_smoltcp_device::ChannelizedDevice;

const DANGLE_TIME_SECONDS: u64 = 10;

pub enum ServeTcpMode {
    Outgoing,
    Incoming {
        tcp: TcpStream,
        client_addr: IpEndpoint,
    },
}

pub async fn serve_tcp(
    tx_to_wg: Sender<BytesMut>,
    mut rx_from_wg: Receiver<BytesMut>,
    external_addr: IpEndpoint,
    mode: ServeTcpMode,
    mtu: usize,
    tcp_buffer_size: usize,
) -> anyhow::Result<()> {
    let target_addr = match external_addr.addr {
        IpAddress::Ipv4(x) => SocketAddr::new(std::net::IpAddr::V4(x.into()), external_addr.port),
        IpAddress::Ipv6(x) => SocketAddr::new(std::net::IpAddr::V6(x.into()), external_addr.port),
    };

    let mut dev = ChannelizedDevice::new(tx_to_wg, mtu);

    let ic = Config::new(HardwareAddress::Ip);
    let mut ii = Interface::new(ic, &mut dev, Instant::now());
    ii.update_ip_addrs(|aa| {
        let _ = aa.push(IpCidr::new(external_addr.addr, 0));
    });

    /// To enable avoid un-rust-analyzer-able big content of tokio::select.
    #[derive(Debug)]
    enum SelectOutcome {
        TimePassed,
        PacketFromWg(Option<BytesMut>),
        WrittenToRealTcpSocket(Result<usize, std::io::Error>),
        ReadFromRealTcpSocket(Result<usize, std::io::Error>),
        /// No timeout was active, we need to calculate a new one
        Noop,
        /// Global deadline reached
        Deadline,
    }

    macro_rules! loop_with_deadline {
        ($loop_label:lifetime, $deadline:ident, $sockets:ident, $code:block) => {
            let mut sleeper: Option<tokio::time::Sleep> = None;
            $loop_label: loop {
                $code

                let ret: SelectOutcome = if let Some(tmo) = sleeper.take() {
                    //trace!("Selecting with a sleeper");
                    tokio::select! {
                        biased;
                        x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                        _ = tmo => SelectOutcome::TimePassed,
                        _ = &mut $deadline => SelectOutcome::Deadline,
                    }
                } else {
                    //trace!("Selecting without a sleeper");
                    tokio::select! {
                        biased;
                        x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                        _ = std::future::ready(()) => SelectOutcome::Noop,
                        _ = &mut $deadline => SelectOutcome::Deadline,
                    }
                };
                match ret {
                    SelectOutcome::TimePassed => {
                        trace!("Time passed");
                        ii.poll(Instant::now(), &mut dev, &mut $sockets);
                    }
                    SelectOutcome::PacketFromWg(Some(from_wg)) => {
                        trace!("Packet from wg of len {}", from_wg.len());
                        dev.rx = Some(from_wg);
                        ii.poll(Instant::now(), &mut dev, &mut $sockets);
                    }
                    SelectOutcome::Noop => {
                        let t = ii.poll_delay(Instant::now(), &mut $sockets);
                        let t = t.map(|x|Duration::from_micros(x.total_micros())).unwrap_or(Duration::from_secs(60));
                        trace!("Setup timeout: {t:?}");
                        sleeper = Some(tokio::time::sleep(t));
                        continue;
                    }
                    SelectOutcome::PacketFromWg(None) => {
                        warn!("Everything is shutting down, exiting");
                        return Ok(());
                    }
                    SelectOutcome::WrittenToRealTcpSocket(_) | SelectOutcome::ReadFromRealTcpSocket(_) => unreachable!(),
                    SelectOutcome::Deadline => {
                        break $loop_label;
                    }
                }
                sleeper = None;
            }
        }
    }

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; tcp_buffer_size]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; tcp_buffer_size]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut external_tcp_buffer = vec![0; tcp_buffer_size];

    let mut sockets = SocketSet::new([SocketStorage::EMPTY]);
    let h = sockets.add(tcp_socket);

    ii.poll(Instant::now(), &mut dev, &mut sockets);

    let outgoing = matches!(mode, ServeTcpMode::Outgoing);

    let mut tcp = match mode {
        ServeTcpMode::Outgoing => {
            let tcp_ret = TcpStream::connect(target_addr).await;
            let tcp = match tcp_ret {
                Ok(x) => x,
                Err(e) => {
                    debug!("Failed to connect to upstream TCP: {e}");
                    // Run the deadline loop without a socket to deliver TCP RSTs.

                    let graveyard_deadline =
                        tokio::time::sleep(Duration::from_secs(DANGLE_TIME_SECONDS));
                    tokio::pin!(graveyard_deadline);
                    let mut sockets = SocketSet::new([]);
                    loop_with_deadline!('graveyard_loop, graveyard_deadline, sockets, {

                    });

                    return Ok(());
                }
            };
            debug!("Connected to upstream TCP");
            {
                let s = sockets.get_mut::<tcp::Socket>(h);
                s.listen(external_addr)?;
            }
            tcp
        }
        ServeTcpMode::Incoming { tcp, client_addr } => {
            {
                let s = sockets.get_mut::<tcp::Socket>(h);
                s.connect(ii.context(), client_addr, external_addr)?;
            }
            tcp
        }
    };
    let (mut tcp_r, mut tcp_w) = tcp.split();

    let accept_deadline = tokio::time::sleep(Duration::from_secs(DANGLE_TIME_SECONDS));
    tokio::pin!(accept_deadline);
    loop_with_deadline!('accept_loop, accept_deadline, sockets, {
        let s = sockets.get_mut::<tcp::Socket>(h);

        if s.is_active() && s.state() != State::SynSent {
            break 'accept_loop;
        }
        if s.state() == State::Closed {
            break 'accept_loop;
        }
    });
    drop(accept_deadline);

    if outgoing {
        if !sockets.get_mut::<tcp::Socket>(h).is_active() {
            warn!("Failed to accept the connection from client");
            return Ok(());
        }
    } else {
        let s = sockets.get_mut::<tcp::Socket>(h);
        if s.state() == State::SynSent || !s.is_active() {
            warn!("Failed to connect to TCP within Wireguard");
            return Ok(());
        }
    }

    if outgoing {
        debug!("Accepted the connection");
    } else {
        debug!("Connected");
    }

    let mut sleeper: Option<tokio::time::Sleep> = None;

    let mut already_shutdowned = false;

    // Data transfer
    'main_loop: loop {
        let s = sockets.get_mut::<tcp::Socket>(h);

        match s.state() {
            State::Closed
            | State::Listen
            | State::Closing
            | State::LastAck
            | State::TimeWait => {
                debug!("Client TCP socket no longer active");
                break 'main_loop;
            }
            State::FinWait1
            | State::SynSent
            | State::CloseWait
            | State::FinWait2
            | State::SynReceived
            | State::Established => {
                // Continuing for now
            }
        }

        let number_of_bytes_can_be_sent_to_client = if s.can_send() {
            s.send_capacity() - s.send_queue()
        } else {
            0
        };

        let (data_to_send_to_external_socket, do_shutdown): (Option<&[u8]>, bool) = if s.may_recv()
        {
            if let Ok(b) = s.peek(65536) {
                if b.is_empty() {
                    (None, false)
                } else {
                    (Some(b), false)
                }
            } else {
                (None, false)
            }
        } else {
            if !already_shutdowned && matches!(s.state(), State::CloseWait) {
                debug!("EOF received from client");
                (None, true)
            } else {
                (None, false)
            }
        };

        let dtstes = data_to_send_to_external_socket;
        let nbsend = number_of_bytes_can_be_sent_to_client;
        let ret: SelectOutcome = if let Some(tmo) = sleeper.take() {
            if !do_shutdown {
                tokio::select! {
                    biased;
                    x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                    x = tcp_w.write(dtstes.unwrap_or(b"")), if dtstes.is_some() => SelectOutcome::WrittenToRealTcpSocket(x),
                    x = tcp_r.read(&mut external_tcp_buffer[..nbsend]), if nbsend > 0 => SelectOutcome::ReadFromRealTcpSocket(x),
                    _ = tmo => SelectOutcome::TimePassed,
                }
            } else {
                tokio::select! {
                    biased;
                    x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                    x = tcp_w.shutdown() => { SelectOutcome::WrittenToRealTcpSocket(x.map(|()|0)) }
                    x = tcp_r.read(&mut external_tcp_buffer[..nbsend]), if nbsend > 0 => SelectOutcome::ReadFromRealTcpSocket(x),
                    _ = tmo => SelectOutcome::TimePassed,
                }
            }
        } else {
            if !do_shutdown {
                tokio::select! {
                    biased;
                    x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                    x = tcp_w.write(dtstes.unwrap_or(b"")), if dtstes.is_some() => SelectOutcome::WrittenToRealTcpSocket(x),
                    x = tcp_r.read(&mut external_tcp_buffer[..nbsend]), if nbsend > 0 => SelectOutcome::ReadFromRealTcpSocket(x),
                    _ = std::future::ready(()) => SelectOutcome::Noop,
                }
            } else {
                tokio::select! {
                    biased;
                    x = rx_from_wg.recv() => SelectOutcome::PacketFromWg(x),
                    x = tcp_w.shutdown() => { SelectOutcome::WrittenToRealTcpSocket(x.map(|()|0)) }
                    x = tcp_r.read(&mut external_tcp_buffer[..nbsend]), if nbsend > 0 => SelectOutcome::ReadFromRealTcpSocket(x),
                    _ = std::future::ready(()) => SelectOutcome::Noop,
                }
            }
        };
        match ret {
            SelectOutcome::TimePassed => {
                trace!("Time passed");
                ii.poll(Instant::now(), &mut dev, &mut sockets);
            }
            SelectOutcome::PacketFromWg(Some(from_wg)) => {
                trace!("Packet from wg of len {}", from_wg.len());
                dev.rx = Some(from_wg);
                ii.poll(Instant::now(), &mut dev, &mut sockets);
            }
            SelectOutcome::ReadFromRealTcpSocket(Ok(0)) => {
                debug!("EOF");
                s.close();
            }
            SelectOutcome::WrittenToRealTcpSocket(Ok(0)) => {
                debug!("Shutdown finished");
                already_shutdowned = true;
            }
            SelectOutcome::WrittenToRealTcpSocket(Ok(n_bytes)) => {
                trace!("Written to real TCP socket");
                // mark this part of data as really received (not just peeked)
                s.recv(|_| (n_bytes, ()))?;
            }
            SelectOutcome::ReadFromRealTcpSocket(Ok(n_bytes)) => {
                trace!("Read from real TCP socket");
                let ret = s.send_slice(&external_tcp_buffer[..n_bytes]);
                assert_eq!(ret, Ok(n_bytes));
            }
            SelectOutcome::Noop => {
                let t = ii.poll_delay(Instant::now(), &mut sockets);
                let t = t
                    .map(|x| Duration::from_micros(x.total_micros()))
                    .unwrap_or(Duration::from_secs(60));
                trace!("Setup timeout: {t:?}");
                sleeper = Some(tokio::time::sleep(t));
                continue;
            }
            SelectOutcome::PacketFromWg(None) => {
                warn!("Everything is shutting down, exiting");
                return Ok(());
            }
            SelectOutcome::WrittenToRealTcpSocket(Err(e)) => {
                warn!("Error writing to real TCP socket: {e}");
                s.abort();
                break 'main_loop;
            }

            SelectOutcome::ReadFromRealTcpSocket(Err(e)) => {
                warn!("Error reading from real TCP socket: {e}");
                s.abort();
                break 'main_loop;
            }
            SelectOutcome::Deadline => {
                unreachable!()
            }
        }
        sleeper = None;
    }
    trace!("Exited main TCP handling loop");
    let deadline = tokio::time::sleep(Duration::from_secs(DANGLE_TIME_SECONDS));
    tokio::pin!(deadline);

    let _ = tcp.shutdown().await;
    drop(tcp);

    // Finisishing touches after disconnection to let FINs or RSTs propagate\
    loop_with_deadline!('finishing_loop, deadline, sockets, {});
    trace!("Finished dangling");

    Ok::<_, anyhow::Error>(())
}

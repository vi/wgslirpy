use std::net::SocketAddr;

use bytes::BytesMut;
use simple_dns::ResourceRecord;
use smoltcp::{
    phy::{Checksum, ChecksumCapabilities},
    wire::{
        IpAddress, IpProtocol, IpRepr, IpVersion, Ipv4Packet, Ipv6Packet, UdpPacket,
    },
};

use tracing::{warn, info};


pub async fn dns(
    from_wg: BytesMut,
) -> anyhow::Result<BytesMut> {
    let mut checksummer = ChecksumCapabilities::ignored();
    checksummer.udp = Checksum::Tx;
    checksummer.ipv4 = Checksum::Tx;
    checksummer.tcp = Checksum::Tx;

    let buf = &from_wg[..];
    let (src_addr, dst_addr, payload): (IpAddress, IpAddress, &[u8]) =
        match IpVersion::of_packet(&buf[..]) {
            Err(_e) => {
                anyhow::bail!("DNSERR1");
            }
            Ok(IpVersion::Ipv4) => {
                let Ok(p) = Ipv4Packet::new_checked(&buf[..]) else { anyhow::bail!("DNSERR2") };
                (p.src_addr().into(), p.dst_addr().into(), p.payload())
            }
            Ok(IpVersion::Ipv6) => {
                let Ok(p) = Ipv6Packet::new_checked(&buf[..]) else { anyhow::bail!("DNSERR3") };
                (p.src_addr().into(), p.dst_addr().into(), p.payload())
            }
        };

    let (payload, srcport, dstport) = match UdpPacket::new_checked(payload) {
        Ok(u) => {
            if !u.verify_checksum(&src_addr, &dst_addr) {
                warn!("Failed UDP checksum");
                anyhow::bail!("DNSERR5");
            }
            (u.payload(), u.src_port(), u.dst_port())
        }
        Err(_e) => anyhow::bail!("DNSERR4"),
    };

    let Ok(dns) = simple_dns::Packet::parse(payload) else {
        warn!("Non-DNS packet to DNS service");
        anyhow::bail!("DNSERR6")
    };

    if dns.questions.is_empty() {
        warn!("DNS query with no questions");
        anyhow::bail!("DNSERR7")
    }

    if dns.questions.len() > 1 {
        warn!("DNS query with more than one question");
    }

    let q = &dns.questions[0];

    let mut reply = dns.clone().into_reply();
    
    let nam = format!("{}:0", q.qname);
    info!("DNS query {nam} from {src_addr} {srcport}");

    if let Ok(ret) = tokio::net::lookup_host(nam).await {
        for x in ret {
            match x {
                SocketAddr::V4(t) => reply.answers.push(ResourceRecord {
                    name: q.qname.clone(),
                    class: simple_dns::CLASS::IN,
                    ttl: 60,
                    rdata: simple_dns::rdata::RData::A(simple_dns::rdata::A::from(*t.ip())),
                    cache_flush: false,
                }),
                SocketAddr::V6(t) => reply.answers.push(ResourceRecord {
                    name: q.qname.clone(),
                    class: simple_dns::CLASS::IN,
                    ttl: 60,
                    rdata: simple_dns::rdata::RData::AAAA(simple_dns::rdata::AAAA::from(*t.ip())),
                    cache_flush: false,
                }),
            }
        }
    } else {
        *reply.rcode_mut() = simple_dns::RCODE::ServerFailure;
    }


    let Ok(data) = reply.build_bytes_vec_compressed() else {
        anyhow::bail!("Failed to build DNS reply");
    };

    let mut buf = BytesMut::new();
    buf.resize(data.len() + 64, 0);

    let r = IpRepr::new(
        dst_addr,
        src_addr,
        IpProtocol::Udp,
        data.len() + 8,
        64,
    );

    let len = r.buffer_len();

    let r2 = smoltcp::wire::UdpRepr {
        src_port: dstport,
        dst_port: srcport,
    };

    match r {
        IpRepr::Ipv4(r) => {
            let mut ippkt4 = Ipv4Packet::new_unchecked(buf);
            r.emit(&mut ippkt4, &checksummer);
            let mut udppkt = UdpPacket::new_unchecked(ippkt4.payload_mut());
            r2.emit(
                &mut udppkt,
                &dst_addr,
                &src_addr,
                data.len(),
                |p| p.copy_from_slice(&data[..]),
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
                &dst_addr,
                &src_addr,
                data.len(),
                |p| p.copy_from_slice(&data[..]),
                &checksummer,
            );
            buf = ippkt6.into_inner();
        }
    }
    buf.resize(len, 0);
    

    Ok::<_, anyhow::Error>(buf)
}

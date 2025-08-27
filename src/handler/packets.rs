use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use pnet::packet::{
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    icmpv6::Icmpv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
};

use crate::handler::direction;
use crate::model::{Direction as FlowDir, IcmpKind, NetEvent, Transport};
use crate::render;

pub(crate) fn build_udp_event(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: &HashSet<IpAddr>,
) -> Option<NetEvent> {
    let udp = UdpPacket::new(packet)?;
    let udp_source = udp.get_source();
    let udp_destination = udp.get_destination();
    let dir = if direction::is_destination(destination, ips) {
        FlowDir::Inbound
    } else {
        FlowDir::Outbound
    };
    Some(NetEvent::new(
        interface_name,
        dir,
        source,
        destination,
        Transport::Udp {
            src_port: udp_source,
            dst_port: udp_destination,
            length: udp.get_length(),
            is_dns: udp_source == 53 || udp_destination == 53,
        },
    ))
}

pub fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Arc<HashSet<IpAddr>>,
) {
    if let Some(ev) = build_udp_event(interface_name, source, destination, packet, &ips) {
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

pub(crate) fn build_tcp_event(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: &HashSet<IpAddr>,
) -> Option<NetEvent> {
    let tcp = TcpPacket::new(packet)?;
    let dir = if direction::is_destination(destination, ips) {
        FlowDir::Inbound
    } else {
        FlowDir::Outbound
    };
    Some(NetEvent::new(
        interface_name,
        dir,
        source,
        destination,
        Transport::Tcp {
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
            length: packet.len(),
        },
    ))
}

pub fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Arc<HashSet<IpAddr>>,
) {
    if let Some(ev) = build_tcp_event(interface_name, source, destination, packet, &ips) {
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

pub(crate) fn build_icmp_event(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: &HashSet<IpAddr>,
) -> Option<NetEvent> {
    let icmp_packet = IcmpPacket::new(packet)?;
    let dir: FlowDir = if direction::is_destination(destination, ips) {
        FlowDir::Inbound
    } else {
        FlowDir::Outbound
    };
    let kind = match icmp_packet.get_icmp_type() {
        IcmpTypes::EchoReply => {
            let p = echo_reply::EchoReplyPacket::new(packet).unwrap();
            IcmpKind::EchoReply {
                seq: p.get_sequence_number(),
                id: p.get_identifier(),
            }
        }
        IcmpTypes::EchoRequest => {
            let p = echo_request::EchoRequestPacket::new(packet).unwrap();
            IcmpKind::EchoRequest {
                seq: p.get_sequence_number(),
                id: p.get_identifier(),
            }
        }
        other => IcmpKind::Other(other.0),
    };
    Some(NetEvent::new(
        interface_name,
        dir,
        source,
        destination,
        Transport::Icmp(kind),
    ))
}

pub fn handle_icmp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Arc<HashSet<IpAddr>>,
) {
    if let Some(ev) = build_icmp_event(interface_name, source, destination, packet, &ips) {
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

pub(crate) fn build_icmpv6_event(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: &HashSet<IpAddr>,
) -> Option<NetEvent> {
    let icmpv6_packet = Icmpv6Packet::new(packet)?;
    let dir = if direction::is_destination(destination, ips) {
        FlowDir::Inbound
    } else {
        FlowDir::Outbound
    };
    Some(NetEvent::new(
        interface_name,
        dir,
        source,
        destination,
        Transport::Icmpv6 {
            type_u8: icmpv6_packet.get_icmpv6_type().0,
        },
    ))
}

pub fn handle_icmpv6_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Arc<HashSet<IpAddr>>,
) {
    if let Some(ev) = build_icmpv6_event(interface_name, source, destination, packet, &ips) {
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
    use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::udp::MutableUdpPacket;
    use std::net::{IpAddr, Ipv4Addr};

    fn ips_set() -> HashSet<IpAddr> {
        let mut set = HashSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        set
    }

    #[test]
    fn test_build_udp_event_dns_inbound() {
        let mut buf = vec![0u8; 8];
        {
            let mut p = MutableUdpPacket::new(&mut buf[..]).unwrap();
            p.set_source(53);
            p.set_destination(53000);
            p.set_length(8);
        }
        let ev = build_udp_event(
            "eth0",
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            &buf,
            &ips_set(),
        )
        .expect("event");
        match ev.transport {
            Transport::Udp {
                is_dns,
                src_port,
                dst_port,
                length,
            } => {
                assert!(is_dns);
                assert_eq!(src_port, 53);
                assert_eq!(dst_port, 53000);
                assert_eq!(length, 8);
            }
            _ => panic!("not udp"),
        }
    }

    #[test]
    fn test_build_tcp_event_outbound() {
        let mut buf = vec![0u8; 20];
        {
            let mut p = MutableTcpPacket::new(&mut buf[..]).unwrap();
            p.set_source(55555);
            p.set_destination(80);
        }
        let ev = build_tcp_event(
            "eth0",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            &buf,
            &ips_set(),
        )
        .expect("event");
        match ev.transport {
            Transport::Tcp {
                src_port,
                dst_port,
                length,
            } => {
                assert_eq!(src_port, 55555);
                assert_eq!(dst_port, 80);
                assert_eq!(length, 20);
            }
            _ => panic!("not tcp"),
        }
    }

    #[test]
    fn test_build_icmp_event_echo_request_outbound() {
        let mut buf = vec![0u8; 8];
        {
            let mut icmp = MutableIcmpPacket::new(&mut buf[..]).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            let mut echo = MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
            echo.set_identifier(123);
            echo.set_sequence_number(9);
        }
        let ev = build_icmp_event(
            "eth0",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            &buf,
            &ips_set(),
        )
        .expect("event");
        match ev.transport {
            Transport::Icmp(IcmpKind::EchoRequest { id, seq }) => {
                assert_eq!(id, 123);
                assert_eq!(seq, 9);
            }
            _ => panic!("not icmp echo request"),
        }
    }

    #[test]
    fn test_build_icmpv6_event_inbound() {
        let mut buf = vec![0u8; 4];
        {
            let mut p = MutableIcmpv6Packet::new(&mut buf[..]).unwrap();
            p.set_icmpv6_type(Icmpv6Types::EchoReply);
        }
        let ev = build_icmpv6_event(
            "eth0",
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            &buf,
            &ips_set(),
        )
        .expect("event");
        match ev.transport {
            Transport::Icmpv6 { type_u8 } => assert_eq!(type_u8, Icmpv6Types::EchoReply.0),
            _ => panic!("not icmpv6"),
        }
    }
}

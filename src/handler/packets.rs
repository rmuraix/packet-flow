use std::net::IpAddr;

use pnet::packet::{
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    icmpv6::Icmpv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
};

use crate::handler::direction;
use crate::model::{Direction as FlowDir, IcmpKind, NetEvent, Transport};
use crate::render;

pub fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Vec<IpAddr>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let udp_source: u16 = udp.get_source();
        let udp_destination = udp.get_destination();
        let dir: FlowDir = if direction::is_destination(destination, ips) {
            FlowDir::Inbound
        } else {
            FlowDir::Outbound
        };
        let ev: NetEvent = NetEvent::new(
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
        );
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}
pub fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Vec<IpAddr>,
) {
    let tcp: Option<TcpPacket<'_>> = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        let dir = if direction::is_destination(destination, ips) {
            FlowDir::Inbound
        } else {
            FlowDir::Outbound
        };
        let ev = NetEvent::new(
            interface_name,
            dir,
            source,
            destination,
            Transport::Tcp {
                src_port: tcp.get_source(),
                dst_port: tcp.get_destination(),
                length: packet.len(),
            },
        );
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}
pub fn handle_icmp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Vec<IpAddr>,
) {
    let icmp_packet: Option<IcmpPacket<'_>> = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        let dir: FlowDir = if direction::is_destination(destination, ips) {
            FlowDir::Inbound
        } else {
            FlowDir::Outbound
        };
        let kind = match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let p: echo_reply::EchoReplyPacket<'_> = echo_reply::EchoReplyPacket::new(packet).unwrap();
                IcmpKind::EchoReply {
                    seq: p.get_sequence_number(),
                    id: p.get_identifier(),
                }
            }
            IcmpTypes::EchoRequest => {
                let p: echo_request::EchoRequestPacket<'_> = echo_request::EchoRequestPacket::new(packet).unwrap();
                IcmpKind::EchoRequest {
                    seq: p.get_sequence_number(),
                    id: p.get_identifier(),
                }
            }
            other => IcmpKind::Other(other.0),
        };
        let ev: NetEvent = NetEvent::new(interface_name, dir, source, destination, Transport::Icmp(kind));
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}
pub fn handle_icmpv6_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Vec<IpAddr>,
) {
    let icmpv6_packet: Option<Icmpv6Packet<'_>> = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        let dir = if direction::is_destination(destination, ips) {
            FlowDir::Inbound
        } else {
            FlowDir::Outbound
        };
        let ev = NetEvent::new(
            interface_name,
            dir,
            source,
            destination,
            Transport::Icmpv6 {
                type_u8: icmpv6_packet.get_icmpv6_type().0,
            },
        );
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

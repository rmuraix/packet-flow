mod direction;
mod packets;

extern crate pnet;

use pnet::datalink::NetworkInterface;

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use crate::model::{Direction as FlowDir, NetEvent, Transport};
use crate::render;
use crate::handler::packets::{build_udp_event, build_tcp_event, build_icmp_event, build_icmpv6_event};

pub fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    ips: Arc<HashSet<IpAddr>>,
    noudp: bool,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            if !noudp {
                packets::handle_udp_packet(interface_name, source, destination, packet, ips)
            }
        }
        IpNextHeaderProtocols::Tcp => {
            packets::handle_tcp_packet(interface_name, source, destination, packet, ips)
        }
        IpNextHeaderProtocols::Icmp => {
            packets::handle_icmp_packet(interface_name, source, destination, packet, ips)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            packets::handle_icmpv6_packet(interface_name, source, destination, packet, ips)
        }
        _ => println!(
            "[{}]: {} ===== [Unknown {} packet] =====> {}; protocol: {:?} length: {}",
            interface_name,
            source,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            destination,
            protocol,
            packet.len()
        ),
    }
}

pub(crate) fn build_ipv4_event(
    interface_name: &str,
    ethernet: &EthernetPacket,
    ips: &HashSet<IpAddr>,
    noudp: bool,
) -> Option<NetEvent> {
    let header = Ipv4Packet::new(ethernet.payload())?;
    let src = IpAddr::V4(header.get_source());
    let dst = IpAddr::V4(header.get_destination());
    let proto = header.get_next_level_protocol();
    let payload = header.payload();
    match proto {
        IpNextHeaderProtocols::Udp => {
            if noudp { None } else { build_udp_event(interface_name, src, dst, payload, ips) }
        }
        IpNextHeaderProtocols::Tcp => build_tcp_event(interface_name, src, dst, payload, ips),
        IpNextHeaderProtocols::Icmp => build_icmp_event(interface_name, src, dst, payload, ips),
        _ => None,
    }
}

pub(crate) fn build_ipv6_event(
    interface_name: &str,
    ethernet: &EthernetPacket,
    ips: &HashSet<IpAddr>,
    noudp: bool,
) -> Option<NetEvent> {
    let header = Ipv6Packet::new(ethernet.payload())?;
    let src = IpAddr::V6(header.get_source());
    let dst = IpAddr::V6(header.get_destination());
    let next = header.get_next_header();
    let payload = header.payload();
    match next {
        IpNextHeaderProtocols::Udp => {
            if noudp { None } else { build_udp_event(interface_name, src, dst, payload, ips) }
        }
        IpNextHeaderProtocols::Tcp => build_tcp_event(interface_name, src, dst, payload, ips),
        IpNextHeaderProtocols::Icmpv6 => build_icmpv6_event(interface_name, src, dst, payload, ips),
        _ => None,
    }
}

pub fn handle_arp_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    ips: Arc<HashSet<IpAddr>>,
) {
    if let Some(ev) = build_arp_event(interface_name, ethernet, &ips) {
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed ARP Packet", interface_name);
    }
}

pub(crate) fn build_arp_event(
    interface_name: &str,
    ethernet: &EthernetPacket,
    ips: &HashSet<IpAddr>,
) -> Option<NetEvent> {
    let header = ArpPacket::new(ethernet.payload())?;
    let dir = if direction::is_destination(IpAddr::V4(header.get_target_proto_addr()), ips) {
        FlowDir::Inbound
    } else {
        FlowDir::Outbound
    };
    Some(NetEvent::new(
        interface_name,
        dir,
        IpAddr::V4(header.get_sender_proto_addr()),
        IpAddr::V4(header.get_target_proto_addr()),
        Transport::Arp {
            operation: header.get_operation().0,
            sender_mac: ethernet.get_source(),
            sender_ip: header.get_sender_proto_addr(),
            target_mac: ethernet.get_destination(),
            target_ip: header.get_target_proto_addr(),
        },
    ))
}

pub(crate) fn build_ethernet_event(
    interface_name: &str,
    ethernet: &EthernetPacket,
    ips: &HashSet<IpAddr>,
    noudp: bool,
) -> Option<NetEvent> {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => build_ipv4_event(interface_name, ethernet, ips, noudp),
        EtherTypes::Ipv6 => build_ipv6_event(interface_name, ethernet, ips, noudp),
        EtherTypes::Arp => build_arp_event(interface_name, ethernet, ips),
        _ => None,
    }
}

pub fn handle_ethernet_frame(
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
    ips: Arc<HashSet<IpAddr>>,
    noudp: bool,
) {
    let interface_name = &interface.name[..];
    if let Some(ev) = build_ethernet_event(interface_name, ethernet, &ips, noudp) {
        render::print_event(&ev);
    } else {
        println!(
            "[{}]: {} ===== [Unknown] =====> {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::MutablePacket;
    use pnet::util::MacAddr;
    use pnet::packet::arp::{MutableArpPacket, ArpHardwareTypes, ArpOperations};

    fn ips_set() -> HashSet<IpAddr> {
        let mut set = HashSet::new();
        set.insert(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)));
        set
    }

    #[test]
    fn test_build_ipv4_udp_filtered_by_noudp() {
        // Build IPv4 + UDP in Ethernet
        let mut ip_buf = vec![0u8; 20 + 8];
        {
            let mut ip = MutableIpv4Packet::new(&mut ip_buf[..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + 8) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(std::net::Ipv4Addr::new(1, 1, 1, 1));
            ip.set_destination(std::net::Ipv4Addr::new(10, 0, 0, 2));
            let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
            udp.set_source(53);
            udp.set_destination(53000);
            udp.set_length(8);
        }
        let mut eth_buf = vec![0u8; 14 + ip_buf.len()];
        {
            let mut eth = MutableEthernetPacket::new(&mut eth_buf[..]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
            eth.set_source(MacAddr(0,0,0,0,0,1));
            eth.set_destination(MacAddr(0,0,0,0,0,2));
            eth.set_payload(&ip_buf);
        }
        let eth = EthernetPacket::new(&eth_buf[..]).unwrap();
        // With noudp=true, builder should filter out
        let ev = build_ipv4_event("eth0", &eth, &ips_set(), true);
        assert!(ev.is_none());
        // With noudp=false, event exists
        let ev = build_ipv4_event("eth0", &eth, &ips_set(), false).expect("event");
        match ev.transport { Transport::Udp { is_dns, .. } => assert!(is_dns), _ => panic!("not udp") }
    }

    #[test]
    fn test_build_ipv6_tcp_outbound() {
        // Build IPv6 + TCP in Ethernet
        let mut ip6_buf = vec![0u8; 40 + 20];
        {
            let mut ip6 = MutableIpv6Packet::new(&mut ip6_buf[..]).unwrap();
            ip6.set_version(6);
            ip6.set_payload_length(20);
            ip6.set_next_header(IpNextHeaderProtocols::Tcp);
            ip6.set_hop_limit(64);
            ip6.set_source(std::net::Ipv6Addr::LOCALHOST);
            ip6.set_destination(std::net::Ipv6Addr::LOCALHOST);
            let mut tcp = MutableTcpPacket::new(ip6.payload_mut()).unwrap();
            tcp.set_source(50000);
            tcp.set_destination(443);
        }
        let mut eth_buf = vec![0u8; 14 + ip6_buf.len()];
        {
            let mut eth = MutableEthernetPacket::new(&mut eth_buf[..]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv6);
            eth.set_source(MacAddr(0,0,0,0,0,1));
            eth.set_destination(MacAddr(0,0,0,0,0,2));
            eth.set_payload(&ip6_buf);
        }
        let eth = EthernetPacket::new(&eth_buf[..]).unwrap();
        let ev = build_ipv6_event("eth0", &eth, &ips_set(), false).expect("event");
        match ev.transport { Transport::Tcp { dst_port, .. } => assert_eq!(dst_port, 443), _ => panic!("not tcp") }
    }

    #[test]
    fn test_build_ethernet_arp_inbound() {
        // Build ARP request targeting our host IP
        let mut arp_buf = vec![0u8; 28];
        {
            let mut arp = MutableArpPacket::new(&mut arp_buf[..]).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Request);
            arp.set_sender_hw_addr(MacAddr(0,1,2,3,4,5));
            arp.set_sender_proto_addr(std::net::Ipv4Addr::new(10,0,0,3));
            arp.set_target_hw_addr(MacAddr(0,0,0,0,0,0));
            arp.set_target_proto_addr(std::net::Ipv4Addr::new(10,0,0,2));
        }
        let mut eth_buf = vec![0u8; 14 + arp_buf.len()];
        {
            let mut eth = MutableEthernetPacket::new(&mut eth_buf[..]).unwrap();
            eth.set_ethertype(EtherTypes::Arp);
            eth.set_source(MacAddr(0,1,2,3,4,5));
            eth.set_destination(MacAddr(0,0,0,0,0,0));
            eth.set_payload(&arp_buf);
        }
        let eth = EthernetPacket::new(&eth_buf[..]).unwrap();
        let ev = build_ethernet_event("eth0", &eth, &ips_set(), false).expect("event");
        match ev.transport {
            Transport::Arp { operation, sender_ip, target_ip, .. } => {
                assert_eq!(operation, ArpOperations::Request.0);
                assert_eq!(sender_ip, std::net::Ipv4Addr::new(10,0,0,3));
                assert_eq!(target_ip, std::net::Ipv4Addr::new(10,0,0,2));
            }
            _ => panic!("not arp"),
        }
        assert!(matches!(ev.direction, FlowDir::Inbound));
    }
}

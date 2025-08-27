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

use std::net::IpAddr;
use crate::model::{Direction as FlowDir, NetEvent, Transport};
use crate::render;

pub fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    ips: Vec<IpAddr>,
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

pub fn handle_ipv4_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    ips: Vec<IpAddr>,
    noudp: bool,
) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            ips,
            noudp,
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

pub fn handle_ipv6_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    ips: Vec<IpAddr>,
    noudp: bool,
) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            ips,
            noudp,
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

pub fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket, ips: Vec<IpAddr>) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        let dir = if direction::is_destination(IpAddr::V4(header.get_target_proto_addr()), ips) {
            FlowDir::Inbound
        } else {
            FlowDir::Outbound
        };
        let ev = NetEvent::new(
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
        );
        render::print_event(&ev);
    } else {
        println!("[{}]: Malformed ARP Packet", interface_name);
    }
}

pub fn handle_ethernet_frame(
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
    ips: Vec<IpAddr>,
    noudp: bool,
) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet, ips, noudp),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet, ips, noudp),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet, ips),
        _ => println!(
            "[{}]: {} ===== [Unknown] =====> {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

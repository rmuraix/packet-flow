use std::net::IpAddr;

use pnet::packet::{
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    icmpv6::Icmpv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
};

use crate::handler::direction;

pub fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ips: Vec<IpAddr>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let udp_source = udp.get_source();
        let udp_destination = udp.get_destination();
        if (udp_source == 53) || (udp_destination == 53) {
            // When this device is on the receiving end
            if direction::is_destination(destination, ips) {
                println!(
                    "[{}]: {}:{} \x1b[33m<===== [UDP/DNS] =====\x1b[0m {}:{}; length: {}",
                    interface_name,
                    destination,
                    udp_destination,
                    source,
                    udp_source,
                    udp.get_length()
                );
            } else {
                println!(
                    "[{}]: {}:{} \x1b[33m====== [UDP/DNS] =====>\x1b[0m {}:{}; length: {}",
                    interface_name,
                    source,
                    udp_source,
                    destination,
                    udp_destination,
                    udp.get_length()
                );
            }
        } else {
            // When this device is on the receiving end
            if direction::is_destination(destination, ips) {
                println!(
                    "[{}]: {}:{} \x1b[33m<===== [UDP] =====\x1b[0m {}:{}; length: {}",
                    interface_name,
                    destination,
                    udp_destination,
                    source,
                    udp_source,
                    udp.get_length()
                );
            } else {
                println!(
                    "[{}]: {}:{} \x1b[33m====== [UDP] =====>\x1b[0m {}:{}; length: {}",
                    interface_name,
                    source,
                    udp_source,
                    destination,
                    udp_destination,
                    udp.get_length()
                );
            }
        }
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
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        // When this device is on the receiving end
        if direction::is_destination(destination, ips) {
            println!(
                "[{}]: {}:{} \x1b[34m<==== [TCP] =====\x1b[0m {}:{}; length: {}",
                interface_name,
                destination,
                tcp.get_destination(),
                source,
                tcp.get_source(),
                packet.len()
            );
        } else {
            println!(
                "[{}]: {}:{} \x1b[34m===== [TCP] =====>\x1b[0m {}:{}; length: {}",
                interface_name,
                source,
                tcp.get_source(),
                destination,
                tcp.get_destination(),
                packet.len()
            );
        }
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
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                // When this device is on the receiving end
                if direction::is_destination(destination, ips) {
                    println!(
                        "[{}]: {} \x1b[35m<==== [ICMP echo reply] =====\x1b[0m {} (seq={:?}, id={:?})",
                        interface_name,
                        destination,
                        source,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    );
                } else {
                    println!(
                    "[{}]: {} \x1b[35m===== [ICMP echo reply] =====>\x1b[0m {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
                }
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                // When this device is on the receiving end
                if direction::is_destination(destination, ips) {
                    println!(
                        "[{}]: {} \x1b[35m<==== [ICMP echo] =====\x1b[0m {} (seq={:?}, id={:?})",
                        interface_name,
                        destination,
                        source,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    );
                } else {
                    println!(
                        "[{}]: {} \x1b[35m===== [ICMP echo] =====>\x1b[0m {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    );
                }
            }
            _ => {
                // When this device is on the receiving end
                if direction::is_destination(destination, ips) {
                    println!(
                        "[{}]: {} \x1b[35m<==== [ICMP] =====\x1b[0m {} (type={:?})",
                        interface_name,
                        destination,
                        source,
                        icmp_packet.get_icmp_type()
                    )
                } else {
                    println!(
                        "[{}]: {} \x1b[35m===== [ICMP] =====>\x1b[0m {} (type={:?})",
                        interface_name,
                        source,
                        destination,
                        icmp_packet.get_icmp_type()
                    )
                }
            }
        }
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
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        // When this device is on the receiving end
        if direction::is_destination(destination, ips) {
            println!(
                "[{}]: {} \x1b[95m<==== [ICMPv6] =====\x1b[0m {} (type={:?})",
                interface_name,
                destination,
                source,
                icmpv6_packet.get_icmpv6_type()
            )
        } else {
            println!(
                "[{}]: {} \x1b[95m===== [ICMPv6] =====>\x1b[0m {} (type={:?})",
                interface_name,
                source,
                destination,
                icmpv6_packet.get_icmpv6_type()
            )
        }
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

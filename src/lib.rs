pub mod handler;

use std::net::IpAddr;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;

/// Runtime configuration passed from the CLI layer.
pub struct Config {
    pub interface: String,
    pub noudp: bool,
}

/// Main runtime loop. Never returns under normal operation.
pub fn run(config: Config) -> ! {
    use pnet::datalink::Channel::Ethernet;

    let iface_name: String = config.interface;
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    // Get device's IP address
    let mut ips: Vec<IpAddr> = Vec::new();
    for interface in &interfaces {
        if !interface.ips.is_empty() && interface.is_up() {
            for ip_net in &interface.ips {
                if !ip_net.ip().is_loopback() {
                    ips.push(ip_net.ip());
                }
            }
        }
    }
    println!("IP address of this device:{:?}", ips);

    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packet-flow: unhandled channel type"),
        Err(e) => panic!("packet-flow: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            crate::handler::handle_ethernet_frame(
                                &interface,
                                &fake_ethernet_frame.to_immutable(),
                                ips.clone(),
                                config.noudp,
                            );
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            crate::handler::handle_ethernet_frame(
                                &interface,
                                &fake_ethernet_frame.to_immutable(),
                                ips.clone(),
                                config.noudp,
                            );
                            continue;
                        }
                    }
                }
                crate::handler::handle_ethernet_frame(
                    &interface,
                    &EthernetPacket::new(packet).unwrap(),
                    ips.clone(),
                    config.noudp,
                );
            }
            Err(e) => panic!("packet-flow: unable to receive packet: {}", e),
        }
    }
}

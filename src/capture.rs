use std::net::IpAddr;

use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;

pub struct Capture {
    interface: NetworkInterface,
    rx: Box<dyn DataLinkReceiver>,
    buf: [u8; 1600],
}

impl Capture {
    pub fn open(iface_name: &str) -> anyhow::Result<Self> {
        let interfaces: Vec<NetworkInterface> = datalink::interfaces();
        let interface: NetworkInterface = interfaces
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == iface_name)
            .ok_or_else(|| anyhow::anyhow!("No such network interface: {}", iface_name))?;

        let (_, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow::anyhow!("packet-flow: unhandled channel type")),
            Err(e) => return Err(anyhow::anyhow!("packet-flow: unable to create channel: {}", e)),
        };

        Ok(Self {
            interface,
            rx,
            buf: [0u8; 1600],
        })
    }

    pub fn interface(&self) -> &NetworkInterface {
        &self.interface
    }

    pub fn host_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = Vec::new();
        for interface in datalink::interfaces() {
            if !interface.ips.is_empty() && interface.is_up() {
                for ip_net in interface.ips {
                    if !ip_net.ip().is_loopback() {
                        ips.push(ip_net.ip());
                    }
                }
            }
        }
        ips
    }

    pub fn next_ethernet<'a>(&'a mut self) -> anyhow::Result<EthernetPacket<'a>> {
        match self.rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && self.interface.is_up()
                    && !self.interface.is_broadcast()
                    && ((!self.interface.is_loopback() && self.interface.is_point_to_point())
                        || self.interface.is_loopback())
                {
                    if self.interface.is_loopback() {
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
                            let mut fake = MutableEthernetPacket::new(&mut self.buf[..]).unwrap();
                            fake.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake.set_ethertype(EtherTypes::Ipv4);
                            fake.set_payload(&packet[payload_offset..]);
                            let im = EthernetPacket::new(&self.buf[..]).unwrap();
                            return Ok(im);
                        } else if version == 6 {
                            let mut fake = MutableEthernetPacket::new(&mut self.buf[..]).unwrap();
                            fake.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake.set_ethertype(EtherTypes::Ipv6);
                            fake.set_payload(&packet[payload_offset..]);
                            let im = EthernetPacket::new(&self.buf[..]).unwrap();
                            return Ok(im);
                        }
                    }
                }
                Ok(EthernetPacket::new(packet).unwrap())
            }
            Err(e) => Err(anyhow::anyhow!("packet-flow: unable to receive packet: {}", e)),
        }
    }
}

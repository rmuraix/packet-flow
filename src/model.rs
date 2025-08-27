use std::net::IpAddr;
use std::net::Ipv4Addr;
use pnet::util::MacAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpKind {
    EchoReply { seq: u16, id: u16 },
    EchoRequest { seq: u16, id: u16 },
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
        is_dns: bool,
    },
    Tcp {
        src_port: u16,
        dst_port: u16,
        length: usize,
    },
    Icmp(IcmpKind),
    Icmpv6 { type_u8: u8 },
    Arp {
        operation: u16,
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    pub interface: String,
    pub direction: Direction,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub transport: Transport,
}

impl NetEvent {
    pub fn new(
        interface: impl Into<String>,
        direction: Direction,
        source: IpAddr,
        destination: IpAddr,
        transport: Transport,
    ) -> Self {
        Self {
            interface: interface.into(),
            direction,
            source,
            destination,
            transport,
        }
    }
}

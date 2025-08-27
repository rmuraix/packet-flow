use crate::model::{Direction, IcmpKind, NetEvent, Transport};
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_color_enabled(enabled: bool) {
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

fn col(code: &'static str) -> &'static str {
    if COLOR_ENABLED.load(Ordering::Relaxed) {
        code
    } else {
        ""
    }
}

pub fn render_line(e: &NetEvent) -> String {
    match &e.transport {
        Transport::Udp {
            src_port,
            dst_port,
            length,
            is_dns,
        } => {
            let label = if *is_dns { "UDP/DNS" } else { "UDP" };
            match e.direction {
                Direction::Inbound => format!(
                    "[{}]: {}:{} {}<===== [{}] ====={} {}:{}; length: {}",
                    e.interface,
                    e.destination,
                    dst_port,
                    col("\x1b[33m"),
                    label,
                    col("\x1b[0m"),
                    e.source,
                    src_port,
                    length
                ),
                Direction::Outbound => format!(
                    "[{}]: {}:{} {}====== [{}] =====>{} {}:{}; length: {}",
                    e.interface,
                    e.source,
                    src_port,
                    col("\x1b[33m"),
                    label,
                    col("\x1b[0m"),
                    e.destination,
                    dst_port,
                    length
                ),
            }
        }
        Transport::Tcp {
            src_port,
            dst_port,
            length,
        } => match e.direction {
            Direction::Inbound => format!(
                "[{}]: {}:{} {}<==== [TCP] ====={} {}:{}; length: {}",
                e.interface,
                e.destination,
                dst_port,
                col("\x1b[34m"),
                col("\x1b[0m"),
                e.source,
                src_port,
                length
            ),
            Direction::Outbound => format!(
                "[{}]: {}:{} {}===== [TCP] =====>{} {}:{}; length: {}",
                e.interface,
                e.source,
                src_port,
                col("\x1b[34m"),
                col("\x1b[0m"),
                e.destination,
                dst_port,
                length
            ),
        },
        Transport::Icmp(kind) => {
            match kind {
                IcmpKind::EchoReply { seq, id } => {
                    match e.direction {
                        Direction::Inbound => format!(
                            "[{}]: {} {}<==== [ICMP echo reply] ====={} {} (seq={:?}, id={:?})",
                            e.interface,
                            e.destination,
                            col("\x1b[35m"),
                            col("\x1b[0m"),
                            e.source,
                            seq,
                            id
                        ),
                        Direction::Outbound => {
                            format!(
                    "[{}]: {} {}===== [ICMP echo reply] =====>{} {} (seq={:?}, id={:?})",
                    e.interface, e.source, col("\x1b[35m"), col("\x1b[0m"), e.destination, seq, id
                )
                        }
                    }
                }
                IcmpKind::EchoRequest { seq, id } => match e.direction {
                    Direction::Inbound => format!(
                        "[{}]: {} {}<==== [ICMP echo] ====={} {} (seq={:?}, id={:?})",
                        e.interface,
                        e.destination,
                        col("\x1b[35m"),
                        col("\x1b[0m"),
                        e.source,
                        seq,
                        id
                    ),
                    Direction::Outbound => format!(
                        "[{}]: {} {}===== [ICMP echo] =====>{} {} (seq={:?}, id={:?})",
                        e.interface,
                        e.source,
                        col("\x1b[35m"),
                        col("\x1b[0m"),
                        e.destination,
                        seq,
                        id
                    ),
                },
                IcmpKind::Other(t) => match e.direction {
                    Direction::Inbound => format!(
                        "[{}]: {} {}<==== [ICMP] ====={} {} (type={:?})",
                        e.interface,
                        e.destination,
                        col("\x1b[35m"),
                        col("\x1b[0m"),
                        e.source,
                        t
                    ),
                    Direction::Outbound => format!(
                        "[{}]: {} {}===== [ICMP] =====>{} {} (type={:?})",
                        e.interface,
                        e.source,
                        col("\x1b[35m"),
                        col("\x1b[0m"),
                        e.destination,
                        t
                    ),
                },
            }
        }
        Transport::Icmpv6 { type_u8 } => match e.direction {
            Direction::Inbound => format!(
                "[{}]: {} {}<==== [ICMPv6] ====={} {} (type={:?})",
                e.interface,
                e.destination,
                col("\x1b[95m"),
                col("\x1b[0m"),
                e.source,
                type_u8
            ),
            Direction::Outbound => format!(
                "[{}]: {} {}===== [ICMPv6] =====>{} {} (type={:?})",
                e.interface,
                e.source,
                col("\x1b[95m"),
                col("\x1b[0m"),
                e.destination,
                type_u8
            ),
        },
        Transport::Arp {
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        } => match e.direction {
            Direction::Inbound => format!(
                "[{}]: {}({}) {}<==== [ARP] ======{} {}({}); operation: {:?}",
                e.interface,
                target_mac,
                target_ip,
                col("\x1b[31m"),
                col("\x1b[0m"),
                sender_mac,
                sender_ip,
                operation
            ),
            Direction::Outbound => format!(
                "[{}]: {}({}) {}===== [ARP] =====>{} {}({}); operation: {:?}",
                e.interface,
                sender_mac,
                sender_ip,
                col("\x1b[31m"),
                col("\x1b[0m"),
                target_mac,
                target_ip,
                operation
            ),
        },
    }
}

pub fn print_event(e: &NetEvent) {
    println!("{}", render_line(e));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Direction, IcmpKind, NetEvent, Transport};
    use pnet::util::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn render_udp_dns_inbound_no_color() {
        set_color_enabled(false);
        let e = NetEvent::new(
            "eth0",
            Direction::Inbound,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            Transport::Udp {
                src_port: 53,
                dst_port: 53000,
                length: 42,
                is_dns: true,
            },
        );
        let line = render_line(&e);
        assert_eq!(
            line,
            "[eth0]: 10.0.0.2:53000 <===== [UDP/DNS] ===== 1.1.1.1:53; length: 42"
        );
    }

    #[test]
    fn render_tcp_outbound_no_color() {
        set_color_enabled(false);
        let e = NetEvent::new(
            "eth0",
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            Transport::Tcp {
                src_port: 50123,
                dst_port: 443,
                length: 1200,
            },
        );
        let line = render_line(&e);
        assert_eq!(
            line,
            "[eth0]: 10.0.0.2:50123 ===== [TCP] =====> 93.184.216.34:443; length: 1200"
        );
    }

    #[test]
    fn render_icmp_echo_reply_inbound_no_color() {
        set_color_enabled(false);
        let e = NetEvent::new(
            "eth0",
            Direction::Inbound,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            Transport::Icmp(IcmpKind::EchoReply { seq: 1, id: 99 }),
        );
        let line = render_line(&e);
        assert_eq!(
            line,
            "[eth0]: 10.0.0.2 <==== [ICMP echo reply] ===== 8.8.8.8 (seq=1, id=99)"
        );
    }

    #[test]
    fn render_arp_outbound_no_color() {
        set_color_enabled(false);
        let e = NetEvent::new(
            "eth0",
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Transport::Arp {
                operation: 1,
                sender_mac: MacAddr(0, 1, 2, 3, 4, 5),
                sender_ip: Ipv4Addr::new(10, 0, 0, 2),
                target_mac: MacAddr(0, 0, 0, 0, 0, 0),
                target_ip: Ipv4Addr::new(10, 0, 0, 1),
            },
        );
        let line = render_line(&e);
        assert_eq!(line, "[eth0]: 00:01:02:03:04:05(10.0.0.2) ===== [ARP] =====> 00:00:00:00:00:00(10.0.0.1); operation: 1");
    }
}

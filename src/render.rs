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

pub fn print_event(e: &NetEvent) {
    match &e.transport {
        Transport::Udp {
            src_port,
            dst_port,
            length,
            is_dns,
        } => {
            let label: &'static str = if *is_dns { "UDP/DNS" } else { "UDP" };
            match e.direction {
                Direction::Inbound => println!(
                    "[{}]: {}:{} {}<===== [{}] ====={} {}:{}; length: {}",
                    e.interface, e.destination, dst_port, col("\x1b[33m"), label, col("\x1b[0m"), e.source, src_port, length
                ),
                Direction::Outbound => println!(
                    "[{}]: {}:{} {}====== [{}] =====>{} {}:{}; length: {}",
                    e.interface, e.source, src_port, col("\x1b[33m"), label, col("\x1b[0m"), e.destination, dst_port, length
                ),
            }
        }
        Transport::Tcp {
            src_port,
            dst_port,
            length,
        } => match e.direction {
            Direction::Inbound => println!(
                "[{}]: {}:{} {}<==== [TCP] ====={} {}:{}; length: {}",
                e.interface, e.destination, dst_port, col("\x1b[34m"), col("\x1b[0m"), e.source, src_port, length
            ),
            Direction::Outbound => println!(
                "[{}]: {}:{} {}===== [TCP] =====>{} {}:{}; length: {}",
                e.interface, e.source, src_port, col("\x1b[34m"), col("\x1b[0m"), e.destination, dst_port, length
            ),
        },
        Transport::Icmp(kind) => match kind {
            IcmpKind::EchoReply { seq, id } => match e.direction {
                Direction::Inbound => println!(
                    "[{}]: {} {}<==== [ICMP echo reply] ====={} {} (seq={:?}, id={:?})",
                    e.interface, e.destination, col("\x1b[35m"), col("\x1b[0m"), e.source, seq, id
                ),
                Direction::Outbound => println!(
                    "[{}]: {} {}===== [ICMP echo reply] =====>{} {} (seq={:?}, id={:?})",
                    e.interface, e.source, col("\x1b[35m"), col("\x1b[0m"), e.destination, seq, id
                ),
            },
            IcmpKind::EchoRequest { seq, id } => match e.direction {
                Direction::Inbound => println!(
                    "[{}]: {} {}<==== [ICMP echo] ====={} {} (seq={:?}, id={:?})",
                    e.interface, e.destination, col("\x1b[35m"), col("\x1b[0m"), e.source, seq, id
                ),
                Direction::Outbound => println!(
                    "[{}]: {} {}===== [ICMP echo] =====>{} {} (seq={:?}, id={:?})",
                    e.interface, e.source, col("\x1b[35m"), col("\x1b[0m"), e.destination, seq, id
                ),
            },
            IcmpKind::Other(t) => match e.direction {
                Direction::Inbound => println!(
                    "[{}]: {} {}<==== [ICMP] ====={} {} (type={:?})",
                    e.interface, e.destination, col("\x1b[35m"), col("\x1b[0m"), e.source, t
                ),
                Direction::Outbound => println!(
                    "[{}]: {} {}===== [ICMP] =====>{} {} (type={:?})",
                    e.interface, e.source, col("\x1b[35m"), col("\x1b[0m"), e.destination, t
                ),
            },
        },
        Transport::Icmpv6 { type_u8 } => match e.direction {
            Direction::Inbound => println!(
                "[{}]: {} {}<==== [ICMPv6] ====={} {} (type={:?})",
                e.interface, e.destination, col("\x1b[95m"), col("\x1b[0m"), e.source, type_u8
            ),
            Direction::Outbound => println!(
                "[{}]: {} {}===== [ICMPv6] =====>{} {} (type={:?})",
                e.interface, e.source, col("\x1b[95m"), col("\x1b[0m"), e.destination, type_u8
            ),
        },
        Transport::Arp {
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        } => match e.direction {
            Direction::Inbound => println!(
                "[{}]: {}({}) {}<==== [ARP] ======{} {}({}); operation: {:?}",
                e.interface, target_mac, target_ip, col("\x1b[31m"), col("\x1b[0m"), sender_mac, sender_ip, operation
            ),
            Direction::Outbound => println!(
                "[{}]: {}({}) {}===== [ARP] =====>{} {}({}); operation: {:?}",
                e.interface, sender_mac, sender_ip, col("\x1b[31m"), col("\x1b[0m"), target_mac, target_ip, operation
            ),
        },
    }
}

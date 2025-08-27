use crate::model::{Direction, IcmpKind, NetEvent, Transport};

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
                    "[{}]: {}:{} \x1b[33m<===== [{}] =====\x1b[0m {}:{}; length: {}",
                    e.interface, e.destination, dst_port, label, e.source, src_port, length
                ),
                Direction::Outbound => println!(
                    "[{}]: {}:{} \x1b[33m====== [{}] =====>\x1b[0m {}:{}; length: {}",
                    e.interface, e.source, src_port, label, e.destination, dst_port, length
                ),
            }
        }
        Transport::Tcp {
            src_port,
            dst_port,
            length,
        } => match e.direction {
            Direction::Inbound => println!(
                "[{}]: {}:{} \x1b[34m<==== [TCP] =====\x1b[0m {}:{}; length: {}",
                e.interface, e.destination, dst_port, e.source, src_port, length
            ),
            Direction::Outbound => println!(
                "[{}]: {}:{} \x1b[34m===== [TCP] =====>\x1b[0m {}:{}; length: {}",
                e.interface, e.source, src_port, e.destination, dst_port, length
            ),
        },
        Transport::Icmp(kind) => match kind {
            IcmpKind::EchoReply { seq, id } => match e.direction {
                Direction::Inbound => println!(
                    "[{}]: {} \x1b[35m<==== [ICMP echo reply] =====\x1b[0m {} (seq={:?}, id={:?})",
                    e.interface, e.destination, e.source, seq, id
                ),
                Direction::Outbound => println!(
                    "[{}]: {} \x1b[35m===== [ICMP echo reply] =====>\x1b[0m {} (seq={:?}, id={:?})",
                    e.interface, e.source, e.destination, seq, id
                ),
            },
            IcmpKind::EchoRequest { seq, id } => match e.direction {
                Direction::Inbound => println!(
                    "[{}]: {} \x1b[35m<==== [ICMP echo] =====\x1b[0m {} (seq={:?}, id={:?})",
                    e.interface, e.destination, e.source, seq, id
                ),
                Direction::Outbound => println!(
                    "[{}]: {} \x1b[35m===== [ICMP echo] =====>\x1b[0m {} (seq={:?}, id={:?})",
                    e.interface, e.source, e.destination, seq, id
                ),
            },
            IcmpKind::Other(t) => match e.direction {
                Direction::Inbound => println!(
                    "[{}]: {} \x1b[35m<==== [ICMP] =====\x1b[0m {} (type={:?})",
                    e.interface, e.destination, e.source, t
                ),
                Direction::Outbound => println!(
                    "[{}]: {} \x1b[35m===== [ICMP] =====>\x1b[0m {} (type={:?})",
                    e.interface, e.source, e.destination, t
                ),
            },
        },
        Transport::Icmpv6 { type_u8 } => match e.direction {
            Direction::Inbound => println!(
                "[{}]: {} \x1b[95m<==== [ICMPv6] =====\x1b[0m {} (type={:?})",
                e.interface, e.destination, e.source, type_u8
            ),
            Direction::Outbound => println!(
                "[{}]: {} \x1b[95m===== [ICMPv6] =====>\x1b[0m {} (type={:?})",
                e.interface, e.source, e.destination, type_u8
            ),
        },
    }
}

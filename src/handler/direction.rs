use std::collections::HashSet;
use std::net::IpAddr;

pub fn is_destination(ip: IpAddr, ips: &HashSet<IpAddr>) -> bool {
    ips.contains(&ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_destination() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let mut ips: HashSet<IpAddr> = HashSet::new();
        ips.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));

        assert_eq!(is_destination(ip, &ips), false);

        ips.insert(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        assert_eq!(is_destination(ip, &ips), true);
    }
}

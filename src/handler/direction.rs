use std::net::IpAddr;

pub fn is_destination(ip: IpAddr, ips: Vec<IpAddr>) -> bool {
    let mut is_destination = false;
    for i in ips {
        if i == ip {
            is_destination = true;
            break;
        }
    }
    is_destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_destination() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let mut ips: Vec<IpAddr> = Vec::new();
        ips.push(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));

        assert_eq!(is_destination(ip, (*ips).to_vec()), false);

        ips.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        assert_eq!(is_destination(ip, (*ips).to_vec()), true);
    }
}

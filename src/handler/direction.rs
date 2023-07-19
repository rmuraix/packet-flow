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

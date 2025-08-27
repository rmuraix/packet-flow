pub mod handler;
pub mod capture;
pub mod model;
pub mod render;

/// Runtime configuration passed from the CLI layer.
pub struct Config {
    pub interface: String,
    pub noudp: bool,
}

/// Main runtime loop. Returns error instead of panicking.
pub fn run(config: Config) -> anyhow::Result<()> {
    let mut cap: capture::Capture = capture::Capture::open(&config.interface)?;

    let ips_vec: Vec<std::net::IpAddr> = cap.host_ips();
    println!("IP address of this device:{:?}", ips_vec);
    let ips_set: std::collections::HashSet<std::net::IpAddr> = ips_vec.into_iter().collect();
    let ips = std::sync::Arc::new(ips_set);
    let iface_owned: pnet::datalink::NetworkInterface = cap.interface().clone();

    loop {
        let frame = cap.next_ethernet()?;
        crate::handler::handle_ethernet_frame(&iface_owned, &frame, std::sync::Arc::clone(&ips), config.noudp);
    }
}

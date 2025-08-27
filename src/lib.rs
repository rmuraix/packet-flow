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

    let ips: Vec<std::net::IpAddr> = cap.host_ips();
    println!("IP address of this device:{:?}", ips);
    let iface_owned: pnet::datalink::NetworkInterface = cap.interface().clone();

    loop {
        let frame = cap.next_ethernet()?;
        crate::handler::handle_ethernet_frame(
            &iface_owned,
            &frame,
            ips.clone(),
            config.noudp,
        );
    }
}

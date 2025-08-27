pub mod handler;
pub mod capture;
pub mod model;
pub mod render;

/// Runtime configuration passed from the CLI layer.
pub struct Config {
    pub interface: String,
    pub noudp: bool,
}

/// Main runtime loop. Never returns under normal operation.
pub fn run(config: Config) -> ! {
    let mut cap: capture::Capture = capture::Capture::open(&config.interface)
        .unwrap_or_else(|e| panic!("{}", e));

    let ips: Vec<std::net::IpAddr> = cap.host_ips();
    println!("IP address of this device:{:?}", ips);
    let iface_owned: pnet::datalink::NetworkInterface = cap.interface().clone();

    loop {
        match cap.next_ethernet() {
            Ok(frame) => crate::handler::handle_ethernet_frame(
                &iface_owned,
                &frame,
                ips.clone(),
                config.noudp,
            ),
            Err(e) => panic!("{}", e),
        }
    }
}

pub mod capture;
pub mod handler;
pub mod model;
pub mod render;

/// Runtime configuration passed from the CLI layer.
pub struct Config {
    pub interface: String,
    pub noudp: bool,
    pub no_color: bool,
}

/// Main runtime loop. Returns error instead of panicking.
pub fn run(config: Config) -> anyhow::Result<()> {
    let mut cap: capture::Capture = capture::Capture::open(&config.interface)?;

    // Configure rendering
    let disable_color = config.no_color || std::env::var_os("NO_COLOR").is_some();
    crate::render::set_color_enabled(!disable_color);

    let ips_vec: Vec<std::net::IpAddr> = cap.host_ips();
    println!("IP address of this device:{:?}", ips_vec);
    let ips_set: std::collections::HashSet<std::net::IpAddr> = ips_vec.into_iter().collect();
    let ips = std::sync::Arc::new(ips_set);
    let iface_owned: pnet::datalink::NetworkInterface = cap.interface().clone();

    // Install Ctrl-C handler for graceful shutdown
    let terminate = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let t2 = std::sync::Arc::clone(&terminate);
    ctrlc::set_handler(move || {
        t2.store(true, std::sync::atomic::Ordering::SeqCst);
    })?;

    while !terminate.load(std::sync::atomic::Ordering::Relaxed) {
        if let Some(frame) = cap.next_ethernet()? {
            crate::handler::handle_ethernet_frame(
                &iface_owned,
                &frame,
                std::sync::Arc::clone(&ips),
                config.noudp,
            );
        }
    }
    Ok(())
}

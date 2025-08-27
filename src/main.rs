use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Name of the network interface
    #[arg(short, long, value_name = "NETWORK INTERFACE")]
    interface: String,
    /// Do not display UDP
    #[arg(long)]
    noudp: bool,
}

fn main() {
    let cli: Cli = Cli::parse();
    let config = packet_flow::Config {
        interface: cli.interface,
        noudp: cli.noudp,
    };

    packet_flow::run(config)
}

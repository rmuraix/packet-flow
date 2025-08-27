use clap::Parser;
use std::process::ExitCode;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Name of the network interface
    #[arg(short, long, value_name = "NETWORK INTERFACE")]
    interface: String,
    /// Do not display UDP
    #[arg(long)]
    noudp: bool,
    /// Disable ANSI colors in output (or set NO_COLOR)
    #[arg(long = "no-color")]
    no_color: bool,
}

fn main() -> ExitCode {
    let cli: Cli = Cli::parse();
    let config = packet_flow::Config {
        interface: cli.interface,
        noudp: cli.noudp,
        no_color: cli.no_color,
    };
    if let Err(err) = packet_flow::run(config) {
        eprintln!("packet-flow error: {:#}", err);
        return ExitCode::from(1);
    }
    // run() currently never returns; OK for future extensibility.
    ExitCode::SUCCESS
}

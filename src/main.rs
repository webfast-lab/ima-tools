use clap::Parser;
use ima_tools::{HashAlgorithm, ReplayOptions, replay_measurements};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Replay Linux IMA measurements and print the final PCR hash"
)]
struct Cli {
    /// PCR hash algorithm to use for extend operations.
    #[arg(long, default_value = "sha256", value_parser = parse_algorithm)]
    algo: HashAlgorithm,

    /// PCR index to replay.
    #[arg(long, default_value_t = 10)]
    pcr: u32,

    /// Only extend the first N matching measurement records.
    #[arg(long)]
    count: Option<usize>,

    /// Path to ascii_runtime_measurements, binary_runtime_measurements, or a saved copy.
    input: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let input = fs::read(&cli.input)?;
    let options = ReplayOptions {
        algorithm: cli.algo,
        pcr: cli.pcr,
        count: cli.count,
    };
    let hash = replay_measurements(&input, options)?;
    println!("{}", hex::encode(hash));
    Ok(())
}

fn parse_algorithm(value: &str) -> Result<HashAlgorithm, String> {
    value
        .parse::<HashAlgorithm>()
        .map_err(|error| error.to_string())
}

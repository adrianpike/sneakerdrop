use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sneakerdrop_sim::{Config, run};

#[derive(Parser)]
#[command(about = "Deterministic simulation harness for Sneakerdrop")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one scenario with one seed
    Run {
        #[arg(long, default_value = "chaos")]
        scenario: String,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Override the number of steps (hours)
        #[arg(long)]
        steps: Option<u64>,
        /// Print every event to stderr
        #[arg(long)]
        trace: bool,
    },
    /// Run scenarios across many seeds, reporting failures
    Sweep {
        /// Scenarios to run (default: all except soak)
        #[arg(long, value_delimiter = ',')]
        scenarios: Vec<String>,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = 20)]
        seeds: u64,
        /// Print each report, not only failures
        #[arg(long)]
        verbose: bool,
    },
    /// List scenarios
    List,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::List => {
            for s in Config::SCENARIOS {
                println!("{s}");
            }
            ExitCode::SUCCESS
        }
        Command::Run {
            scenario,
            seed,
            steps,
            trace,
        } => {
            let Some(mut cfg) = Config::scenario(&scenario, seed) else {
                eprintln!("unknown scenario {scenario}; try `list`");
                return ExitCode::FAILURE;
            };
            cfg.trace = trace;
            if let Some(s) = steps {
                cfg.steps = s;
            }
            let report = run(cfg);
            println!("{report}");
            if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::Sweep {
            scenarios,
            from,
            seeds,
            verbose,
        } => {
            let scenarios: Vec<String> = if scenarios.is_empty() {
                Config::SCENARIOS
                    .iter()
                    .filter(|s| **s != "soak")
                    .map(|s| s.to_string())
                    .collect()
            } else {
                scenarios
            };
            let mut failures = Vec::new();
            for name in &scenarios {
                let Some(_) = Config::scenario(name, 0) else {
                    eprintln!("unknown scenario {name}");
                    return ExitCode::FAILURE;
                };
                let (mut delivered, mut sent) = (0, 0);
                for seed in from..from + seeds {
                    let report = run(Config::scenario(name, seed).expect("checked"));
                    delivered += report.metrics.delivered;
                    sent += report.metrics.sealed_sent;
                    if verbose || !report.ok() {
                        println!("{report}");
                    }
                    if let Some(v) = report.violation {
                        failures.push(format!("{name} seed={seed}: {v}"));
                    }
                }
                println!("{name}: {seeds} seeds, {sent} sealed sent, {delivered} delivered");
            }
            if failures.is_empty() {
                println!("all {} runs passed", scenarios.len() as u64 * seeds);
                ExitCode::SUCCESS
            } else {
                println!("\n{} failure(s):", failures.len());
                for f in &failures {
                    println!("  {f}");
                }
                ExitCode::FAILURE
            }
        }
    }
}

//! depscope CLI — a small, dependency-supply-chain scanner for Cargo projects.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use depscope::{detect_risks, from_lockfile, sbom_json, summarize, Level, Risk};

#[derive(Parser)]
#[command(
    name = "depscope",
    version,
    about = "Scope your Rust dependency supply chain from Cargo.lock"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Summarize package counts grouped by source
    Scan {
        /// Path to Cargo.lock
        lockfile: PathBuf,
        /// Emit JSON instead of a human-readable summary
        #[arg(long)]
        json: bool,
    },
    /// List supply-chain risks detected in the lockfile
    Risks {
        /// Path to Cargo.lock
        lockfile: PathBuf,
        /// Emit JSON instead of a human-readable list
        #[arg(long)]
        json: bool,
    },
    /// Emit a minimal CycloneDX-style SBOM (JSON)
    Sbom {
        /// Path to Cargo.lock
        lockfile: PathBuf,
    },
    /// CI gate: exit non-zero if any High/Medium risk is found
    Check {
        /// Path to Cargo.lock
        lockfile: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("depscope: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Scan { lockfile, json } => {
            let pkgs = from_lockfile(&lockfile)?;
            let summary = summarize(&pkgs);
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "Scanned {} packages from {}",
                    summary.total,
                    lockfile.display()
                );
                for (k, v) in &summary.by_source {
                    println!("  {:<10} {}", k, v);
                }
            }
        }
        Commands::Risks { lockfile, json } => {
            let pkgs = from_lockfile(&lockfile)?;
            let risks = detect_risks(&pkgs);
            if json {
                println!("{}", serde_json::to_string_pretty(&risks)?);
            } else if risks.is_empty() {
                println!("No supply-chain risks detected.");
            } else {
                for r in &risks {
                    println!(
                        "[{}] {}@{} — {}",
                        level_str(r.level),
                        r.name,
                        r.version,
                        r.reason
                    );
                }
            }
        }
        Commands::Sbom { lockfile } => {
            let pkgs = from_lockfile(&lockfile)?;
            println!("{}", sbom_json(&pkgs)?);
        }
        Commands::Check { lockfile } => {
            let pkgs = from_lockfile(&lockfile)?;
            let risks = detect_risks(&pkgs);
            let flagged: Vec<&Risk> = risks
                .iter()
                .filter(|r| matches!(r.level, Level::High | Level::Medium))
                .collect();
            for r in &flagged {
                eprintln!(
                    "[{}] {}@{} — {}",
                    level_str(r.level),
                    r.name,
                    r.version,
                    r.reason
                );
            }
            if flagged.is_empty() {
                println!("depscope: clean (no High/Medium risks).");
                return Ok(());
            }
            eprintln!("depscope: {} High/Medium risk(s) found.", flagged.len());
            std::process::exit(2);
        }
    }
    Ok(())
}

fn level_str(l: Level) -> &'static str {
    match l {
        Level::Low => "LOW",
        Level::Medium => "MEDIUM",
        Level::High => "HIGH",
    }
}

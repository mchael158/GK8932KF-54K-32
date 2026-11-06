mod output;

use clap::{Parser, Subcommand};
use output::{print_hash_line, print_inventory_summary};
use sentinel_analyzer::{format_diff_report, format_verify_report};
use sentinel_inventory::{
    collect_snapshot, compare_snapshots, verify_snapshot, CollectOptions,
};
use sentinel_storage::{read_snapshot, write_snapshot};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "chronos-sentinel",
    version,
    about = "Inventory, integrity checks, and snapshot diff (CLI, Linux/Arch)"
)]
struct Cli {
    #[arg(long, global = true, help = "Pacman local database path")]
    pacman_db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Collect packages, binaries, and optional shared libraries
    Inventory {
        #[arg(short, long, help = "Write JSON snapshot to path")]
        output: Option<PathBuf>,
        #[arg(long, help = "Print JSON to stdout")]
        json: bool,
        #[arg(long, help = "BLAKE3 hash for each tracked artifact")]
        hash: bool,
        #[arg(long, help = "Scan /usr/lib for shared objects")]
        libs: bool,
        #[arg(long, help = "Synthetic snapshot for development")]
        demo: bool,
    },
    /// Compare two JSON snapshots
    Diff {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
        #[arg(long, help = "Print JSON to stdout")]
        json: bool,
        #[arg(long, help = "Detailed report on stderr (same as default today)")]
        verbose: bool,
    },
    /// Re-check snapshot hashes against files on disk
    Verify {
        #[arg(long, help = "Snapshot created with `inventory --hash`")]
        snapshot: PathBuf,
        #[arg(long, help = "Print JSON to stdout")]
        json: bool,
    },
    /// BLAKE3 for one or more paths
    Hash {
        paths: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Event agent (not implemented)
    Agent,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let pacman_db = cli
        .pacman_db
        .unwrap_or_else(|| CollectOptions::default().pacman_db);

    match cli.command {
        Commands::Inventory {
            output,
            json,
            hash,
            libs,
            demo,
        } => {
            let opts = CollectOptions {
                pacman_db,
                hash_executables: hash,
                scan_libraries: libs,
                demo,
                ..CollectOptions::default()
            };
            let snapshot = collect_snapshot(&opts).await?;

            if let Some(path) = &output {
                write_snapshot(path, &snapshot)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                print_inventory_summary(&snapshot, output.as_deref());
            }
        }
        Commands::Diff {
            before,
            after,
            json,
            verbose: _,
        } => {
            let older = read_snapshot(&before)?;
            let newer = read_snapshot(&after)?;
            let diff = compare_snapshots(&older, &newer);
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                eprint!(
                    "{}",
                    format_diff_report(
                        &before.display().to_string(),
                        &after.display().to_string(),
                        &diff
                    )
                );
            }
        }
        Commands::Verify { snapshot, json } => {
            let snap = read_snapshot(&snapshot)?;
            let findings = verify_snapshot(&snap);
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                eprint!("{}", format_verify_report(&findings));
            }
        }
        Commands::Hash { paths, json } => {
            if paths.is_empty() {
                eprintln!("provide at least one path");
                std::process::exit(2);
            }
            for path in paths {
                let hash = sentinel_integrity::hash_file_blake3(&path)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "path": path.display().to_string(),
                            "algorithm": "blake3",
                            "hex": hash.hex,
                        })
                    );
                } else {
                    print_hash_line(&path, &hash.hex);
                }
            }
        }
        Commands::Agent => {
            sentinel_agent::run_agent().await?;
        }
    }
    Ok(())
}

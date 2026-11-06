mod output;
mod state;

use clap::{Parser, Subcommand};
use output::{print_hash_line, print_inventory_summary};
use sentinel_analyzer::{format_diff_report, format_verify_report};
use sentinel_inventory::{
    collect_snapshot, compare_snapshots, count_problems, verify_snapshot, CollectOptions,
};
use sentinel_storage::{read_snapshot, write_snapshot};
use state::{
    baseline_missing_message, baseline_path, collect_opts, last_check_path, print_off_header,
    print_on_ok, print_status,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "chronos-sentinel",
    version,
    about = "ON/OFF integrity watch — Linux/Arch CLI",
    after_help = "Daily use:  on  → start baseline   |   off  → scan & report"
)]
struct Cli {
    #[arg(long, global = true, hide = true, help = "Pacman local database path")]
    pacman_db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Save baseline snapshot (.chronos/baseline.json)
    On {
        #[arg(long, help = "Synthetic snapshot (Windows / dev)")]
        demo: bool,
    },
    /// Scan now, diff against baseline, verify hashes
    Off {
        #[arg(long, help = "Synthetic snapshot (Windows / dev)")]
        demo: bool,
        #[arg(long, help = "JSON diff on stdout")]
        json: bool,
    },
    /// Show whether a baseline exists
    Status,
    /// Advanced: manual inventory export
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
    /// Advanced: compare two JSON files
    Diff {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Advanced: re-check hashes in a snapshot file
    Verify {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Advanced: BLAKE3 for paths
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
        Commands::On { demo } => {
            let snapshot = collect_snapshot(&collect_opts(pacman_db, demo)).await?;
            let path = baseline_path();
            write_snapshot(&path, &snapshot)?;
            print_on_ok(&path, snapshot.packages.len());
        }
        Commands::Off { demo, json } => {
            let base_path = baseline_path();
            if !base_path.exists() {
                eprintln!("{}", baseline_missing_message());
                std::process::exit(2);
            }
            print_off_header();
            let baseline = read_snapshot(&base_path)?;
            let current = collect_snapshot(&collect_opts(pacman_db, demo)).await?;
            let check_path = last_check_path();
            write_snapshot(&check_path, &current)?;

            let diff = compare_snapshots(&baseline, &current);
            let findings = verify_snapshot(&current);

            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "baseline": base_path.display().to_string(),
                        "current": check_path.display().to_string(),
                        "diff": diff,
                        "verify": findings,
                    })
                );
            } else {
                eprint!(
                    "{}",
                    format_diff_report(
                        &base_path.display().to_string(),
                        &check_path.display().to_string(),
                        &diff,
                    )
                );
                eprint!("{}", format_verify_report(&findings));
            }

            let dirty = !diff.packages_changed.is_empty()
                || !diff.executables_hash_changed.is_empty()
                || !diff.orphans_added.is_empty()
                || count_problems(&findings) > 0;
            if dirty && !demo {
                std::process::exit(1);
            }
        }
        Commands::Status => {
            let path = baseline_path();
            if path.exists() {
                let snap = read_snapshot(&path)?;
                print_status(true, &path, Some(&snap.collected_at.to_string()));
            } else {
                print_status(false, &path, None);
            }
        }
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
        Commands::Diff { before, after, json } => {
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
                        &diff,
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

mod guide;
mod output;
mod state;

use clap::{Parser, Subcommand};
use output::{print_hash_line, print_inventory_summary};
use sentinel_analyzer::{format_diff_report, format_verify_report};
use sentinel_inventory::{collect_snapshot, compare_snapshots, verify_snapshot, CollectOptions, PacmanFilesScope};
use sentinel_storage::{read_snapshot, write_snapshot};
use guide::{print_quickstart, require_demo_on_host};
use state::{baseline_missing_message, baseline_path, print_off_header, state_dir};
use std::collections::HashSet;
use std::path::PathBuf;
use sentinel_agent::MitigationPolicy;

fn mitigation_policy(
    mitigate: bool,
    dry_run: bool,
    confirm: bool,
    allow_pids: &[u32],
    allow_comm: &[String],
) -> MitigationPolicy {
    MitigationPolicy {
        dry_run: dry_run || (mitigate && !confirm),
        confirmed: confirm,
        allow_pids: allow_pids.iter().copied().collect::<HashSet<_>>(),
        allow_comm: allow_comm.to_vec(),
    }
}

fn brain_opts(
    pacman_db: PathBuf,
    demo: bool,
    mitigate: bool,
    json: bool,
    quiet: bool,
    files_scope: PacmanFilesScope,
    state_dir: PathBuf,
    mitigation_policy: MitigationPolicy,
) -> sentinel_agent::BrainOptions {
    sentinel_agent::BrainOptions {
        pacman_db,
        demo,
        mitigate,
        json,
        quiet,
        files_scope,
        state_dir,
        mitigation_policy,
    }
}

async fn run_brain(
    op: sentinel_agent::OpCode,
    pacman_db: PathBuf,
    demo: bool,
    mitigate: bool,
    json: bool,
    quiet: bool,
    files_scope: PacmanFilesScope,
    state_dir: PathBuf,
    mitigation_policy: MitigationPolicy,
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    let result = sentinel_agent::brain::run(
        op,
        brain_opts(
            pacman_db,
            demo,
            mitigate,
            json,
            quiet,
            files_scope,
            state_dir,
            mitigation_policy,
        ),
    )
    .await?;
    Ok(result.exit_code)
}

#[derive(Parser)]
#[command(
    name = "chronos-sentinel",
    version,
    about = "pacman integrity baseline (Arch)",
    after_help = "Windows/dev:  chronos-sentinel try     |     -d = --demo = --dem"
)]
struct Cli {
    #[arg(long, short = 'v', global = true, help = "show Byteflow audit: lines on stderr")]
    verbose: bool,

    #[arg(long, global = true, hide = true, help = "Pacman local database path")]
    pacman_db: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Track every %FILES% path (default: usr/bin, usr/lib, etc/ssh, … prefixes only)"
    )]
    full_files: bool,

    #[arg(
        long,
        global = true,
        help = "Override state directory (else CHRONOS_STATE_DIR, XDG, or .chronos/)"
    )]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Synthetic end-to-end run: on → status → off (uses -d)
    Try {
        #[arg(long, help = "JSON on the final off step")]
        json: bool,
    },
    /// Save baseline (.chronos/baseline.json)
    On {
        #[arg(long, short = 'd', visible_alias = "dem", help = "demo snapshot (required off Linux)")]
        demo: bool,
    },
    /// Diff and verify against baseline
    Off {
        #[arg(long, short = 'd', visible_alias = "dem", help = "demo snapshot (required off Linux)")]
        demo: bool,
        #[arg(long, help = "JSON diff on stdout")]
        json: bool,
        #[arg(
            long,
            help = "Evaluate process mitigation for suspicious paths (Linux; dry-run unless --mitigate-confirm)"
        )]
        mitigate: bool,
        #[arg(long, help = "Only report PIDs that would be signaled (never kill)")]
        mitigate_dry_run: bool,
        #[arg(long, help = "Actually send SIGTERM after --mitigate (destructive)")]
        mitigate_confirm: bool,
        #[arg(long, value_name = "PID", action = clap::ArgAction::Append)]
        mitigate_allow_pid: Vec<u32>,
        #[arg(long, value_name = "COMM", action = clap::ArgAction::Append)]
        mitigate_allow_comm: Vec<String>,
    },
    /// Show baseline path / ON state
    Status,
    /// Export inventory JSON (add -d on Windows)
    Inventory {
        #[arg(short, long, help = "Write JSON snapshot to path")]
        output: Option<PathBuf>,
        #[arg(long, help = "Print JSON to stdout")]
        json: bool,
        #[arg(long, help = "BLAKE3 hash for each tracked artifact")]
        hash: bool,
        #[arg(long, help = "Scan /usr/lib for shared objects")]
        libs: bool,
        #[arg(long, short = 'd', visible_alias = "dem", help = "demo snapshot")]
        demo: bool,
    },
    Diff {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Verify {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Hash {
        paths: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Agent {
        #[arg(long, default_value_t = 300, help = "seconds between off scans")]
        interval: u64,
        #[arg(long, short = 'd', visible_alias = "dem", help = "demo snapshot")]
        demo: bool,
        #[arg(long, help = "Evaluate mitigation each scan (dry-run unless --mitigate-confirm)")]
        mitigate: bool,
        #[arg(long, help = "Only report PIDs that would be signaled")]
        mitigate_dry_run: bool,
        #[arg(long, help = "Actually send SIGTERM (destructive)")]
        mitigate_confirm: bool,
        #[arg(long, value_name = "PID", action = clap::ArgAction::Append)]
        mitigate_allow_pid: Vec<u32>,
        #[arg(long, value_name = "COMM", action = clap::ArgAction::Append)]
        mitigate_allow_comm: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let pacman_db = cli
        .pacman_db
        .unwrap_or_else(|| CollectOptions::default().pacman_db);

    let quiet = !cli.verbose;
    let files_scope = if cli.full_files {
        PacmanFilesScope::AllPackageFiles
    } else {
        PacmanFilesScope::IntegrityPrefixes
    };
    let resolved_state = state_dir(cli.state_dir.as_deref());
    let policy_none = mitigation_policy(false, false, false, &[], &[]);

    let Some(command) = cli.command else {
        print_quickstart();
        std::process::exit(0);
    };

    match command {
        Commands::Try { json } => {
            eprintln!("=== try: on (demo) ===");
            let code = run_brain(
                sentinel_agent::OpCode::On,
                pacman_db.clone(),
                true,
                false,
                false,
                false,
                files_scope,
                resolved_state.clone(),
                policy_none.clone(),
            )
            .await?;
            if code != 0 {
                std::process::exit(code);
            }
            eprintln!("=== try: status ===");
            run_brain(
                sentinel_agent::OpCode::Status,
                pacman_db.clone(),
                false,
                false,
                false,
                true,
                files_scope,
                resolved_state.clone(),
                policy_none.clone(),
            )
            .await?;
            eprintln!("=== try: off (demo) ===");
            if !json {
                print_off_header();
            }
            let code = run_brain(
                sentinel_agent::OpCode::Off,
                pacman_db,
                true,
                false,
                json,
                quiet,
                files_scope,
                resolved_state.clone(),
                policy_none.clone(),
            )
            .await?;
            std::process::exit(code);
        }
        Commands::On { demo } => {
            require_demo_on_host(demo, "on");
            let code = run_brain(
                sentinel_agent::OpCode::On,
                pacman_db,
                demo,
                false,
                false,
                quiet,
                files_scope,
                resolved_state.clone(),
                policy_none.clone(),
            )
            .await?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Off {
            demo,
            json,
            mitigate,
            mitigate_dry_run,
            mitigate_confirm,
            mitigate_allow_pid,
            mitigate_allow_comm,
        } => {
            require_demo_on_host(demo, "off");
            if !baseline_path(cli.state_dir.as_deref()).exists() {
                eprintln!("{}", baseline_missing_message(cli.state_dir.as_deref()));
                std::process::exit(2);
            }
            if !json {
                print_off_header();
            }
            let policy = mitigation_policy(
                mitigate,
                mitigate_dry_run,
                mitigate_confirm,
                &mitigate_allow_pid,
                &mitigate_allow_comm,
            );
            let code = run_brain(
                sentinel_agent::OpCode::Off,
                pacman_db,
                demo,
                mitigate,
                json,
                quiet,
                files_scope,
                resolved_state.clone(),
                policy,
            )
            .await?;
            std::process::exit(code);
        }
        Commands::Status => {
            let code = run_brain(
                sentinel_agent::OpCode::Status,
                pacman_db,
                false,
                false,
                false,
                quiet,
                files_scope,
                resolved_state.clone(),
                policy_none.clone(),
            )
            .await?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Inventory {
            output,
            json,
            hash,
            libs,
            demo,
        } => {
            require_demo_on_host(demo, "inventory");
            let opts = CollectOptions {
                pacman_db,
                hash_executables: hash,
                scan_libraries: libs,
                demo,
                files_scope,
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
        Commands::Agent {
            interval,
            demo,
            mitigate,
            mitigate_dry_run,
            mitigate_confirm,
            mitigate_allow_pid,
            mitigate_allow_comm,
        } => {
            let policy = mitigation_policy(
                mitigate,
                mitigate_dry_run,
                mitigate_confirm,
                &mitigate_allow_pid,
                &mitigate_allow_comm,
            );
            sentinel_agent::run_agent(
                brain_opts(
                    pacman_db,
                    demo,
                    mitigate,
                    false,
                    quiet,
                    files_scope,
                    resolved_state,
                    policy,
                ),
                interval,
            )
            .await?;
        }
    }
    Ok(())
}

mod cli;
mod completions;
mod guide;
mod log_json;
mod output;
mod state;

use cli::{Cli, Commands};
use clap::Parser;
use output::{print_hash_line, print_inventory_summary};
use sentinel_analyzer::{format_diff_report, format_verify_report};
use sentinel_inventory::{
    collect_snapshot, compare_snapshots, discover_config_path, load_merged_collect_options,
    verify_snapshot, CollectOptions, PacmanFilesScope,
};
use sentinel_storage::{read_snapshot, verify_snapshot_file, write_keypair, write_snapshot};
use guide::{print_quickstart, require_demo_on_host};
use state::{baseline_missing_message, baseline_path, print_off_header, state_dir};
use std::collections::HashSet;
use std::path::PathBuf;
use sentinel_agent::MitigationPolicy;

struct SigningCli {
    sign_baseline: bool,
    require_sign: bool,
    verify_baseline_sig: bool,
    require_signed_baseline: bool,
    signing_key_path: Option<PathBuf>,
}

fn signing_from_cli(cli: &Cli) -> SigningCli {
    SigningCli {
        sign_baseline: cli.sign && !cli.no_sign,
        require_sign: cli.require_sign,
        verify_baseline_sig: cli.verify_signature && !cli.no_verify_signature,
        require_signed_baseline: cli.require_signed_baseline,
        signing_key_path: cli.signing_key.clone(),
    }
}

fn default_keygen_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let p = xdg.trim();
        if !p.is_empty() {
            return PathBuf::from(p).join("chronos-sentinel");
        }
    }
    PathBuf::from(".chronos/keys")
}

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
    collect: &CollectOptions,
    demo: bool,
    mitigate: bool,
    json: bool,
    quiet: bool,
    state_dir: PathBuf,
    mitigation_policy: MitigationPolicy,
    log_json: bool,
    sign_baseline: bool,
    require_sign: bool,
    verify_baseline_sig: bool,
    require_signed_baseline: bool,
    signing_key_path: Option<PathBuf>,
) -> sentinel_agent::BrainOptions {
    sentinel_agent::BrainOptions {
        pacman_db: collect.pacman_db.clone(),
        demo,
        mitigate,
        json,
        quiet,
        files_scope: collect.files_scope,
        scan_roots: collect.scan_roots.clone(),
        lib_roots: collect.lib_roots.clone(),
        hash_executables: collect.hash_executables,
        scan_libraries: collect.scan_libraries,
        integrity_prefixes: collect.integrity_prefixes.clone(),
        state_dir,
        mitigation_policy,
        log_json,
        sign_baseline,
        require_sign,
        verify_baseline_sig,
        require_signed_baseline,
        signing_key_path,
    }
}

async fn run_brain(
    op: sentinel_agent::OpCode,
    collect: &CollectOptions,
    demo: bool,
    mitigate: bool,
    json: bool,
    quiet: bool,
    state_dir: PathBuf,
    mitigation_policy: MitigationPolicy,
    log_json: bool,
    signing: &SigningCli,
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    let result = sentinel_agent::brain::run(
        op,
        brain_opts(
            collect,
            demo,
            mitigate,
            json,
            quiet,
            state_dir,
            mitigation_policy,
            log_json,
            signing.sign_baseline,
            signing.require_sign,
            signing.verify_baseline_sig,
            signing.require_signed_baseline,
            signing.signing_key_path.clone(),
        ),
    )
    .await?;
    Ok(result.exit_code)
}

fn finish(log_json: bool, command: &str, code: i32) -> ! {
    if log_json {
        log_json::command_done(command, code);
    }
    std::process::exit(code);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    if let Some(Commands::Completions { shell }) = &cli.command {
        completions::print_completions(*shell)?;
        return Ok(());
    }
    if let Some(Commands::GenMan { output }) = &cli.command {
        if let Some(path) = output {
            completions::write_man_page(path)?;
        } else {
            completions::print_man_page()?;
        }
        return Ok(());
    }
    if let Some(Commands::Keygen { output_dir }) = &cli.command {
        let dir = output_dir.clone().unwrap_or_else(default_keygen_dir);
        let (secret, public) = write_keypair(&dir)?;
        eprintln!("Wrote signing key: {}", secret.display());
        eprintln!("Wrote public key:  {}", public.display());
        return Ok(());
    }
    if let Some(Commands::SignVerify { snapshot }) = &cli.command {
        let path = snapshot
            .clone()
            .unwrap_or_else(|| baseline_path(cli.state_dir.as_deref()));
        match verify_snapshot_file(&path).map_err(|e| std::io::Error::other(e))? {
            Some(_) => {
                eprintln!("Signature OK: {}", path.display());
                std::process::exit(0);
            }
            None => {
                eprintln!("No signature sidecar for {}", path.display());
                std::process::exit(2);
            }
        }
    }

    let log_json = log_json::enabled(cli.log_json);
    let signing = signing_from_cli(&cli);

    let mut collect = match load_merged_collect_options(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    if let Some(db) = &cli.pacman_db {
        collect.pacman_db = db.clone();
    }
    if cli.full_files {
        collect.files_scope = PacmanFilesScope::AllPackageFiles;
    }

    let quiet = !cli.verbose;
    let resolved_state = state_dir(cli.state_dir.as_deref());
    let policy_none = mitigation_policy(false, false, false, &[], &[]);

    if log_json {
        let discovered = discover_config_path();
        let cfg_path = cli.config.as_deref().or(discovered.as_deref());
        log_json::config_loaded(cfg_path);
    }

    let Some(command) = cli.command else {
        print_quickstart();
        std::process::exit(0);
    };

    if log_json {
        log_json::command_start(command.name());
    }

    match command {
        Commands::Try { json } => {
            eprintln!("=== try: on (demo) ===");
            let code = run_brain(
                sentinel_agent::OpCode::On,
                &collect,
                true,
                false,
                false,
                false,
                resolved_state.clone(),
                policy_none.clone(),
                log_json,
                &signing,
            )
            .await?;
            if code != 0 {
                finish(log_json, "try", code);
            }
            eprintln!("=== try: status ===");
            run_brain(
                sentinel_agent::OpCode::Status,
                &collect,
                false,
                false,
                false,
                true,
                resolved_state.clone(),
                policy_none.clone(),
                log_json,
                &signing,
            )
            .await?;
            eprintln!("=== try: off (demo) ===");
            if !json {
                print_off_header();
            }
            let code = run_brain(
                sentinel_agent::OpCode::Off,
                &collect,
                true,
                false,
                json,
                quiet,
                resolved_state.clone(),
                policy_none.clone(),
                log_json,
                &signing,
            )
            .await?;
            finish(log_json, "try", code);
        }
        Commands::On { demo } => {
            require_demo_on_host(demo, "on");
            let code = run_brain(
                sentinel_agent::OpCode::On,
                &collect,
                demo,
                false,
                false,
                quiet,
                resolved_state.clone(),
                policy_none.clone(),
                log_json,
                &signing,
            )
            .await?;
            if code != 0 {
                finish(log_json, "on", code);
            }
            if log_json {
                log_json::command_done("on", 0);
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
                &collect,
                demo,
                mitigate,
                json,
                quiet,
                resolved_state.clone(),
                policy,
                log_json,
                &signing,
            )
            .await?;
            finish(log_json, "off", code);
        }
        Commands::Status => {
            let code = run_brain(
                sentinel_agent::OpCode::Status,
                &collect,
                false,
                false,
                false,
                quiet,
                resolved_state.clone(),
                policy_none.clone(),
                log_json,
                &signing,
            )
            .await?;
            finish(log_json, "status", code);
        }
        Commands::Inventory {
            output,
            json,
            hash,
            libs,
            demo,
        } => {
            require_demo_on_host(demo, "inventory");
            let mut opts = collect.clone();
            opts.hash_executables = hash || opts.hash_executables;
            opts.scan_libraries = libs || opts.scan_libraries;
            opts.demo = demo;
            let snapshot = collect_snapshot(&opts).await?;
            if let Some(path) = &output {
                write_snapshot(path, &snapshot)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                print_inventory_summary(&snapshot, output.as_deref());
            }
            if log_json {
                log_json::command_done("inventory", 0);
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
                    &collect,
                    demo,
                    mitigate,
                    false,
                    quiet,
                    resolved_state,
                    policy,
                    log_json,
                    signing.sign_baseline,
                    signing.require_sign,
                    signing.verify_baseline_sig,
                    signing.require_signed_baseline,
                    signing.signing_key_path.clone(),
                ),
                interval,
            )
            .await?;
        }
        Commands::Completions { .. }
        | Commands::GenMan { .. }
        | Commands::Keygen { .. }
        | Commands::SignVerify { .. } => unreachable!(),
    }
    Ok(())
}

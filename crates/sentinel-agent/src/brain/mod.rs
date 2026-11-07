//! Byteflow sandbox entry: natives `sentinel_run`, `mitigate_pid`.

mod program;

use crate::byteflow_bridge::SentinelAuditSink;
use crate::mitigation::{self, MitigationAction};
use byteflow::{FlowOutcome, NativeTable, Runtime, RuntimeConfig, Value};
use program::brain_program;
use sentinel_analyzer::{format_diff_report, format_verify_report};
use sentinel_inventory::count_problems;
use sentinel_inventory::verify_snapshot_demo_aware;
use sentinel_inventory::{
    collect_snapshot, compare_snapshots, CollectOptions, PacmanFilesScope,
};
use sentinel_storage::{read_snapshot, write_snapshot};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Mutex as AsyncMutex;

static BRAIN_SERIAL: OnceLock<AsyncMutex<()>> = OnceLock::new();

pub use program::OpCode;

const NATIVE_SENTINEL_RUN: u32 = 8;
const NATIVE_MITIGATE_PID: u32 = 9;

#[derive(Debug, Clone)]
pub struct BrainOptions {
    pub pacman_db: PathBuf,
    pub demo: bool,
    pub mitigate: bool,
    pub json: bool,
    /// Suppress user-facing stderr and Byteflow audit lines (heartbeat / background).
    pub quiet: bool,
    /// Default [`PacmanFilesScope::IntegrityPrefixes`]; set [`PacmanFilesScope::AllPackageFiles`] for full `%FILES%`.
    pub files_scope: PacmanFilesScope,
}

#[derive(Debug, Default)]
pub struct BrainState {
    pub pacman_db: PathBuf,
    pub demo: bool,
    pub mitigate: bool,
    pub json: bool,
    pub quiet: bool,
    pub files_scope: PacmanFilesScope,
    pub baseline: PathBuf,
    pub last_check: PathBuf,
    pub mitigations: Mutex<Vec<MitigationAction>>,
    pub last_report: Mutex<String>,
}

impl BrainState {
    pub fn new(opts: &BrainOptions) -> Self {
        Self {
            pacman_db: opts.pacman_db.clone(),
            demo: opts.demo,
            mitigate: opts.mitigate,
            json: opts.json,
            quiet: opts.quiet,
            files_scope: opts.files_scope,
            baseline: PathBuf::from(".chronos/baseline.json"),
            last_check: PathBuf::from(".chronos/last-check.json"),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct BrainResult {
    pub exit_code: i32,
    pub report: String,
    pub mitigations: Vec<MitigationAction>,
}

pub async fn run(
    op: OpCode,
    opts: BrainOptions,
) -> Result<BrainResult, Box<dyn std::error::Error + Send + Sync>> {
    let serial = BRAIN_SERIAL.get_or_init(|| AsyncMutex::new(()));
    let _guard = serial.lock().await;

    let state = Arc::new(BrainState::new(&opts));
    let audit = Arc::new(SentinelAuditSink::new());
    let table = sentinel_native_table(Arc::clone(&state))?;

    let mut config = RuntimeConfig::sandbox();
    config.workers = 2;
    config.security_audit = Some(audit.clone());

    let rt = Runtime::with_natives_and_config(brain_program(), table, config)?;

    let handle = rt.spawn(0, &[Value::Int(op as i64)])?;
    let outcome = handle.join();
    rt.shutdown();

    let report = state.last_report.lock().expect("report").clone();
    let mitigations = state.mitigations.lock().expect("mitigations").clone();

    let exit_code = match outcome {
        FlowOutcome::Completed(Value::Int(code)) => code as i32,
        FlowOutcome::Completed(_) => 0,
        FlowOutcome::Failed(msg) => return Err(format!("brain flow failed: {msg}").into()),
    };

    for line in audit.drain_lines() {
        if !opts.quiet {
            eprintln!("audit: {line}");
        }
    }

    Ok(BrainResult {
        exit_code,
        report,
        mitigations,
    })
}

fn sentinel_native_table(
    state: Arc<BrainState>,
) -> Result<Arc<NativeTable>, Box<dyn std::error::Error + Send + Sync>> {
    let st_run = Arc::clone(&state);
    let st_mit = Arc::clone(&state);

    Ok(NativeTable::builder()
        .register_at(0, "print", |_| Ok(Value::Unit))?
        .register_at(NATIVE_SENTINEL_RUN, "sentinel_run", move |args| {
            let op = match args.first() {
                Some(Value::Int(n)) => OpCode::from_i64(*n),
                _ => {
                    return Err(byteflow::Fault::NativeError(
                        "sentinel_run: expected op int".into(),
                    ))
                }
            };
            let code = run_host_op(op, &st_run)?;
            Ok(Value::Int(code as i64))
        })?
        .register_at(NATIVE_MITIGATE_PID, "mitigate_pid", move |args| {
            let pid = match args.first() {
                Some(Value::Int(p)) if *p > 1 => *p as u32,
                _ => return Err(byteflow::Fault::NativeError("mitigate_pid: bad pid".into())),
            };
            let sig = match args.get(1) {
                Some(Value::Int(s)) => *s as i32,
                _ => 15,
            };
            mitigation::signal_pid(pid, sig).map_err(byteflow::Fault::NativeError)?;
            st_mit
                .mitigations
                .lock()
                .expect("mitigations")
                .push(MitigationAction {
                    pid,
                    signal: sig,
                    reason: "byteflow native mitigate_pid".into(),
                });
            Ok(Value::Int(1))
        })?
        .build())
}

fn run_host_op(op: OpCode, state: &BrainState) -> Result<i32, byteflow::Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| byteflow::Fault::NativeError(e.to_string()))?;

    rt.block_on(async { run_host_op_async(op, state).await })
        .map_err(byteflow::Fault::NativeError)
}

async fn run_host_op_async(op: OpCode, state: &BrainState) -> Result<i32, String> {
    let collect = CollectOptions {
        pacman_db: state.pacman_db.clone(),
        hash_executables: true,
        scan_libraries: true,
        demo: state.demo,
        files_scope: state.files_scope,
        ..CollectOptions::default()
    };

    match op {
        OpCode::On => {
            let snap = collect_snapshot(&collect)
                .await
                .map_err(|e| e.to_string())?;
            write_snapshot(&state.baseline, &snap).map_err(|e| e.to_string())?;
            let msg = format!(
                "ON baseline {} — {} packages, {} artifacts ({} hashed, {} missing on disk, {} %FILES% rows in scope [{}], {} orphans from bin scan)",
                state.baseline.display(),
                snap.packages.len(),
                snap.collection.artifacts_tracked,
                snap.collection.artifacts_hashed,
                snap.collection.artifacts_missing_on_disk,
                snap.collection.integrity_paths_in_db,
                snap.collection.integrity_scope,
                snap.collection.bin_scan_orphans,
            );
            *state.last_report.lock().expect("report") = msg.clone();
            if !state.quiet {
                eprintln!("{msg}");
            }
            Ok(0)
        }
        OpCode::Off => {
            if !state.baseline.exists() {
                let msg = "no baseline — run ON first";
                *state.last_report.lock().expect("report") = msg.into();
                if !state.quiet {
                    eprintln!("{msg}");
                }
                return Ok(2);
            }
            let baseline = read_snapshot(&state.baseline).map_err(|e| e.to_string())?;
            let current = collect_snapshot(&collect)
                .await
                .map_err(|e| e.to_string())?;
            write_snapshot(&state.last_check, &current).map_err(|e| e.to_string())?;
            let diff = compare_snapshots(&baseline, &current);
            let findings = verify_snapshot_demo_aware(&current, state.demo);
            let mut report = format_diff_report(
                &state.baseline.display().to_string(),
                &state.last_check.display().to_string(),
                &diff,
            );
            report.push_str(&format_verify_report(&findings));

            if state.mitigate {
                let suspicious: Vec<String> = diff
                    .executables_hash_changed
                    .iter()
                    .map(|h| h.path.clone())
                    .chain(diff.orphans_added.iter().map(|o| o.path.clone()))
                    .collect();
                if !suspicious.is_empty() {
                    let actions = mitigation::mitigate_paths(&suspicious, 15);
                    for a in &actions {
                        report.push_str(&format!(
                            "\nMITIGATED pid {} signal {} ({})",
                            a.pid, a.signal, a.reason
                        ));
                    }
                    *state.mitigations.lock().expect("mitigations") = actions;
                }
            }

            *state.last_report.lock().expect("report") = report.clone();
            if state.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "baseline": state.baseline.display().to_string(),
                        "current": state.last_check.display().to_string(),
                        "diff": diff,
                        "verify": findings,
                    })
                );
            } else {
                eprint!("{report}");
            }

            let dirty = !diff.packages_changed.is_empty()
                || !diff.executables_hash_changed.is_empty()
                || !diff.orphans_added.is_empty()
                || count_problems(&findings) > 0;
            Ok(if dirty && !state.demo { 1 } else { 0 })
        }
        OpCode::Status => {
            let msg = if state.baseline.exists() {
                format!("ON baseline at {}", state.baseline.display())
            } else {
                "OFF — no baseline".into()
            };
            *state.last_report.lock().expect("report") = msg.clone();
            if !state.quiet {
                eprintln!("{msg}");
            }
            Ok(0)
        }
    }
}

pub async fn run_daemon(
    opts: BrainOptions,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("brain daemon: OFF check every {interval_secs}s (Ctrl+C to stop)");
    loop {
        let result = run(OpCode::Off, opts.clone()).await?;
        if result.exit_code == 1 {
            eprintln!("brain: anomaly exit {}", result.exit_code);
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

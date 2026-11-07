use crate::completions::CompletionShell;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "chronos-sentinel",
    version,
    about = "pacman integrity baseline (Arch)",
    after_help = "Windows/dev:  chronos-sentinel try     |     -d = --demo = --dem"
)]
pub struct Cli {
    #[arg(long, short = 'v', global = true, help = "show Byteflow audit: lines on stderr")]
    pub verbose: bool,

    #[arg(
        long,
        global = true,
        help = "JSON log lines on stderr (or CHRONOS_LOG_JSON=1)"
    )]
    pub log_json: bool,

    #[arg(
        long,
        global = true,
        help = "Pacman local database (default: /var/lib/pacman/local on Linux)"
    )]
    pub pacman_db: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "TOML config (else CHRONOS_CONFIG, XDG, /etc/chronos-sentinel/config.toml)"
    )]
    pub config: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Track every %FILES% path (default: usr/bin, usr/lib, etc/ssh, … prefixes only)"
    )]
    pub full_files: bool,

    #[arg(
        long,
        global = true,
        help = "Override state directory (else CHRONOS_STATE_DIR, XDG, or .chronos/)"
    )]
    pub state_dir: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Ed25519 signing key JSON (else CHRONOS_SIGNING_KEY / XDG / /etc)"
    )]
    pub signing_key: Option<PathBuf>,

    #[arg(
        long,
        default_value_t = true,
        global = true,
        help = "Sign baseline on `on` when a key is present"
    )]
    pub sign: bool,

    #[arg(long, global = true, help = "Do not sign baseline on `on`")]
    pub no_sign: bool,

    #[arg(
        long,
        global = true,
        help = "Refuse `on` if baseline cannot be signed"
    )]
    pub require_sign: bool,

    #[arg(
        long,
        default_value_t = true,
        global = true,
        help = "Verify baseline.json.sig on `off` when present"
    )]
    pub verify_signature: bool,

    #[arg(long, global = true, help = "Skip signature verification on `off`")]
    pub no_verify_signature: bool,

    #[arg(
        long,
        global = true,
        help = "Refuse `off` if baseline has no signature sidecar"
    )]
    pub require_signed_baseline: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Synthetic end-to-end run: on → status → off (uses -d)
    Try {
        #[arg(long, help = "JSON on the final off step")]
        json: bool,
    },
    /// Save baseline (state dir/baseline.json)
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
    /// Print shell completion script to stdout
    Completions {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
    /// Write roff man page to stdout or --output
    GenMan {
        #[arg(short, long, help = "Write chronos-sentinel.1 instead of stdout")]
        output: Option<PathBuf>,
    },
    /// Create Ed25519 signing.key + signing.pub.json
    Keygen {
        #[arg(
            short,
            long,
            help = "Output directory (default: XDG config or .chronos/keys)"
        )]
        output_dir: Option<PathBuf>,
    },
    /// Verify baseline.json + .sig without running a full off scan
    SignVerify {
        #[arg(long, help = "Snapshot JSON (default: state dir/baseline.json)")]
        snapshot: Option<PathBuf>,
    },
}

impl Commands {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Try { .. } => "try",
            Self::On { .. } => "on",
            Self::Off { .. } => "off",
            Self::Status => "status",
            Self::Inventory { .. } => "inventory",
            Self::Diff { .. } => "diff",
            Self::Verify { .. } => "verify",
            Self::Hash { .. } => "hash",
            Self::Agent { .. } => "agent",
            Self::Completions { .. } => "completions",
            Self::GenMan { .. } => "gen-man",
            Self::Keygen { .. } => "keygen",
            Self::SignVerify { .. } => "sign-verify",
        }
    }
}

use clap::{Parser, Subcommand};
use sentinel_inventory::{collect_snapshot, compare_snapshots, CollectOptions};
use sentinel_storage::Store;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "chronos-sentinel", about = "Monitoramento comportamental e integridade (Linux/Arch)")]
struct Cli {
    #[arg(long, default_value = "chronos-sentinel.db")]
    database: PathBuf,

    #[arg(long)]
    pacman_db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fase 1: inventário de pacotes, executáveis e hashes
    Inventory {
        #[arg(long)]
        json: bool,
        #[arg(long, help = "Calcula BLAKE3 dos executáveis encontrados")]
        hash: bool,
        #[arg(long, help = "Snapshot sintético (dev / Windows)")]
        demo: bool,
    },
    /// Compara dois snapshots persistidos
    Diff {
        #[arg(long, help = "ID do snapshot mais antigo")]
        from: Option<i64>,
        #[arg(long, help = "ID do snapshot mais recente")]
        to: Option<i64>,
        #[arg(long)]
        json: bool,
    },
    /// Fase 2+: agente de eventos (placeholder)
    Agent,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Inventory { json, hash, demo } => {
            let opts = CollectOptions {
                pacman_db: cli
                    .pacman_db
                    .unwrap_or_else(|| CollectOptions::default().pacman_db),
                hash_executables: hash,
                demo,
                ..CollectOptions::default()
            };
            let snapshot = collect_snapshot(&opts).await?;
            let db_path = cli.database.to_string_lossy();
            let store = Store::open(&db_path)?;
            let id = store.save_inventory(&snapshot)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                eprintln!(
                    "Inventário: {} pacotes, {} executáveis, {} órfãos (snapshot #{id} → {})",
                    snapshot.packages.len(),
                    snapshot.tracked_executables.len(),
                    snapshot.orphan_executables.len(),
                    cli.database.display()
                );
            }
        }
        Commands::Diff { from, to, json } => {
            let db_path = cli.database.to_string_lossy();
            let store = Store::open(&db_path)?;
            let (to_id, after) = match to {
                Some(id) => store
                    .load_inventory(id)?
                    .map(|s| (id, s))
                    .ok_or_else(|| format!("snapshot #{id} não encontrado"))?,
                None => store
                    .latest_inventory()?
                    .ok_or("nenhum snapshot no banco — rode `inventory` primeiro")?,
            };
            let (from_id, before) = match from {
                Some(id) => store
                    .load_inventory(id)?
                    .map(|s| (id, s))
                    .ok_or_else(|| format!("snapshot #{id} não encontrado"))?,
                None => store
                    .previous_inventory(to_id)?
                    .ok_or("apenas um snapshot — rode `inventory` de novo ou use --from")?,
            };
            let diff = compare_snapshots(&before, &after);
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                eprintln!("Diff #{from_id} → #{to_id}:");
                eprintln!("  pacotes +{} -{} ~{}", diff.packages_added.len(), diff.packages_removed.len(), diff.packages_changed.len());
                eprintln!(
                    "  executáveis +{} -{} hash~{}",
                    diff.executables_added.len(),
                    diff.executables_removed.len(),
                    diff.executables_hash_changed.len()
                );
                eprintln!(
                    "  órfãos +{} -{}",
                    diff.orphans_added.len(),
                    diff.orphans_removed.len()
                );
            }
        }
        Commands::Agent => {
            sentinel_agent::run_agent().await?;
        }
    }
    Ok(())
}

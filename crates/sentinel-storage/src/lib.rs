mod error;

pub use error::StorageError;

use rusqlite::{params, Connection, OptionalExtension};
use sentinel_core::SentinelEvent;
use sentinel_inventory::InventorySnapshot;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS inventory_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                collected_at TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    pub fn save_inventory(&self, snapshot: &InventorySnapshot) -> Result<i64, StorageError> {
        let json = serde_json::to_string(snapshot)?;
        self.conn.execute(
            "INSERT INTO inventory_snapshots (collected_at, body_json) VALUES (?1, ?2)",
            params![snapshot.collected_at.to_string(), json],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn load_inventory(&self, id: i64) -> Result<Option<InventorySnapshot>, StorageError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT body_json FROM inventory_snapshots WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|j| serde_json::from_str(&j).map_err(StorageError::from))
            .transpose()
    }

    pub fn latest_inventory(&self) -> Result<Option<(i64, InventorySnapshot)>, StorageError> {
        let row: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT id, body_json FROM inventory_snapshots ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(id, json)| {
            serde_json::from_str(&json)
                .map(|snap| (id, snap))
                .map_err(StorageError::from)
        })
        .transpose()
    }

    pub fn previous_inventory(&self, before_id: i64) -> Result<Option<(i64, InventorySnapshot)>, StorageError> {
        let row: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT id, body_json FROM inventory_snapshots WHERE id < ?1 ORDER BY id DESC LIMIT 1",
                params![before_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(id, json)| {
            serde_json::from_str(&json)
                .map(|snap| (id, snap))
                .map_err(StorageError::from)
        })
        .transpose()
    }

    pub fn append_event(&self, event: &SentinelEvent) -> Result<(), StorageError> {
        let json = serde_json::to_string(event)?;
        let kind = match event {
            SentinelEvent::ProcessExec { .. } => "process_exec",
            SentinelEvent::ProcessExit { .. } => "process_exit",
            SentinelEvent::PackageTransaction { .. } => "package_transaction",
            SentinelEvent::FileIntegrityChange { .. } => "file_integrity_change",
        };
        let recorded_at = match event {
            SentinelEvent::ProcessExec { observation } => observation.started_at.to_string(),
            SentinelEvent::ProcessExit { .. } => time_now_string(),
            SentinelEvent::PackageTransaction { recorded_at, .. } => recorded_at.to_string(),
            SentinelEvent::FileIntegrityChange { recorded_at, .. } => recorded_at.to_string(),
        };
        self.conn.execute(
            "INSERT INTO events (recorded_at, kind, body_json) VALUES (?1, ?2, ?3)",
            params![recorded_at, kind, json],
        )?;
        Ok(())
    }
}

fn time_now_string() -> String {
    time::OffsetDateTime::now_utc().to_string()
}

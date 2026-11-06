//! Optional background Byteflow status loop (used when wired from `agent` helpers).

use crate::brain::{self, BrainOptions, OpCode};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::task::JoinHandle;

static HEARTBEAT: OnceLock<JoinHandle<()>> = OnceLock::new();

const HEARTBEAT_SECS: u64 = 60;

#[allow(dead_code)]
pub fn ensure_heartbeat(mut opts: BrainOptions) {
    opts.quiet = true;
    let _ = HEARTBEAT.get_or_init(|| {
        tokio::spawn(async move {
            loop {
                if let Err(e) = brain::run(OpCode::Status, opts.clone()).await {
                    eprintln!("byteflow heartbeat: {e}");
                }
                tokio::time::sleep(Duration::from_secs(HEARTBEAT_SECS)).await;
            }
        })
    });
}

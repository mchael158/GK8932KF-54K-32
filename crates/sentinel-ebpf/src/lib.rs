//! eBPF hooks (Aya). Linux only.

#[cfg(target_os = "linux")]
pub const SUPPORTED: bool = true;

#[cfg(not(target_os = "linux"))]
pub const SUPPORTED: bool = false;

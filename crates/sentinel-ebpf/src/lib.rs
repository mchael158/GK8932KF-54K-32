//! Phase 2: execve, clone, exit hooks via Aya.
//!
//! Cross-compilation and loading require a Linux kernel and eBPF toolchain.

#[cfg(target_os = "linux")]
pub const SUPPORTED: bool = true;

#[cfg(not(target_os = "linux"))]
pub const SUPPORTED: bool = false;

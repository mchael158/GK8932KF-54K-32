//! Fase 2: hooks execve, clone, exit via Aya.
//!
//! Compilação cruzada e carregamento exigem kernel Linux e toolchain eBPF.

#[cfg(target_os = "linux")]
pub const SUPPORTED: bool = true;

#[cfg(not(target_os = "linux"))]
pub const SUPPORTED: bool = false;

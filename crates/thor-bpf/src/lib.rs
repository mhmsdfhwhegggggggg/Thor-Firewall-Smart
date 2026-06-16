//! Thor eBPF Programs
//! Compiled with target: bpfel-unknown-none (kernel-space)
//! Loader code (user-space Rust) is gated on #[cfg(not(target_arch = "bpf"))]

#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
use core::panic::PanicInfo;
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }

// User-space loader modules
#[cfg(not(target_arch = "bpf"))]
pub mod xdp_drop;
#[cfg(not(target_arch = "bpf"))]
pub mod process_monitor;
#[cfg(not(target_arch = "bpf"))]
pub mod network_correlator;
#[cfg(not(target_arch = "bpf"))]
pub mod fim_monitor;

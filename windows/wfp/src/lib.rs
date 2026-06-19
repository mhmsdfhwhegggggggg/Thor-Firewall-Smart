//! Thor Windows Filtering Platform (WFP) — Network Driver Stub
//!
//! # Phase 2 Roadmap: Windows XDR Support
//!
//! This stub documents the architecture for the Windows kernel-mode
//! network filter that mirrors the Linux XDP/eBPF fast-path.
//!
//! ## Architecture Decision
//!
//! We use **Windows Filtering Platform (WFP)** rather than NDIS LWF for the
//! initial Windows implementation because:
//! - WFP runs at IRQL PASSIVE_LEVEL (safer for initial development)
//! - Exposes layered callout model (ALE, Stream, Datagram, Packet)
//! - Native support in Windows 7 and later (broad compatibility)
//! - Microsoft's recommended approach for security software
//!
//! Long-term, we plan to add the `ebpf-for-windows` project as an optional
//! backend so the same eBPF programs (`.bpf.c`) can run on Windows natively.
//!
//! ## WFP Callout Registration Flow
//!
//! ```
//! DriverEntry()
//!   └── FwpmEngineOpen0()          // open filter engine
//!         ├── FwpmSubLayerAdd0()   // register Thor sub-layer
//!         ├── FwpmCalloutAdd0()    // register classify / notify callbacks
//!         └── FwpmFilterAdd0()     // install the actual filter rule
//! ```
//!
//! ## Key WFP Layers Used
//!
//! | WFP Layer | Purpose |
//! |---|---|
//! | `FWPM_LAYER_INBOUND_IPPACKET_V4` | Drop inbound packets by IP (like XDP_DROP) |
//! | `FWPM_LAYER_OUTBOUND_IPPACKET_V4` | Block data exfiltration |
//! | `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` | Track connection flows |
//! | `FWPM_LAYER_STREAM_V4` | Deep packet inspection at TCP stream level |
//!
//! ## Next Steps (to implement)
//!
//! 1. Set up a Windows Driver Kit (WDK) build environment
//! 2. Create a kernel-mode driver project (`thor-wfp.sys`)
//! 3. Implement `DriverEntry` + `DriverUnload`
//! 4. Register WFP callout for `FWPM_LAYER_INBOUND_IPPACKET_V4`
//! 5. Implement blocklist sync from Control Plane via named pipe or IOCTL
//! 6. Get WHQL code signing certificate
//!
//! ## Communication with Thor Control Plane
//!
//! The Windows WFP driver will use a **kernel-mode named pipe** to receive
//! real-time blocklist updates from the Thor Windows Agent (user-space process).
//! The user-space agent connects to the Thor SOC Control Plane via the same
//! mTLS protocol used by Linux agents (`thor-common/crypto.rs`).
//!
//! ```
//! Control Plane (mTLS) → thor-agent-win.exe → named pipe → thor-wfp.sys
//!                                 ↓
//!                         UnifiedThorEvent (Windows EDR events)
//!                                 ↑
//!                         WFP callout callbacks
//! ```

/// Placeholder to make this a valid Rust crate.
///
/// The actual WFP implementation requires the Windows Driver Kit (WDK)
/// and must be compiled with MSVC on a Windows build host.
/// The Rust bindings are provided by the `windows-drivers-rs` project:
/// https://github.com/microsoft/windows-drivers-rs
pub fn wfp_not_yet_implemented() {
    // This function exists only to satisfy the Rust compiler.
    // See module-level doc comment for the WFP implementation roadmap.
    unimplemented!("WFP driver implementation — Phase 2 (Windows XDR)")
}

/// Simulated WFP filter condition structure (for documentation purposes).
///
/// In the real kernel driver this maps to `FWPM_FILTER_CONDITION0`.
#[derive(Debug, Clone)]
pub struct WfpFilterCondition {
    /// Layer field key (e.g. `FWPM_CONDITION_IP_REMOTE_ADDRESS`)
    pub field_key: [u8; 16], // GUID
    /// Match type (equal, not-equal, range, flags-all-set…)
    pub match_type: u32,
    /// The value to match against
    pub condition_value: WfpConditionValue,
}

/// Discriminated union matching `FWP_CONDITION_VALUE0`.
#[derive(Debug, Clone)]
pub enum WfpConditionValue {
    Uint32(u32),
    Uint64(u64),
    /// IPv4 address (network byte order)
    Ipv4Addr(u32),
    /// IPv4 address range
    Ipv4Range { start: u32, end: u32 },
}

/// Describes a complete WFP filter (maps to `FWPM_FILTER0`).
#[derive(Debug, Clone)]
pub struct WfpFilter {
    pub display_name:  String,
    pub layer_key:     [u8; 16], // GUID of the target layer
    pub action:        WfpAction,
    pub conditions:    Vec<WfpFilterCondition>,
    pub weight:        u64,
}

/// WFP filter action type (maps to `FWP_ACTION_TYPE`).
#[derive(Debug, Clone, PartialEq)]
pub enum WfpAction {
    /// Pass the packet through (FWP_ACTION_PERMIT)
    Permit,
    /// Drop the packet (FWP_ACTION_BLOCK)
    Block,
    /// Route to user-space callout for deep inspection
    CalloutInspect,
}

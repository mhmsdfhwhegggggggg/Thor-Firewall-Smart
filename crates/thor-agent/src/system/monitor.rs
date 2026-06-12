use sysinfo::{System, SystemExt};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

pub static DEGRADED_MODE: AtomicBool = AtomicBool::new(false);

pub fn monitor_resources() {
    let mut sys = System::new_all();
    
    loop {
        sys.refresh_system();
        
        // If agent exceeds 80% of allowed memory limit (e.g. 200MB) or if load is extremely high
        let used_mem = sys.used_memory() / 1024 / 1024; // MB
        
        if used_mem > 200 {
            if !DEGRADED_MODE.load(Ordering::Relaxed) {
                warn!("⚠️ Resource pressure detected. Activating DEGRADED MODE.");
                DEGRADED_MODE.store(true, Ordering::Relaxed);
                
                // Emergency protocols:
                // 1. Pause L7 WAF scanning
                // 2. Pause LLM reporting
                // 3. Keep only XDP Drop and IOC Check (lightest and fastest operations)
            }
        } else {
            if DEGRADED_MODE.load(Ordering::Relaxed) {
                warn!("✅ Resources normalized. Exiting DEGRADED MODE.");
                DEGRADED_MODE.store(false, Ordering::Relaxed);
            }
        }
        
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

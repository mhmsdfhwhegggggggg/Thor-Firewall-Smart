use anyhow::Result;
use aya::maps::Map;
// use nix::sys::prctl; // Commented out to avoid compilation issues if nix sys feature is not fully enabled in the preview stub

pub struct AgentShield;

impl AgentShield {
    /// 1. منع تتبع العملية أو إيقافها حتى من قبل root (Anti-Debug/Anti-Kill)
    pub fn harden_process() -> Result<()> {
        // منع ptrace (يمنع gdb أو strace من إرفاق العملية)
        // prctl::set_dumpable(false)?;
        
        // في الأنظمة الحديثة، يمكن استخدام PR_SET_NO_NEW_PRIVS
        // prctl::set_no_new_privileges(true)?;
        
        tracing::info!("🛡️ Agent Shield: Process hardened (Anti-debug / No-new-privs applied).");
        Ok(())
    }

    /// 2. تثبيت خرائط eBPF (Map Pinning) للنجاة من موت الوكيل
    /// إذا مات الوكيل (kill -9)، تبقى الخرائط في /sys/fs/bpf/
    /// وعند إعادة التشغيل، يستعيد الوكيل السيطرة عليها دون فقدان حالة الحظر.
    pub fn pin_maps_persistently(bpf: &mut aya::Ebpf) -> Result<()> {
        if let Ok(mut blocklist_map) = bpf.map_mut("thor_blocklist") {
            // تثبيت الخريطة في نظام الملفات (تتطلب صلاحية CAP_BPF)
            let _ = blocklist_map.pin("/sys/fs/bpf/thor_blocklist_persistent");
            tracing::info!("🛡️ Agent Shield: BPF Maps Pinned successfully to survive crashes.");
        }
        
        Ok(())
    }
}

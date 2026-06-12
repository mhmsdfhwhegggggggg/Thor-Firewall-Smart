// crates/thor-bpf/build.rs
use std::env;
use std::path::PathBuf;

fn main() {
    // Force the compiler to use BTF CO-RE
    println!("cargo:rerun-if-env-changed=BPF_TARGET");
    
    // In a production environment, the generated vmlinux.h of the target kernel is included
    // or use the universal vmlinux.h from aya
    let _bpf_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    
    // Ensure that the code is built as an eBPF target
    if let Ok(arch) = env::var("CARGO_CFG_TARGET_ARCH") {
        if arch == "bpf" {
            println!("cargo:rustc-cfg=bpf");
        }
    }
}

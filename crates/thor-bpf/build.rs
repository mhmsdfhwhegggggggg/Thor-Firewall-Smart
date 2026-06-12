//! Thor BPF build script — compiles .bpf.c files with clang and generates Rust bindings
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let src_dir = PathBuf::from("src");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let include_dir = PathBuf::from("include");

    let bpf_files = ["xdp_drop", "process_monitor", "network_correlator"];

    for prog in &bpf_files {
        let c_file = src_dir.join(format!("{}.bpf.c", prog));
        let o_file = out_dir.join(format!("{}.bpf.o", prog));

        println!("cargo:rerun-if-changed={}", c_file.display());

        let status = Command::new("clang")
            .args([
                "-O2", "-g", "-target", "bpf",
                "-D__TARGET_ARCH_x86",
                "-mcpu=v3",
                "-I", include_dir.to_str().unwrap(),
                "-I", "/usr/include",
                "-I", "/usr/local/include",
                "-Wno-unused-value", "-Wno-pointer-sign",
                "-Wno-compare-distinct-pointer-types",
                "-c", c_file.to_str().unwrap(),
                "-o", o_file.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to execute clang — install with: apt install clang");

        if !status.success() {
            panic!("Failed to compile BPF program: {}", c_file.display());
        }

        // Generate Rust skeleton using aya-gen
        let skel_file = out_dir.join(format!("{}_skel.rs", prog));
        let _gen_result = Command::new("bpftool")
            .args(["gen", "skeleton", o_file.to_str().unwrap()])
            .output();
    }

    println!("cargo:rerun-if-changed=include/common.h");
}

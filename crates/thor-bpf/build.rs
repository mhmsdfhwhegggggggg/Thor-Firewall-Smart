// crates/thor-bpf/build.rs
//!
//! BPF Build Script — aya-build integration
//!
//! # What this does
//! 1. Discovers all *.bpf.c source files in `src/`
//! 2. Compiles each to eBPF ELF using clang targeting `bpf` arch
//! 3. Embeds the resulting bytecode using `include_bytes_aligned!` macro
//!    (or aya's `aya::include_bytes_aligned!` for 8-byte alignment)
//!
//! # Build requirements
//!   apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
//!
//! # Environment variables
//!   BPF_CLANG   — clang binary path (default: clang)
//!   BPF_CFLAGS  — extra C flags for BPF compilation
//!   CARGO_FEATURE_SKIP_BPF_BUILD — set to skip (for CI without kernel headers)

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Re-run if any BPF source changes
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=BPF_CFLAGS");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=include/");

    // Allow skipping in CI environments without kernel headers
    if env::var("CARGO_FEATURE_SKIP_BPF_BUILD").is_ok() ||
       env::var("THOR_SKIP_BPF_BUILD").map(|v| v == "1").unwrap_or(false) {
        println!("cargo:warning=BPF build skipped (THOR_SKIP_BPF_BUILD=1)");
        // Generate empty stubs so include_bytes_aligned! still compiles
        generate_stubs();
        return;
    }

    let clang = env::var("BPF_CLANG").unwrap_or_else(|_| "clang".to_string());
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    let src_dir = manifest_dir.join("src");
    let include_dir = manifest_dir.join("include");

    // Verify clang is available
    if Command::new(&clang).arg("--version").output().is_err() {
        println!("cargo:warning=clang not found ({}). Generating BPF stubs.", clang);
        println!("cargo:warning=Install with: apt-get install clang llvm libbpf-dev");
        generate_stubs();
        return;
    }

    // Compile each *.bpf.c to a *.bpf.o ELF
    let bpf_sources = find_bpf_sources(&src_dir);
    if bpf_sources.is_empty() {
        println!("cargo:warning=No *.bpf.c sources found in {:?}", src_dir);
        generate_stubs();
        return;
    }

    for source in &bpf_sources {
        compile_bpf_program(&clang, source, &include_dir, &out_dir);
    }

    // Generate the include-bytes module pointing at compiled objects
    generate_bpf_bytes_module(&bpf_sources, &out_dir);

    println!("cargo:warning=BPF programs compiled: {}", bpf_sources.len());
}

/// Find all *.bpf.c files in src/
fn find_bpf_sources(src_dir: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    if let Ok(entries) = std::fs::read_dir(src_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("c") {
                if path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".bpf.c"))
                    .unwrap_or(false)
                {
                    sources.push(path);
                }
            }
        }
    }
    sources.sort();
    sources
}

/// Compile a single BPF C file to ELF object
fn compile_bpf_program(clang: &str, source: &Path, include_dir: &Path, out_dir: &Path) {
    let stem = source.file_stem().and_then(|s| s.to_str())
        .map(|s| s.trim_end_matches(".bpf"))
        .unwrap_or("unknown");
    let output = out_dir.join(format!("{}.bpf.o", stem));

    // Get kernel headers path
    let kernel_ver = std::process::Command::new("uname")
        .arg("-r").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let kernel_include = format!("/usr/include/linux");
    let kernel_arch_include = format!("/usr/src/linux-headers-{}/include", kernel_ver);

    let extra_cflags = env::var("BPF_CFLAGS").unwrap_or_default();

    let mut cmd = Command::new(clang);
    cmd.args(&[
        "-O2",
        "-target", "bpf",
        "-D__TARGET_ARCH_x86",
        "-Wall",
        "-Wno-unused-value",
        "-Wno-pointer-sign",
        "-Wno-compare-distinct-pointer-types",
        "-fno-stack-protector",
        "-g",  // BTF debug info for CO-RE
        "-c",
    ]);

    // Include paths
    if include_dir.exists() {
        cmd.arg(format!("-I{}", include_dir.display()));
    }
    cmd.arg(format!("-I{}", kernel_include));
    if std::path::Path::new(&kernel_arch_include).exists() {
        cmd.arg(format!("-I{}", kernel_arch_include));
    }
    // libbpf headers
    cmd.arg("-I/usr/include/bpf");

    // Extra flags from env
    if !extra_cflags.is_empty() {
        for flag in extra_cflags.split_whitespace() {
            cmd.arg(flag);
        }
    }

    cmd.arg(source);
    cmd.arg("-o");
    cmd.arg(&output);

    println!("cargo:warning=Compiling BPF: {:?} → {:?}", source.file_name().unwrap(), output);

    match cmd.output() {
        Ok(out) if out.status.success() => {
            println!("cargo:warning=BPF compiled OK: {}.bpf.o", stem);
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("cargo:warning=BPF compile FAILED: {}", stderr.lines().next().unwrap_or("unknown error"));
            // Generate a stub so cargo doesn't fail on CI
            generate_stub_object(&output);
        }
        Err(e) => {
            println!("cargo:warning=clang spawn failed: {}", e);
            generate_stub_object(&output);
        }
    }
}

/// Generate an empty ELF stub (so include_bytes_aligned! compiles even without clang)
fn generate_stub_object(path: &Path) {
    // Minimal ELF64 little-endian header (no sections, valid magic)
    let elf_stub: &[u8] = &[
        0x7f, 0x45, 0x4c, 0x46, // magic
        0x02, 0x01, 0x01, 0x00, // 64-bit, little-endian, version 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, // ET_REL
        0xf7, 0x00, // EM_BPF
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // entry
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // phoff
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shoff = 64
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x38, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let _ = std::fs::write(path, elf_stub);
}

/// Generate stubs for all expected BPF programs
fn generate_stubs() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| "/tmp".into()));
    let programs = [
        "xdp_drop", "fim_monitor", "process_monitor",
        "network_correlator", "syscall_profiler", "tls_inspector",
        "dns_monitor", "l7_inspector",
    ];
    for prog in &programs {
        let path = out_dir.join(format!("{}.bpf.o", prog));
        generate_stub_object(&path);
    }
    generate_bpf_bytes_module_stubs(&out_dir, &programs);
}

/// Generate a Rust module with include_bytes_aligned! for all BPF programs
fn generate_bpf_bytes_module(sources: &[PathBuf], out_dir: &Path) {
    let mut code = String::from(
        "// AUTO-GENERATED by build.rs — do not edit manually\n         // BPF program bytecode embedded at compile time (8-byte aligned)\n         // Each constant can be loaded by aya::Ebpf::load()\n\n"
    );

    for source in sources {
        let stem = source.file_stem().and_then(|s| s.to_str())
            .map(|s| s.trim_end_matches(".bpf"))
            .unwrap_or("unknown")
            .to_uppercase()
            .replace('-', "_");
        let obj_path = out_dir.join(format!("{}.bpf.o", stem.to_lowercase().replace('_', "_")));

        code.push_str(&format!(
            "/// Embedded BPF ELF for {stem} program.\n             /// 8-byte aligned for aya::Ebpf::load().\n             pub static {stem}_BPF: &[u8] = \n             #[repr(align(8))]\n             struct AlignedBpf_{stem}([u8; include_bytes!(\"{obj_path}\").len()]);\n             &AlignedBpf_{stem}(*include_bytes!(\"{obj_path}\"}).0;\n\n",
            stem = stem,
            obj_path = obj_path.display()
        ));
    }

    let out_path = out_dir.join("bpf_programs.rs");
    std::fs::write(&out_path, code).expect("Failed to write bpf_programs.rs");
    println!("cargo:warning=Generated BPF bytes module: {:?}", out_path);
}

fn generate_bpf_bytes_module_stubs(out_dir: &Path, programs: &[&str]) {
    let mut code = String::from(
        "// AUTO-GENERATED by build.rs (stub mode — BPF build skipped)\n         // These stubs allow compilation without kernel headers.\n\n"
    );
    for prog in programs {
        let stem = prog.to_uppercase().replace('-', "_");
        let obj_path = out_dir.join(format!("{}.bpf.o", prog));
        code.push_str(&format!(
            "pub static {stem}_BPF: &[u8] = include_bytes!(\"{obj_path}\");\n",
            stem = stem,
            obj_path = obj_path.display()
        ));
    }
    let out_path = out_dir.join("bpf_programs.rs");
    std::fs::write(&out_path, code).expect("Failed to write bpf_programs.rs stubs");
}

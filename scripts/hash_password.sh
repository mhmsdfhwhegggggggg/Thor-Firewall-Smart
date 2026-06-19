#!/usr/bin/env bash
# scripts/hash_password.sh — Generate Argon2id password hash for THOR_ADMIN_PASSWORD_HASH
#
# Usage: bash scripts/hash_password.sh [password]
#        If no password given, prompts interactively (no echo)
#
# Output: PHC string to set in THOR_ADMIN_PASSWORD_HASH env var
#
# Example:
#   export THOR_ADMIN_PASSWORD_HASH=$(bash scripts/hash_password.sh mySecret123)
#   # Or in .env file:
#   THOR_ADMIN_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$...

set -euo pipefail

# Check for Python (faster) or Rust fallback
if command -v python3 &>/dev/null; then
    if python3 -c "import argon2" 2>/dev/null; then
        # Use argon2-cffi (pip install argon2-cffi)
        if [ -n "${1:-}" ]; then
            python3 -c "
import argon2, sys
ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
print(ph.hash(sys.argv[1]))
" "$1"
        else
            echo -n "Enter password (no echo): " >&2
            read -rs password
            echo >&2
            python3 -c "
import argon2
ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
import sys
print(ph.hash(sys.stdin.read().rstrip()))
" <<< "$password"
        fi
        exit 0
    fi
fi

# Fallback: use cargo if available
if command -v cargo &>/dev/null; then
    echo "argon2-cffi not installed, using cargo (slower)..." >&2
    echo "pip install argon2-cffi  # to fix this" >&2
    
    TMPDIR=$(mktemp -d)
    cat > "$TMPDIR/Cargo.toml" << 'CARGO'
[package]
name = "hash_pass"
version = "0.1.0"
edition = "2021"
[dependencies]
argon2 = "0.5"
CARGO
    mkdir -p "$TMPDIR/src"
    PASSWORD="${1:-}"
    if [ -z "$PASSWORD" ]; then
        echo -n "Enter password (no echo): " >&2
        read -rs PASSWORD
        echo >&2
    fi
    cat > "$TMPDIR/src/main.rs" << RUST
fn main() {
    use argon2::{password_hash::{PasswordHasher, SaltString, rand_core::OsRng}, Argon2};
    let pass = std::env::args().nth(1).unwrap_or_default();
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(pass.as_bytes(), &salt).unwrap();
    println!("{}", hash);
}
RUST
    (cd "$TMPDIR" && cargo run -q -- "$PASSWORD")
    rm -rf "$TMPDIR"
else
    echo "Error: neither python3+argon2-cffi nor cargo found." >&2
    echo "Install: pip install argon2-cffi" >&2
    exit 1
fi

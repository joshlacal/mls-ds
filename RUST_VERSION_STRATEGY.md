# Rust Version Strategy: Server vs FFI Client

**Decision**: Use different Rust versions for different components

---

## Recommendation

### Server: Stable Rust 1.90.0+ (or latest stable)

**Rationale:**
- ✅ **Production stability** is critical for 24/7 service
- ✅ **Predictable behavior** across releases
- ✅ **Ecosystem compatibility** - all dependencies support stable
- ✅ **CI/CD simplicity** - no nightly-specific toolchain management
- ✅ **OpenMLS 0.7.1** works perfectly on stable Rust
- ✅ **Easier debugging** - stable compiler produces better error messages
- ✅ **Security updates** - stable gets backported security fixes

**What you lose by NOT using nightly:**
- ❌ Experimental features (`#![feature(...)]`) - but you don't need any
- ❌ Latest optimizations - negligible impact for server workload
- ❌ Cutting-edge language features - stable is more than sufficient

---

### FFI Client: Nightly Rust (IF AND ONLY IF NEEDED)

**Use nightly ONLY if:**
1. You're using `cbindgen` with advanced features
2. You need `#![feature(c_unwind)]` for better FFI panic handling
3. You're doing experimental Swift interop that requires nightly
4. Your Swift Package Manager setup demands it

**If you DON'T need any of those:** Use stable Rust here too!

---

## Example Toolchain Configuration

### Server (Stable)

**File**: `server/rust-toolchain.toml`
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

**Or** `server/rust-toolchain`:
```
stable
```

**Verify:**
```bash
cd server
rustc --version
# Should show: rustc 1.90.0 (or latest stable)
```

---

### FFI Client (Nightly - Optional)

**File**: `mls-ffi/rust-toolchain.toml`
```toml
[toolchain]
channel = "nightly-2025-11-15"  # Pin to specific date for reproducibility
components = ["rustfmt", "clippy", "rust-src"]
```

**Or use stable if you don't need nightly:**
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

**Verify:**
```bash
cd mls-ffi
rustc --version
# Should show: rustc 1.xx.0-nightly (...)
```

---

## OpenMLS Version Compatibility

### OpenMLS 0.7.1 Requirements

From `openmls/Cargo.toml`:
```toml
[package]
rust-version = "1.70"  # Minimum Supported Rust Version (MSRV)
```

**This means:**
- ✅ Works on Rust 1.70+ (stable)
- ✅ Works on Rust 1.90+ (stable)
- ✅ Works on nightly
- ❌ Does NOT require nightly

**External commit support:**
- Available in 0.6.0+ (your current version)
- Improved in 0.7.1
- No nightly features required

---

## Upgrade Path

### Step 1: Upgrade Server to Stable 1.90+ (if not already)

```bash
cd /home/ubuntu/mls/server

# Check current version
rustc --version

# If < 1.90, upgrade
rustup update stable
rustup default stable

# Verify
rustc --version
# Should show: rustc 1.90.0 or newer
```

### Step 2: Upgrade OpenMLS to 0.7.1

**File**: `server/Cargo.toml`
```toml
[dependencies]
openmls = "0.7.1"  # Changed from 0.6
openmls_traits = "0.3"
openmls_basic_credential = "0.3"
openmls_rust_crypto = "0.3"
```

```bash
cd server

# Update dependencies
cargo update -p openmls

# Check for breaking changes
cargo check 2>&1 | tee ../openmls_upgrade_log.txt

# Build
cargo build --release
```

### Step 3: Fix Breaking Changes (if any)

**Common changes in 0.7.x:**

1. **Method signature updates:**
```rust
// OLD (0.6)
mls_group.export_group_info(&provider, &signer)

// NEW (0.7.1)
mls_group.export_group_info(&provider, &signer, with_ratchet_tree: bool)
```

2. **Error handling:**
```rust
// OLD
.map_err(|e| format!("Error: {:?}", e))

// NEW
.map_err(|e| Error::from(e))
```

3. **Import paths:**
```rust
// Check if any imports changed
use openmls::prelude::*;  // This usually covers everything
```

### Step 4: Run Tests

```bash
# Server tests
cd server
cargo test --all-features

# Integration tests
cd ..
cargo test --workspace
```

---

## CI/CD Configuration

### GitHub Actions Example

**File**: `.github/workflows/rust.yml`

```yaml
name: Rust CI

on: [push, pull_request]

jobs:
  server:
    name: Server (Stable Rust)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust Stable
        uses: dtolnay/rust-toolchain@stable
        
      - name: Cache Dependencies
        uses: Swatinem/rust-cache@v2
        with:
          workspaces: "server -> target"
      
      - name: Check OpenMLS Version
        working-directory: ./server
        run: cargo tree -p openmls
        
      - name: Build Server
        working-directory: ./server
        run: cargo build --release
        
      - name: Run Tests
        working-directory: ./server
        run: cargo test --all-features

  ffi-client:
    name: FFI Client (Nightly Rust)
    runs-on: macos-latest  # For Swift interop testing
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust Nightly
        uses: dtolnay/rust-toolchain@nightly
        
      - name: Build FFI
        working-directory: ./mls-ffi
        run: cargo build --release
        
      - name: Run Swift Tests
        run: swift test
```

---

## Local Development Setup

### Developer Workstation

**Install both toolchains:**
```bash
# Stable (for server)
rustup install stable
rustup default stable

# Nightly (for FFI, if needed)
rustup install nightly
```

**Switching between projects:**
```bash
# Server work (uses stable automatically via rust-toolchain file)
cd /home/ubuntu/mls/server
cargo build
rustc --version  # Shows stable

# FFI work (uses nightly if rust-toolchain specifies it)
cd /home/ubuntu/mls/mls-ffi
cargo build
rustc --version  # Shows nightly if configured
```

**Or use explicit overrides:**
```bash
# Force stable for specific command
cd server
cargo +stable build

# Force nightly for specific command
cd mls-ffi
cargo +nightly build
```

---

## Decision Matrix

| Component | Rust Version | Reason |
|-----------|--------------|--------|
| **Server** | Stable 1.90+ | Production stability, ecosystem support |
| **FFI (Swift interop)** | Nightly (if needed) | Advanced C interop features |
| **FFI (simple)** | Stable 1.90+ | Prefer stability if no special needs |
| **CLI tools** | Stable | User-facing, needs reliability |
| **Build scripts** | Stable | CI/CD simplicity |

---

## When to Use Nightly (FFI Client)

### ✅ Use Nightly If:

1. **You're using `cbindgen` with experimental features:**
```toml
# In mls-ffi/Cargo.toml
[build-dependencies]
cbindgen = { version = "0.26", features = ["experimental"] }
```

2. **You need panic handling across FFI boundary:**
```rust
#![feature(c_unwind)]

#[no_mangle]
pub extern "C-unwind" fn mls_ffi_function() {
    // Can safely panic and unwind through C boundary
}
```

3. **You're using experimental Swift-Rust interop:**
```rust
#![feature(extern_types)]
```

4. **Your dependency REQUIRES nightly** (check `Cargo.toml`):
```bash
cd mls-ffi
cargo tree | grep "#"  # Shows git dependencies
cargo tree | grep "nightly"  # Check for nightly-only deps
```

### ❌ DON'T Use Nightly If:

- You're just calling OpenMLS APIs (works fine on stable)
- You're doing basic C FFI (stable has full support)
- You value build reproducibility (nightly changes daily)
- You want simpler CI/CD

---

## Current Status Check

Run this to see what you're currently using:

```bash
#!/bin/bash

echo "=== Server Rust Version ==="
cd /home/ubuntu/mls/server
rustc --version
echo

echo "=== Server OpenMLS Version ==="
cargo tree -p openmls | head -1
echo

echo "=== Checking for nightly features in server ==="
grep -r "feature(" src/ | head -5 || echo "None found (good!)"
echo

echo "=== Recommended Action ==="
if rustc --version | grep -q nightly; then
    echo "⚠️  Server is using nightly - consider switching to stable"
else
    echo "✅ Server is using stable - correct choice!"
fi
```

---

## Migration Plan

### If Server is Currently on Nightly → Stable

1. **Remove nightly-specific features:**
```bash
cd server
grep -r "#!\[feature" src/
# Remove any feature gates found
```

2. **Update toolchain file:**
```bash
echo "stable" > rust-toolchain
```

3. **Test everything still builds:**
```bash
cargo clean
cargo build --release
cargo test --all
```

4. **Update CI/CD to use stable**

5. **Document change in commit message**

---

## Recommendation Summary

**For Your Project:**

1. ✅ **Server**: Use stable Rust 1.90+ with OpenMLS 0.7.1
2. ❓ **FFI Client**: Check if you actually need nightly
   - If no `#![feature(...)]` in code → Use stable
   - If you have nightly features → Keep nightly (but document why)
3. ✅ **Upgrade OpenMLS to 0.7.1 on BOTH** (works on stable)

**Benefits:**
- Simpler deployment (server on stable)
- Better stability for production
- Consistent behavior across team
- Easier onboarding for new developers

---

## Questions to Ask Yourself

Before deciding on nightly for FFI:

1. Do I have `#![feature(...)]` attributes in my FFI code? → **Check `mls-ffi/src/lib.rs`**
2. Does `cbindgen` fail on stable? → **Try it**
3. Do my FFI dependencies require nightly? → **Check `cargo tree`**
4. Am I using experimental Swift-Rust interop? → **Check your Swift Package setup**

**If all answers are "no"** → Use stable for FFI too!

---

## Final Recommendation

```toml
# server/rust-toolchain.toml
[toolchain]
channel = "stable"  # ← Production stability

# mls-ffi/rust-toolchain.toml (if separate)
[toolchain]
channel = "stable"  # ← Unless you have specific nightly needs
```

**Upgrade both to OpenMLS 0.7.1, stay on stable Rust.**

---

**Questions?** Check what you're currently using:
```bash
cd server && rustc --version
cd mls-ffi && rustc --version  # If separate crate
```

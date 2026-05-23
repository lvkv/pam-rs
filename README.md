# pam-bindings

[![Test Status](https://github.com/lvkv/pam-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/lvkv/pam-rs/actions/workflows/rust.yml)
[![Crate](https://img.shields.io/crates/v/pam-bindings.svg)](https://crates.io/crates/pam-bindings)

Simplified PAM module creation in Rust.

```rust
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::ffi::CStr;

struct AliceOnly;
pam::pam_hooks!(AliceOnly);

impl PamHooks for AliceOnly {
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let username = match pamh.get_user(None) {
            Ok(username) => username,
            Err(e) => {
                eprintln!("failed to get username, error code: {e:?}");
                return e;
            }
        };

        match username.as_str() {
            "alice" => PamResultCode::PAM_SUCCESS,
            _ => PamResultCode::PAM_AUTH_ERR,
        }
    }
}
```

## Introduction

The Pluggable Authentication Modules (PAM) framework enables systems to
authenticate users and perform other functions by composing PAM modules,
which are distributed as shared libraries.

The goal of this library is to provide a simple, type-safe API to write
these modules.

## Usage

Add `pam-bindings` to your dependencies in Cargo.toml:

```toml
[dependencies]
pam-bindings = "0.2.1"
```

## Examples

Example PAM modules can be found under [`pam/examples`](https://github.com/lvkv/pam-rs/tree/main/pam/examples).

### Running an example

The exact paths and package names below may vary by distribution.

```bash
# Install prerequisites
sudo apt-get install -y libpam0g-dev pamtester

# Build an example PAM module
# This walkthrough uses the "username" example module
example=username
cargo build --example $example

# Register a PAM service that loads the module
service=test-pam-service
facility=session
sudo tee /etc/pam.d/$service <<EOF
$facility required    $(pwd)/target/debug/examples/lib$example.so
EOF

# Test the relevant PAM operation
operation=open_session
pamtester $service $USER $operation

# Clean up
sudo rm /etc/pam.d/$service
```

## Acknowledgements

The initial contents of this repository were heavily borrowed from:

- [tozny/rust-pam](https://github.com/tozny/rust-pam)
- [ndenev/pam_groupmap](https://github.com/ndenev/pam_groupmap)
- [beatgammit/pam-http](https://github.com/beatgammit/pam-http)

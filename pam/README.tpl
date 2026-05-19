# {{crate}}

[![Test Status](https://github.com/lvkv/pam-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/lvkv/pam-rs/actions/workflows/rust.yml)
[![Crate](https://img.shields.io/crates/v/{{crate}}.svg)](https://crates.io/crates/{{crate}})

{{readme}}

## Usage

Add `{{crate}}` to your dependencies in Cargo.toml:

```toml
[dependencies]
{{crate}} = "{{version}}"
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

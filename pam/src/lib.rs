//! Simplified PAM module creation in Rust.
//!
//! ```rust
//! use pam::constants::{PamFlag, PamResultCode};
//! use pam::module::{PamHandle, PamHooks};
//! use std::ffi::CStr;
//!
//! struct AliceOnly;
//! pam::pam_hooks!(AliceOnly);
//!
//! impl PamHooks for AliceOnly {
//!     fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
//!         let username = match pamh.get_user(None) {
//!             Ok(username) => username,
//!             Err(e) => {
//!                 eprintln!("failed to get username, error code: {e:?}");
//!                 return e;
//!             }
//!         };
//!
//!         match username.as_str() {
//!             "alice" => PamResultCode::PAM_SUCCESS,
//!             _ => PamResultCode::PAM_AUTH_ERR,
//!         }
//!     }
//! }
//! # fn main() {}
//! ```
//!
//! # Introduction
//!
//! The Pluggable Authentication Modules (PAM) framework enables systems to
//! authenticate users and perform other functions by composing PAM modules,
//! which are distributed as shared libraries.
//!
//! The goal of this library is to provide a simple, type-safe API to write
//! these modules.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented
)]

pub mod constants;
pub mod conv;
pub mod items;
#[doc(hidden)]
pub mod macros;
pub mod module;

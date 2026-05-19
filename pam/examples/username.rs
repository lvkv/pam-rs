#[macro_use]
extern crate pam;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::ffi::CStr;

struct Username;
pam_hooks!(Username);

impl PamHooks for Username {
    fn sm_open_session(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let username = match pamh.get_user(None) {
            Ok(username) => username,
            Err(e) => {
                eprintln!("failed to get username, error code: {e:?}");
                assert!(e != PamResultCode::PAM_SUCCESS);
                return e;
            }
        };

        eprintln!("username: {username}");
        PamResultCode::PAM_SUCCESS
    }
}

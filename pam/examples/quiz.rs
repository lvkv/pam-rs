use pam::constants::{PAM_PROMPT_ECHO_ON, PamFlag, PamResultCode};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::{pam_hooks, pam_try};
use std::ffi::CStr;
use std::str::FromStr;

struct Quiz;
pam_hooks!(Quiz);

impl PamHooks for Quiz {
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => return PamResultCode::PAM_CONV_ERR,
            Err(err) => return err,
        };

        let response = pam_try!(conv.send(PAM_PROMPT_ECHO_ON, "2 + 3 = "));
        let Some(response) = response else {
            return PamResultCode::PAM_CONV_ERR;
        };

        let response = pam_try!(response.to_str(), PamResultCode::PAM_AUTH_ERR);
        let answer = pam_try!(u32::from_str(response), PamResultCode::PAM_AUTH_ERR);

        if answer == 5 {
            PamResultCode::PAM_SUCCESS
        } else {
            PamResultCode::PAM_AUTH_ERR
        }
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

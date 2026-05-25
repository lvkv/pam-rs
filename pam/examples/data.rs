use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use pam::pam_hooks;
use std::ffi::CStr;

struct Data;
pam_hooks!(Data);

impl PamHooks for Data {
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // Store a value on the handle
        if let Err(e) = pamh.set_data("greeting", Box::new(String::from("hello"))) {
            eprintln!("set_data failed, error code: {e:?}");
            return e;
        }

        // Read the data back
        let greeting = match unsafe { pamh.get_data::<String>("greeting") } {
            Ok(greeting) => greeting,
            Err(e) => {
                eprintln!("get_data failed, error code: {e:?}");
                return e;
            }
        };

        if greeting == "hello" {
            eprintln!("data: {greeting}");
            PamResultCode::PAM_SUCCESS
        } else {
            PamResultCode::PAM_AUTH_ERR
        }
    }
}

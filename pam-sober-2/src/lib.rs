extern crate pam;
extern crate rand;

use pam::constants::{PamFlag, PamResultCode};
use pam::items::ItemType::AuthTok;
use pam::module::{PamHandle, PamHooks};
use rand::Rng;
use std::ffi::CStr;
use std::str::FromStr;
use pam::pam_try;

struct PamSober;
pam::pam_hooks!(PamSober);

impl PamHooks for PamSober {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("Let's make sure you're sober enough to perform basic addition! <2>");

        /* TODO: use args to change difficulty ;-)
        let args: HashMap<&str, &str> = args.iter().map(|s| {
            let mut parts = s.splitn(2, "=");
            (parts.next().unwrap(), parts.next().unwrap_or(""))
        }).collect();
        */

        // TODO: maybe we can change difficulty base on user?
        // let user = pam_try!(pamh.get_user(None));

        let mut rng = rand::thread_rng();
        let a = rng.gen::<u32>() % 100;
        let b = rng.gen::<u32>() % 100;
        let math = format!("{} + {} = ", a, b);

        // This println kinda helps debugging since the test script doesn't echo
        eprintln!("[DEBUG]: {}{}", math, a + b);

        //let password = pam_try!(conv.send(PAM_PROMPT_ECHO_ON, &math));
        let password = pamh.get_authtok(AuthTok, Some(&math));

        if let Ok(password) = password {
            let password = password.as_str();
            eprintln!("[DEBUG]: You entered: {}", password);
            let answer = pam_try!(u32::from_str(password), PamResultCode::PAM_AUTH_ERR);
            if answer == a + b {
                PamResultCode::PAM_SUCCESS
            } else {
                println!("Wrong answer provided {} + {} != {}", a, b, answer);
                PamResultCode::PAM_AUTH_ERR
            }
        } else {
            println!("You failed the PAM sobriety test.");
            PamResultCode::PAM_AUTH_ERR
        }
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}

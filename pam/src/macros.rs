use crate::constants::PamResultCode;

/// Macro to generate the `extern "C"` entrypoint bindings needed by PAM
///
/// You can call `pam_hooks!(SomeType);` for any type that implements `PamHooks`
///
/// ## Errors
///
/// - [`PamResultCode::PAM_ABORT`] if `argc` is negative.
/// - [`PamResultCode::PAM_ABORT`] if `argv` is null and `argc` is positive.
/// - [`PamResultCode::PAM_ABORT`] if any element of `argv` is unexpectedly null.
///
/// ## Examples:
///
/// Here is full example of a PAM module that would authenticate and authorize everybody:
///
/// ```
/// use pam::module::{PamHooks, PamHandle};
/// use pam::constants::{PamResultCode, PamFlag};
/// use pam::pam_hooks;
/// use std::ffi::CStr;
///
/// # fn main() {}
/// struct MyPamModule;
/// pam_hooks!(MyPamModule);
///
/// impl PamHooks for MyPamModule {
///    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
///        println!("Everybody is authenticated!");
///        PamResultCode::PAM_SUCCESS
///    }
///
///    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
///        println!("Everybody is authorized!");
///        PamResultCode::PAM_SUCCESS
///    }
/// }
/// ```
#[macro_export]
macro_rules! pam_hooks {
    ($ident:ident) => {
        pub use self::pam_hooks_scope::*;
        mod pam_hooks_scope {
            use std::os::raw::{c_char, c_int};
            use $crate::constants::{PamFlag, PamResultCode};
            use $crate::module::{PamHandle, PamHooks};

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_acct_mgmt(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(argc, argv, |args| {
                        super::$ident::acct_mgmt(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_authenticate(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(argc, argv, |args| {
                        super::$ident::sm_authenticate(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_chauthtok(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(argc, argv, |args| {
                        super::$ident::sm_chauthtok(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_close_session(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(argc, argv, |args| {
                        super::$ident::sm_close_session(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_open_session(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(argc, argv, |args| {
                        super::$ident::sm_open_session(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_setcred(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(argc, argv, |args| {
                        super::$ident::sm_setcred(pamh, args, flags)
                    })
                }
            }
        }
    };
}

#[macro_export]
macro_rules! pam_try {
    ($r:expr) => {
        match $r {
            Ok(t) => t,
            Err(e) => return e,
        }
    };
    ($r:expr, $e:expr) => {
        match $r {
            Ok(t) => t,
            Err(_) => return $e,
        }
    };
}

fn panic_guard<F: FnOnce() -> PamResultCode>(f: F) -> PamResultCode {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(PamResultCode::PAM_ABORT)
}

/// Materializes the PAM module argv into a `Vec<&CStr>`.
///
/// # Errors
///
/// - [`PamResultCode::PAM_ABORT`] if any element of `argv` is null.
///
/// # Safety
///
/// - Each non-null argument must point to a null-terminated C string that outlives the slice.
unsafe fn extract_argv(
    argv: &[*const std::os::raw::c_char],
) -> Result<Vec<&std::ffi::CStr>, PamResultCode> {
    argv.iter()
        .map(|&p| {
            if p.is_null() {
                Err(PamResultCode::PAM_ABORT)
            } else {
                Ok(unsafe { std::ffi::CStr::from_ptr(p) })
            }
        })
        .collect()
}

/// Validates argc/argv, catches panics, and invokes a `PamHooks` method.
///
/// # Safety
///
/// - When `argc > 0`, `argv` must point to an array of `argc` valid `*const c_char` entries.
/// - Each non-null entry must point to a null-terminated C string valid for the duration of `hook`.
#[doc(hidden)]
#[allow(clippy::similar_names)]
pub unsafe fn invoke_hook(
    argc: std::os::raw::c_int,
    argv: *const *const std::os::raw::c_char,
    hook: impl FnOnce(Vec<&std::ffi::CStr>) -> PamResultCode,
) -> PamResultCode {
    panic_guard(|| {
        if argc < 0 || (argc > 0 && argv.is_null()) {
            return PamResultCode::PAM_ABORT;
        }
        #[allow(clippy::cast_sign_loss)]
        let argv: &[*const std::os::raw::c_char] = if argc == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(argv, argc as usize) }
        };
        match unsafe { extract_argv(argv) } {
            Ok(args) => hook(args),
            Err(e) => e,
        }
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
pub mod test {
    use crate::constants::PamResultCode;
    use crate::module::PamHooks;
    use std::os::raw::c_char;
    use std::ptr;

    struct Foo;
    impl PamHooks for Foo {}

    pam_hooks!(Foo);

    #[test]
    fn panic_returns_error_code() {
        let code = super::panic_guard(|| panic!("intentional"));
        assert_eq!(code, PamResultCode::PAM_ABORT);
    }

    #[test]
    fn test_extract_argv() {
        // Error case: one element is null
        let with_null: [*const c_char; 2] = [c"first".as_ptr(), ptr::null()];
        assert_eq!(
            unsafe { super::extract_argv(&with_null) }.unwrap_err(),
            PamResultCode::PAM_ABORT
        );

        // Success: no arguments
        let empty: [*const c_char; 0] = [];
        assert!(unsafe { super::extract_argv(&empty) }.unwrap().is_empty());

        // Success: all elements are valid
        let valid: [*const c_char; 2] = [c"first".as_ptr(), c"second".as_ptr()];
        let args = unsafe { super::extract_argv(&valid) }.unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].to_str().unwrap(), "first");
        assert_eq!(args[1].to_str().unwrap(), "second");
    }
}

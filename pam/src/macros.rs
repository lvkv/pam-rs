use crate::constants::PamResultCode;

/// Macro to generate the `extern "C"` entrypoint bindings needed by PAM
///
/// You can call `pam_hooks!(SomeType);` for any type that implements `PamHooks`
///
/// ## Errors
///
/// - [`PamResultCode::PAM_ABORT`] if the PAM handle is null.
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
                pamh: *mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(pamh, argc, argv, |pamh, args| {
                        super::$ident::acct_mgmt(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_authenticate(
                pamh: *mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(pamh, argc, argv, |pamh, args| {
                        super::$ident::sm_authenticate(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_chauthtok(
                pamh: *mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(pamh, argc, argv, |pamh, args| {
                        super::$ident::sm_chauthtok(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_close_session(
                pamh: *mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(pamh, argc, argv, |pamh, args| {
                        super::$ident::sm_close_session(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_open_session(
                pamh: *mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(pamh, argc, argv, |pamh, args| {
                        super::$ident::sm_open_session(pamh, args, flags)
                    })
                }
            }

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn pam_sm_setcred(
                pamh: *mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                unsafe {
                    $crate::macros::invoke_hook(pamh, argc, argv, |pamh, args| {
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

/// Validates the handle and argc/argv, catches panics, and invokes a `PamHooks` method.
///
/// # Errors
///
/// - [`PamResultCode::PAM_ABORT`] if `pamh` is null.
/// - [`PamResultCode::PAM_ABORT`] if `argc` is negative.
/// - [`PamResultCode::PAM_ABORT`] if `argv` is null and `argc` is positive.
/// - [`PamResultCode::PAM_ABORT`] if any element of `argv` is null.
/// - [`PamResultCode::PAM_ABORT`] if `hook` panics.
///
/// # Safety
///
/// - When non-null, `pamh` must be a valid, aligned pointer to a `PamHandle` usable for the duration of `hook`.
/// - When `argc > 0`, `argv` must point to an array of `argc` valid `*const c_char` entries.
/// - Each non-null entry must point to a null-terminated C string valid for the duration of `hook`.
#[doc(hidden)]
#[allow(clippy::similar_names)]
pub unsafe fn invoke_hook(
    pamh: *mut crate::module::PamHandle,
    argc: std::os::raw::c_int,
    argv: *const *const std::os::raw::c_char,
    hook: impl FnOnce(&mut crate::module::PamHandle, Vec<&std::ffi::CStr>) -> PamResultCode,
) -> PamResultCode {
    panic_guard(|| {
        // PAM should always hand us a valid handle
        let Some(pamh) = (unsafe { pamh.as_mut() }) else {
            return PamResultCode::PAM_ABORT;
        };
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
            Ok(args) => hook(pamh, args),
            Err(e) => e,
        }
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::needless_pass_by_value)]
pub mod test {
    use crate::constants::PamResultCode;
    use crate::module::{PamHandle, PamHooks};
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int};
    use std::ptr;

    struct Foo;
    impl PamHooks for Foo {}

    pam_hooks!(Foo);

    #[test]
    fn panic_returns_error_code() {
        let code = super::panic_guard(|| panic!("intentional"));
        assert_eq!(code, PamResultCode::PAM_ABORT);
    }

    /// Test hook returning `PAM_SUCCESS`, distinct from `PAM_ABORT` so an unexpected run is caught.
    fn hook_success(_pamh: &mut PamHandle, _args: Vec<&CStr>) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    /// Test hook that always panics, used to verify a panicking hook becomes `PAM_ABORT`.
    fn hook_panic(_pamh: &mut PamHandle, _args: Vec<&CStr>) -> PamResultCode {
        panic!("hook panicked");
    }

    #[test]
    fn invoke_hook_validation() {
        struct Case {
            pamh: *mut PamHandle,
            argc: c_int,
            argv: *const *const c_char,
            hook: fn(&mut PamHandle, Vec<&CStr>) -> PamResultCode,
            expected: PamResultCode,
        }

        // Mock "valid" PAM handle for testing
        let pamh = ptr::NonNull::<PamHandle>::dangling().as_ptr();

        // Argv arrays
        let one_null: [*const c_char; 1] = [ptr::null()];
        let two_valid: [*const c_char; 2] = [c"first".as_ptr(), c"second".as_ptr()];

        let cases = [
            // Null PAM handle is rejected before the hook runs
            Case {
                pamh: ptr::null_mut(),
                argc: 0,
                argv: ptr::null(),
                hook: hook_success,
                expected: PamResultCode::PAM_ABORT,
            },
            // Negative argc is rejected
            Case {
                pamh,
                argc: -1,
                argv: ptr::null(),
                hook: hook_success,
                expected: PamResultCode::PAM_ABORT,
            },
            // Null argv with positive argc is rejected
            Case {
                pamh,
                argc: 1,
                argv: ptr::null(),
                hook: hook_success,
                expected: PamResultCode::PAM_ABORT,
            },
            // A null element within argv is rejected
            Case {
                pamh,
                argc: 1,
                argv: one_null.as_ptr(),
                hook: hook_success,
                expected: PamResultCode::PAM_ABORT,
            },
            // A panicking hook is contained and reported as an abort
            Case {
                pamh,
                argc: 0,
                argv: ptr::null(),
                hook: hook_panic,
                expected: PamResultCode::PAM_ABORT,
            },
            // Happy path: a valid handle and argv invoke the hook
            Case {
                pamh,
                argc: 2,
                argv: two_valid.as_ptr(),
                hook: hook_success,
                expected: PamResultCode::PAM_SUCCESS,
            },
        ];

        for case in cases {
            let actual = unsafe { super::invoke_hook(case.pamh, case.argc, case.argv, case.hook) };
            assert_eq!(case.expected, actual);
        }
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

//! Functions for use in pam modules.

use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;

use crate::constants::{PamFlag, PamResultCode};

/// Opaque type, used as a pointer when making pam API calls.
///
/// A module is invoked via an external function such as `pam_sm_authenticate`.
/// Such a call provides a pam handle pointer.  The same pointer should be given
/// as an argument when making API calls.
#[repr(C)]
pub struct PamHandle {
    _data: [u8; 0],
    /// Force `!Send + !Sync`.
    ///
    /// PAM handles are not thread-safe. From the [man page for `pam(3)`][1]:
    /// > The libpam interfaces are only thread-safe if each thread within
    /// > the multithreaded application uses its own PAM handle.
    ///
    /// [1]: https://man7.org/linux/man-pages/man3/pam.3.html
    _marker: PhantomData<*const ()>,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: &mut *const libc::c_void,
    ) -> c_int;

    fn pam_set_data(
        pamh: *mut PamHandle,
        module_data_name: *const c_char,
        data: *mut libc::c_void,
        cleanup: extern "C" fn(
            pamh: *const PamHandle,
            data: *mut libc::c_void,
            error_status: c_int,
        ),
    ) -> c_int;

    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: crate::items::ItemType,
        item: &mut *const libc::c_void,
    ) -> c_int;

    fn pam_set_item(
        pamh: *mut PamHandle,
        item_type: crate::items::ItemType,
        item: *const libc::c_void,
    ) -> c_int;

    fn pam_get_user(
        pamh: *const PamHandle,
        user: &mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

extern "C" fn cleanup<T>(_: *const PamHandle, c_data: *mut libc::c_void, _: c_int) {
    // A panic on Drop for T must not unwind across the C boundary
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let _data: Box<T> = Box::from_raw(c_data.cast::<T>());
    }));
    // Dropping the above result can itself panic, and is surprisingly difficult to get right.
    // From the docs for catch_unwind:
    // > Finally, be careful in how you drop the result of this function. If it is Err, it contains the panic payload, and dropping that may in turn panic!
    // See: https://internals.rust-lang.org/t/some-thoughts-on-a-less-slippery-catch-unwind/16902/4
    if let Err(payload) = result {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
            .map_err(std::mem::forget);
    }
}

pub type PamResult<T> = Result<T, PamResultCode>;

impl PamHandle {
    /// Gets some value, identified by `key`, that has been set by the module
    /// previously.
    ///
    /// See `pam_get_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// - [`PamResultCode`] if the lookup itself fails.
    /// - [`PamResultCode::PAM_BUF_ERR`] if the key string bytes contain an internal 0 byte.
    /// - [`PamResultCode::PAM_SYSTEM_ERR`] if PAM reports success but yields a null pointer.
    ///
    /// # Safety
    ///
    /// The data stored under the provided key must be of type `T` otherwise the
    /// behaviour of this function is undefined.
    pub unsafe fn get_data<'a, T>(&'a self, key: &str) -> PamResult<&'a T> {
        let c_key = CString::new(key).map_err(|_| PamResultCode::PAM_BUF_ERR)?;
        let mut ptr: *const libc::c_void = std::ptr::null();
        let res = PamResultCode::from_raw(unsafe { pam_get_data(self, c_key.as_ptr(), &mut ptr) });
        if PamResultCode::PAM_SUCCESS != res {
            return Err(res);
        }
        if ptr.is_null() {
            return Err(PamResultCode::PAM_SYSTEM_ERR);
        }
        let typed_ptr = ptr.cast::<T>();
        let data: &T = unsafe { &*typed_ptr };
        Ok(data)
    }

    /// Stores a value that can be retrieved later with `get_data`.  The value lives
    /// as long as the current pam cycle.
    ///
    /// See `pam_set_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// - [`PamResultCode`] if the store itself fails.
    /// - [`PamResultCode::PAM_BUF_ERR`] if the key string contains a 0 byte.
    pub fn set_data<T: 'static>(&mut self, key: &str, data: Box<T>) -> PamResult<()> {
        let c_key = CString::new(key).map_err(|_| PamResultCode::PAM_BUF_ERR)?;
        let ptr = Box::into_raw(data);
        let res = PamResultCode::from_raw(unsafe {
            pam_set_data(
                self,
                c_key.as_ptr(),
                ptr.cast::<libc::c_void>(),
                cleanup::<T>,
            )
        });
        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            drop(unsafe { Box::from_raw(ptr) });
            Err(res)
        }
    }

    /// Retrieves a value that has been set, possibly by the pam client.  This is
    /// particularly useful for getting a `PamConv` reference.
    ///
    /// See `pam_get_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    pub fn get_item<'a, T: crate::items::Item<'a>>(&'a self) -> PamResult<Option<T>> {
        let mut ptr: *const libc::c_void = std::ptr::null();
        let res = PamResultCode::from_raw(unsafe { pam_get_item(self, T::type_id(), &mut ptr) });
        if PamResultCode::PAM_SUCCESS != res {
            return Err(res);
        }
        let typed_ptr = ptr.cast::<T::Raw>();
        if typed_ptr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { T::from_raw(typed_ptr) }))
        }
    }

    /// Sets a value in the pam context. The value can be retrieved using
    /// `get_item`.
    ///
    /// Note that all items are strings, except `PAM_CONV` and `PAM_FAIL_DELAY`.
    ///
    /// See `pam_set_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    pub fn set_item_str<'a, T: crate::items::Item<'a>>(&mut self, item: T) -> PamResult<()> {
        let res = PamResultCode::from_raw(unsafe {
            pam_set_item(self, T::type_id(), item.into_raw().cast::<libc::c_void>())
        });
        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            Err(res)
        }
    }

    /// Retrieves the name of the user who is authenticating or logging in.
    ///
    /// This is really a specialization of `get_item`.
    ///
    /// See `pam_get_user` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    ///
    /// # Errors
    ///
    /// - [`PamResultCode`] if the lookup itself fails.
    /// - [`PamResultCode::PAM_BUF_ERR`] if the prompt string contains a 0 byte.
    /// - [`PamResultCode::PAM_SYSTEM_ERR`] if PAM reports success but yields a null pointer.
    /// - [`PamResultCode::PAM_SYSTEM_ERR`] if the returned username is not valid UTF-8.
    pub fn get_user(&self, prompt: Option<&str>) -> PamResult<String> {
        let mut ptr: *const c_char = std::ptr::null();
        let prompt_string = prompt
            .map(CString::new)
            .transpose()
            .map_err(|_| PamResultCode::PAM_BUF_ERR)?;
        let c_prompt = prompt_string
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr());
        let res = PamResultCode::from_raw(unsafe { pam_get_user(self, &mut ptr, c_prompt) });
        if PamResultCode::PAM_SUCCESS != res {
            return Err(res);
        }
        if ptr.is_null() {
            return Err(PamResultCode::PAM_SYSTEM_ERR);
        }
        let bytes = unsafe { CStr::from_ptr(ptr).to_bytes() };
        String::from_utf8(bytes.to_vec()).map_err(|_| PamResultCode::PAM_SYSTEM_ERR)
    }
}

/// Provides functions that are invoked by the entrypoints generated by the
/// [`pam_hooks!` macro](../macro.pam_hooks.html).
///
/// All of hooks are ignored by PAM dispatch by default given the default return value of `PAM_IGNORE`.
/// Override any functions that you want to handle with your module. See `man pam(3)`.
#[allow(unused_variables)]
pub trait PamHooks {
    /// This function performs the task of establishing whether the user is permitted to gain access at
    /// this time. It should be understood that the user has previously been validated by an
    /// authentication module. This function checks for other things. Such things might be: the time of
    /// day or the date, the terminal line, remote hostname, etc. This function may also determine
    /// things like the expiration on passwords, and respond that the user change it before continuing.
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is used to (re-)set the authentication token of the user.
    ///
    /// The PAM library calls this function twice in succession. The first time with
    /// `PAM_PRELIM_CHECK` and then, if the module does not return `PAM_TRY_AGAIN`, subsequently with
    /// `PAM_UPDATE_AUTHTOK`. It is only on the second call that the authorization token is
    /// (possibly) changed.
    fn sm_chauthtok(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to terminate a session.
    fn sm_close_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to commence a session.
    fn sm_open_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of altering the credentials of the user with respect to the
    /// corresponding authorization scheme. Generally, an authentication module may have access to more
    /// information about a user than their authentication token. This function is used to make such
    /// information available to the application. It should only be called after the user has been
    /// authenticated but before a session has been established.
    fn sm_setcred(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_handles_drop_panics() {
        // Scenario 1
        // T::drop panics
        {
            struct Bomb;
            impl Drop for Bomb {
                fn drop(&mut self) {
                    panic!();
                }
            }
            let ptr = Box::into_raw(Box::new(Bomb)).cast::<libc::c_void>();
            cleanup::<Bomb>(std::ptr::null(), ptr, 0);
        }

        // Scenario 2
        // Every payload's Drop spawns another panic
        {
            struct BombRecursive;
            impl Drop for BombRecursive {
                fn drop(&mut self) {
                    std::panic::panic_any(Self);
                }
            }
            let ptr = Box::into_raw(Box::new(BombRecursive)).cast::<libc::c_void>();
            cleanup::<BombRecursive>(std::ptr::null(), ptr, 0);
        }
    }
}

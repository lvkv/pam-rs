use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::ptr;

use crate::constants::PamMessageStyle;
use crate::constants::PamResultCode;
use crate::items::Item;
use crate::module::PamResult;

#[repr(C)]
struct PamMessage {
    msg_style: PamMessageStyle,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *const c_char,
    resp_retcode: libc::c_int, // Unused - always zero
}

/// `PamConv` acts as a channel for communicating with user.
///
/// Communication is mediated by the pam client (the application that invoked
/// pam).  Messages sent will be relayed to the user by the client, and response
/// will be relayed back.
#[repr(C)]
pub struct Inner {
    conv: extern "C" fn(
        num_msg: c_int,
        pam_message: &&PamMessage,
        pam_response: &mut *const PamResponse,
        appdata_ptr: *const libc::c_void,
    ) -> PamResultCode,
    appdata_ptr: *const libc::c_void,
}

pub struct Conv<'a>(&'a Inner);

impl Conv<'_> {
    /// Sends a message to the pam client.
    ///
    /// This will typically result in the user seeing a message or a prompt.
    /// There are several message styles available:
    ///
    /// - `PAM_PROMPT_ECHO_OFF`
    /// - `PAM_PROMPT_ECHO_ON`
    /// - `PAM_ERROR_MSG`
    /// - `PAM_TEXT_INFO`
    /// - `PAM_RADIO_TYPE`
    /// - `PAM_BINARY_PROMPT`
    ///
    /// Note that the user experience will depend on how the client implements
    /// these message styles - and not all applications implement all message
    /// styles.
    ///
    /// # Errors
    ///
    /// - [`PamResultCode`] if the conversation call fails.
    /// - [`PamResultCode::PAM_BUF_ERR`] if the message string bytes contain an internal 0 byte.
    pub fn send(&self, style: PamMessageStyle, msg: &str) -> PamResult<Option<CString>> {
        let mut resp_ptr: *const PamResponse = ptr::null();
        let msg_cstr = CString::new(msg).map_err(|_| PamResultCode::PAM_BUF_ERR)?;
        let msg = PamMessage {
            msg_style: style,
            msg: msg_cstr.as_ptr(),
        };

        let ret = (self.0.conv)(1, &&msg, &mut resp_ptr, self.0.appdata_ptr);
        if PamResultCode::PAM_SUCCESS != ret {
            return Err(ret);
        }
        if resp_ptr.is_null() {
            return Err(PamResultCode::PAM_CONV_ERR);
        }

        // PAM spec: the module owns freeing the response array and each resp string.
        let resp_field = unsafe { (*resp_ptr).resp };
        // resp is null for message styles that don't yield input, e.g. PAM_TEXT_INFO.
        let response = if resp_field.is_null() {
            None
        } else {
            let owned = unsafe { CStr::from_ptr(resp_field) }.to_owned();
            unsafe { libc::free(resp_field.cast_mut().cast()) };
            Some(owned)
        };
        unsafe { libc::free(resp_ptr.cast_mut().cast()) };
        Ok(response)
    }
}

impl Item for Conv<'_> {
    type Raw = Inner;

    fn type_id() -> crate::items::ItemType {
        crate::items::ItemType::Conv
    }

    unsafe fn from_raw(raw: *const Self::Raw) -> Self {
        unsafe { Self(&*raw) }
    }

    fn into_raw(self) -> *const Self::Raw {
        std::ptr::from_ref(self.0)
    }
}

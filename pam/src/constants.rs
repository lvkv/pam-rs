use libc::{c_int, c_uint};

// TODO: Import constants from C header file at compile time.

pub type PamFlag = c_uint;
pub type PamItemType = c_int;
pub type PamMessageStyle = c_int;

// The Linux-PAM flags
// see /usr/include/security/_pam_types.h
pub const PAM_SILENT: PamFlag = 0x8000;
pub const PAM_DISALLOW_NULL_AUTHTOK: PamFlag = 0x0001;
pub const PAM_ESTABLISH_CRED: PamFlag = 0x0002;
pub const PAM_DELETE_CRED: PamFlag = 0x0004;
pub const PAM_REINITIALIZE_CRED: PamFlag = 0x0008;
pub const PAM_REFRESH_CRED: PamFlag = 0x0010;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: PamFlag = 0x0020;

// Message styles
pub const PAM_PROMPT_ECHO_OFF: PamMessageStyle = 1;
pub const PAM_PROMPT_ECHO_ON: PamMessageStyle = 2;
pub const PAM_ERROR_MSG: PamMessageStyle = 3;
pub const PAM_TEXT_INFO: PamMessageStyle = 4;
pub const PAM_RADIO_TYPE: PamMessageStyle = 5;
// Intentionally not public: we don't yet have a send API for this style.
#[allow(dead_code)]
pub(crate) const PAM_BINARY_PROMPT: PamMessageStyle = 7;

// The Linux-PAM return values
// see /usr/include/security/_pam_types.h
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub enum PamResultCode {
    PAM_SUCCESS = 0,
    PAM_OPEN_ERR = 1,
    PAM_SYMBOL_ERR = 2,
    PAM_SERVICE_ERR = 3,
    PAM_SYSTEM_ERR = 4,
    PAM_BUF_ERR = 5,
    PAM_PERM_DENIED = 6,
    PAM_AUTH_ERR = 7,
    PAM_CRED_INSUFFICIENT = 8,
    PAM_AUTHINFO_UNAVAIL = 9,
    PAM_USER_UNKNOWN = 10,
    PAM_MAXTRIES = 11,
    PAM_NEW_AUTHTOK_REQD = 12,
    PAM_ACCT_EXPIRED = 13,
    PAM_SESSION_ERR = 14,
    PAM_CRED_UNAVAIL = 15,
    PAM_CRED_EXPIRED = 16,
    PAM_CRED_ERR = 17,
    PAM_NO_MODULE_DATA = 18,
    PAM_CONV_ERR = 19,
    PAM_AUTHTOK_ERR = 20,
    PAM_AUTHTOK_RECOVERY_ERR = 21,
    PAM_AUTHTOK_LOCK_BUSY = 22,
    PAM_AUTHTOK_DISABLE_AGING = 23,
    PAM_TRY_AGAIN = 24,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
    PAM_AUTHTOK_EXPIRED = 27,
    PAM_MODULE_UNKNOWN = 28,
    PAM_BAD_ITEM = 29,
    PAM_CONV_AGAIN = 30,
    PAM_INCOMPLETE = 31,
}

impl TryFrom<c_int> for PamResultCode {
    /// The original value is returned when it does not name a known result code.
    type Error = c_int;

    /// Map a raw [`c_int`] to a [`PamResultCode`].
    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::PAM_SUCCESS,
            1 => Self::PAM_OPEN_ERR,
            2 => Self::PAM_SYMBOL_ERR,
            3 => Self::PAM_SERVICE_ERR,
            4 => Self::PAM_SYSTEM_ERR,
            5 => Self::PAM_BUF_ERR,
            6 => Self::PAM_PERM_DENIED,
            7 => Self::PAM_AUTH_ERR,
            8 => Self::PAM_CRED_INSUFFICIENT,
            9 => Self::PAM_AUTHINFO_UNAVAIL,
            10 => Self::PAM_USER_UNKNOWN,
            11 => Self::PAM_MAXTRIES,
            12 => Self::PAM_NEW_AUTHTOK_REQD,
            13 => Self::PAM_ACCT_EXPIRED,
            14 => Self::PAM_SESSION_ERR,
            15 => Self::PAM_CRED_UNAVAIL,
            16 => Self::PAM_CRED_EXPIRED,
            17 => Self::PAM_CRED_ERR,
            18 => Self::PAM_NO_MODULE_DATA,
            19 => Self::PAM_CONV_ERR,
            20 => Self::PAM_AUTHTOK_ERR,
            21 => Self::PAM_AUTHTOK_RECOVERY_ERR,
            22 => Self::PAM_AUTHTOK_LOCK_BUSY,
            23 => Self::PAM_AUTHTOK_DISABLE_AGING,
            24 => Self::PAM_TRY_AGAIN,
            25 => Self::PAM_IGNORE,
            26 => Self::PAM_ABORT,
            27 => Self::PAM_AUTHTOK_EXPIRED,
            28 => Self::PAM_MODULE_UNKNOWN,
            29 => Self::PAM_BAD_ITEM,
            30 => Self::PAM_CONV_AGAIN,
            31 => Self::PAM_INCOMPLETE,
            other => return Err(other),
        })
    }
}

impl PamResultCode {
    /// Map a [`c_int`] to a [`PamResultCode`].
    /// Unknown values are mapped to [`PamResultCode::PAM_SYSTEM_ERR`].
    pub(crate) fn from_raw(value: c_int) -> Self {
        Self::try_from(value).unwrap_or(Self::PAM_SYSTEM_ERR)
    }
}

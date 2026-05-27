//! Owned, zeroize-on-drop containers for sensitive byte material.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned byte buffer that is zeroed out when dropped.
/// Returned wherever this crate hands a secret back to the caller.
pub struct SecretBytes(Vec<u8>);

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretBytes {
    /// Create a new [`SecretBytes`] from a [`Vec<u8>`].
    pub(crate) const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the bytes as a string slice.
    ///
    /// # Errors
    ///
    /// - [`std::str::Utf8Error`] if the bytes are not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// Return the number of bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if no bytes are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretBytes").field(&"[redacted]").finish()
    }
}

/// Zeroize `len` bytes at `ptr`.
///
/// Used for libc allocations handed back by PAM.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for writes of `len` bytes.
/// - The caller must have exclusive access to the memory for the duration of the call.
pub(crate) unsafe fn zeroize_raw(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
}

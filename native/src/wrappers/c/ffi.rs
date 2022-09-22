use ffi_support::{ByteBuffer};
use std::{ptr, slice};

/// Used for receiving a ByteBuffer from C that was allocated by either C or Rust.
/// If Rust allocated, then the outgoing struct is `ffi_support::ByteBuffer`
/// Caller is responsible for calling free where applicable.
///
/// C will not notice a difference and can use the same struct
#[repr(C)]
#[derive(Debug)]
pub struct ByteArray {
    length: usize,
    data: *const u8,
}

impl Default for ByteArray {
    fn default() -> Self {
        Self {
            length: 0,
            data: ptr::null(),
        }
    }
}

impl ByteArray {
    /// Convert this into a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        if self.data.is_null() || self.length == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(self.data, self.length).to_vec() }
        }
    }

    /// Convert this into a byte vector if possible
    /// Some if success
    /// None if not
    pub fn to_opt_vec(&self) -> Option<Vec<u8>> {
        if self.data.is_null() {
            None
        } else if self.length == 0 {
            Some(Vec::new())
        } else {
            Some(unsafe { slice::from_raw_parts(self.data, self.length).to_vec() })
        }
    }

    ///Convert to outgoing struct ByteBuffer
    pub fn into_byte_buffer(self) -> ByteBuffer {
        ByteBuffer::from_vec(self.to_vec())
    }

    /// Convert a slice to ByteArray
    pub fn from_slice<I: AsRef<[u8]>>(data: I) -> Self {
        let data = data.as_ref();
        Self {
            length: data.len(),
            data: data.as_ptr() as *const u8,
        }
    }
}

impl From<&Vec<u8>> for ByteArray {
    fn from(b: &Vec<u8>) -> Self {
        Self::from_slice(b)
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(b: Vec<u8>) -> Self {
        Self::from_slice(&b)
    }
}

impl From<&[u8]> for ByteArray {
    fn from(b: &[u8]) -> Self {
        Self::from_slice(b)
    }
}

impl From<ByteBuffer> for ByteArray {
    fn from(b: ByteBuffer) -> Self {
        Self::from_slice(&b.destroy_into_vec())
    }
}

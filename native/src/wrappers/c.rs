#[macro_use]
mod macros;

pub mod ffi;

use crate::rust_bbs::{
  rust_bbs_blind_signature_size,
  rust_bbs_blinding_factor_size,
  rust_bls_public_key_g1_size,
  rust_bls_public_key_g2_size,
  rust_bls_secret_key_size,
  rust_bbs_signature_size,
  rust_bls_generate_blinded_g1_key,
  rust_bls_generate_blinded_g2_key,
  rust_bls_generate_g1_key,
  rust_bls_generate_g2_key,
  rust_bls_secret_key_to_bbs_key,
  rust_bls_public_key_to_bbs_key,
  rust_bbs_sign,
  rust_bbs_verify,
  rust_bbs_create_proof,
  rust_bbs_verify_proof,
  rust_bls_verify_proof,
  rust_bbs_blind_signature_commitment,
  rust_bbs_verify_blind_signature_proof,
  rust_bbs_blind_sign,
  rust_bbs_unblind_signature,
};
use std::os::raw::c_char;
use serde_json::{Value, json};

#[repr(C)]
pub struct JsonString {
  ptr: *const c_char,
}

/// Free memory for C string
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn ffi_bbs_signatures_free_json_string(json_string: JsonString) {
  let _ = Box::from_raw(json_string.ptr as *mut c_char);
}

/// Get size of G1 public key
#[no_mangle]
pub extern "C" fn bls_public_key_g1_size() -> i32 {
  rust_bls_public_key_g1_size()
}

/// Get size of G2 public key
#[no_mangle]
pub extern "C" fn bls_public_key_g2_size() -> i32 {
  rust_bls_public_key_g2_size()
}

/// Get size of blinding factor
#[no_mangle]
pub extern "C" fn bbs_blinding_factor_size() -> i32 {
  rust_bbs_blinding_factor_size()
}

/// Get size of bls secret key
#[no_mangle]
pub extern "C" fn bls_secret_key_size() -> i32 {
  rust_bls_secret_key_size()
}

/// Get size of bbs signature
#[no_mangle]
pub extern "C" fn bbs_signature_size() -> i32 {
  rust_bbs_signature_size()
}

/// Get size of blind signature
#[no_mangle]
pub extern "C" fn bbs_blind_signature_size() -> i32 {
  rust_bbs_blind_signature_size()
}

/// Generate Blinded G1 key
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bls_generate_blinded_g1_key(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize blinded G1 key to a JSON string
  match rust_bls_generate_blinded_g1_key(context_json) {
    Ok(mut blinded_g1_key_string) => {
      // add null terminator (for C-string)
      blinded_g1_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = blinded_g1_key_string.into_boxed_str();
    
      // set json_string pointer to boxed blinded_g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to stringify Blinded G1 key: {:?}", error), json_string); }
  }
}

/// Generate Blinded G2 key
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bls_generate_blinded_g2_key(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize blinded G2 key to a JSON string
  match rust_bls_generate_blinded_g2_key(context_json) {
    Ok(mut blinded_g2_key_string) => {
      // add null terminator (for C-string)
      blinded_g2_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = blinded_g2_key_string.into_boxed_str();
    
      // set json_string pointer to boxed blinded_g2_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to stringify Blinded G2 key: {:?}", error), json_string); }
  }
}

/// Generate G1 key
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bls_generate_g1_key(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize G1 key to a JSON string
  match rust_bls_generate_g1_key(context_json) {
    Ok(mut g1_key_string) => {
      // add null terminator (for C-string)
      g1_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = g1_key_string.into_boxed_str();
    
      // set json_string pointer to boxed g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to stringify G1 key: {:?}", error), json_string); }
  }
}

/// Generate G2 key
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bls_generate_g2_key(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize G2 key to a JSON string
  match rust_bls_generate_g2_key(context_json) {
    Ok(mut g2_key_string) => {
      // add null terminator (for C-string)
      g2_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = g2_key_string.into_boxed_str();
    
      // set json_string pointer to boxed g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to stringify G2 key: {:?}", error), json_string); }
  }
}

/// Convert BLS Secret Key to BBS Public Key
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bls_secret_key_to_bbs_key(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bls_secret_key_to_bbs_key(context_json) {
    Ok(mut g2_key_string) => {
      // add null terminator (for C-string)
      g2_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = g2_key_string.into_boxed_str();
    
      // set json_string pointer to boxed g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to stringify BBS key: {:?}", error), json_string); }
  }
}

/// Convert BLS Public Key to BBS Public Key
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bls_public_key_to_bbs_key(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bls_public_key_to_bbs_key(context_json) {
    Ok(mut g2_key_string) => {
      // add null terminator (for C-string)
      g2_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = g2_key_string.into_boxed_str();
    
      // set json_string pointer to boxed g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to stringify BBS key: {:?}", error), json_string); }
  }
}

/// BBS Sign
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_sign(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_sign(context_json) {
    Ok(mut g2_key_string) => {
      // add null terminator (for C-string)
      g2_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = g2_key_string.into_boxed_str();
    
      // set json_string pointer to boxed g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to stringify BBS Signature: {:?}", error), json_string); }
  }
}

/// BBS Create Proof
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_create_proof(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_create_proof(context_json) {
    Ok(mut g2_key_string) => {
      // add null terminator (for C-string)
      g2_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = g2_key_string.into_boxed_str();
    
      // set json_string pointer to boxed g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed generating proof of knowledge: {:?}", error), json_string); }
  }
}

/// BBS Verify Proof
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_verify_proof(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_verify_proof(context_json) {
    Ok(mut output_string) => {
      // add null terminator (for C-string)
      output_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = output_string.into_boxed_str();
    
      // set json_string pointer to boxed output_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed verifying proof of knowledge: {:?}", error), json_string); }
  }
}

/// BLS Verify Proof
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bls_verify_proof(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bls_verify_proof(context_json) {
    Ok(mut output_string) => {
      // add null terminator (for C-string)
      output_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = output_string.into_boxed_str();
    
      // set json_string pointer to boxed output_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed verifying proof of knowledge: {:?}", error), json_string); }
  }
}

/// Generate Blind Signature Commitment JSON
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_blind_signature_commitment(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_blind_signature_commitment(context_json) {
    Ok(mut output_string) => {
      // add null terminator (for C-string)
      output_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = output_string.into_boxed_str();
    
      // set json_string pointer to boxed output_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to generate blind signature commitment: {:?}", error), json_string); }
  }
}

/// Verify Blind Signature Commitment Context
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_verify_blind_signature_proof(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_verify_blind_signature_proof(context_json) {
    Ok(mut output_string) => {
      // add null terminator (for C-string)
      output_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = output_string.into_boxed_str();
    
      // set json_string pointer to boxed output_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to verify blind signature commitment: {:?}", error), json_string); }
  }
}

/// Blind Sign Messages
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_blind_sign(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_blind_sign(context_json) {
    Ok(mut output_string) => {
      // add null terminator (for C-string)
      output_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = output_string.into_boxed_str();
    
      // set json_string pointer to boxed output_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to generate blind signature: {:?}", error), json_string); }
  }
}

/// Unblind blinded signature
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_get_unblinded_signature(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_unblind_signature(context_json) {
    Ok(mut output_string) => {
      // add null terminator (for C-string)
      output_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = output_string.into_boxed_str();
    
      // set json_string pointer to boxed output_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to unblind signature: {:?}", error), json_string); }
  }
}

/// Verify signature
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_verify(
  context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", json_string); }
      }
    },
    Err(_) => { handle_err!("Context not set", json_string); }
  };

  // Serialize response to a JSON string
  match rust_bbs_verify(context_json) {
    Ok(mut output_string) => {
      // add null terminator (for C-string)
      output_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = output_string.into_boxed_str();
    
      // set json_string pointer to boxed output_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(error) => { handle_err!(format!("Failed to verify signature: {:?}", error), json_string); }
  }
}

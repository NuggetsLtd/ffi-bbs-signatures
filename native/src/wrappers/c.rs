#[macro_use]
mod macros;

pub mod ffi;

use bbs::prelude::*;
use crate::rust_bbs::{
  BlindingContext,
  rust_bbs_blind_signature_commitment
};
use std::os::raw::c_char;
use serde_json::{Value, json};
use std::collections::{BTreeMap};

#[repr(C)]
pub struct JsonString {
  ptr: *const c_char,
}

#[no_mangle]
pub unsafe extern "C" fn ffi_bbs_signatures_free_json_string(json_string: JsonString) {
  let _ = Box::from_raw(json_string.ptr as *mut c_char);
}

/// Generate Blind Signature Commitment JSON
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_blind_signature_commitment(
  blinding_context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let blinding_context_json: Value = match String::from_utf8(blinding_context.to_vec()) {
    Ok(blinding_context_string) => {
      match serde_json::from_str(&blinding_context_string) {
        Ok(blinding_context_json) => blinding_context_json,
        Err(_) => { handle_err!("Failed parsing JSON for blinding context", json_string); }
      }
    },
    Err(_) => { handle_err!("Blinding context not set", json_string); }
  };

  // convert public key base64 string to `PublicKey` instance
  let public_key = match blinding_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Public key not set", json_string); }
  };

  // get `blinded` values as array
  let blinded = match blinding_context_json["blinded"].as_array() {
    Some(blinded) => blinded,
    None => { handle_err!("Blinded message indexes array not set", json_string); }
  };

  // get `messages` values as array
  let messages_to_blind = match blinding_context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Messages data array not set", json_string); }
  };

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match blinding_context_json["nonce"].as_str() {
    Some(nonce) => ProofNonce::hash(base64::decode(nonce).unwrap().as_slice()),
    None => { handle_err!("Nonce not set", json_string); }
  };
  
  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = BTreeMap::new();
  let message_count = public_key.message_count() as u64;

  for i in 0..blinded.len() {
      let index = blinded[i].as_u64().unwrap();
      if index > message_count {
        handle_err!(format!(
          "Index is out of bounds. Must be between {} and {}: found {}",
          0,
          public_key.message_count(),
          index
        ), json_string);
      }

      // add message to tree map
      messages.insert(index as usize, SignatureMessage::hash(base64::decode(messages_to_blind[i].as_str().unwrap()).unwrap().as_slice()));
  }

  let bcx = BlindingContext {
    public_key,
    messages,
    nonce
  };

  // generate blind signature commitment
  match rust_bbs_blind_signature_commitment(&bcx) {
    Ok((blinding_context, blinding_factor)) => {
      let blind_commitment_context = json!({
        "commitment": base64::encode(blinding_context.commitment.to_bytes_compressed_form().as_slice()),
        "challenge_hash": base64::encode(blinding_context.challenge_hash.to_bytes_compressed_form().as_slice()),
        "blinding_factor": base64::encode(blinding_factor.to_bytes_compressed_form().as_slice()),
        "proof_of_hidden_messages": base64::encode(blinding_context.proof_of_hidden_messages.to_bytes_compressed_form().as_slice()),
      });

      // Serialize `BlindCommitmentContext` to a JSON string
      match serde_json::to_string(&blind_commitment_context) {
        Ok(mut blind_commitment_context_string) => {
          // add null terminator (for C-string)
          blind_commitment_context_string.push('\0');
    
          // box the string, so string isn't de-allocated on leaving the scope of this fn
          let boxed: Box<str> = blind_commitment_context_string.into_boxed_str();
        
          // set json_string pointer to boxed blind_commitment_context_string
          json_string.ptr = Box::into_raw(boxed).cast();
    
          0
        },
        Err(_) => { handle_err!("Failed to stringify 'BlindCommitmentContext'", json_string); }
      }
    },
    Err(error) => { handle_err!(format!("Failed to generate blind signature commitment: {}", error), json_string); }
  }
}

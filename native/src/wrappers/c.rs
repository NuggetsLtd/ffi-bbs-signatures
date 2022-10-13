#[macro_use]
mod macros;

pub mod ffi;

use bbs::prelude::*;
use crate::rust_bbs::{
  BlindingContext,
  rust_bbs_blind_signature_size,
  rust_bbs_blinding_factor_size,
  rust_bls_public_key_g1_size,
  rust_bls_public_key_g2_size,
  rust_bls_secret_key_size,
  rust_bbs_signature_size,
  rust_bbs_blind_signature_commitment,
  rust_bbs_verify_blind_signature_proof,
  rust_bbs_blind_sign,
  rust_bbs_unblind_signature,
  rust_bbs_verify,
  rust_bbs_create_proof,
  rust_bbs_verify_proof,
};
use std::os::raw::c_char;
use serde_json::{Value, json};
use std::collections::{BTreeMap,BTreeSet};

use bbs::{
  pm_revealed_raw,
  pm_hidden_raw,
};

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

  // convert seed base64 string to slice
  let (bf_bytes, pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => crate::bls_generate_blinded_g1_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'", json_string); }
      }
    },
    None => crate::bls_generate_blinded_g1_key(None)
  };

  let blinded_g1_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
    "blinding_factor": base64::encode(bf_bytes.as_slice()),
  });

  // Serialize blinded G1 key to a JSON string
  match serde_json::to_string(&blinded_g1_key) {
    Ok(mut blinded_g1_key_string) => {
      // add null terminator (for C-string)
      blinded_g1_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = blinded_g1_key_string.into_boxed_str();
    
      // set json_string pointer to boxed blinded_g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => { handle_err!("Failed to stringify Blinded G1 key", json_string); }
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

  // convert seed base64 string to slice
  let (bf_bytes, pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => crate::bls_generate_blinded_g2_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'", json_string); }
      }
    },
    None => crate::bls_generate_blinded_g2_key(None)
  };

  let blinded_g2_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
    "blinding_factor": base64::encode(bf_bytes.as_slice()),
  });

  // Serialize blinded G2 key to a JSON string
  match serde_json::to_string(&blinded_g2_key) {
    Ok(mut blinded_g2_key_string) => {
      // add null terminator (for C-string)
      blinded_g2_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = blinded_g2_key_string.into_boxed_str();
    
      // set json_string pointer to boxed blinded_g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => { handle_err!("Failed to stringify Blinded G2 key", json_string); }
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

  // convert seed base64 string to slice
  let (pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => crate::bls_generate_g1_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'", json_string); }
      }
    },
    None => crate::bls_generate_g1_key(None)
  };

  let g1_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
  });

  // Serialize  G1 key to a JSON string
  match serde_json::to_string(&g1_key) {
    Ok(mut g1_key_string) => {
      // add null terminator (for C-string)
      g1_key_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = g1_key_string.into_boxed_str();
    
      // set json_string pointer to boxed g1_key_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => { handle_err!("Failed to stringify G1 key", json_string); }
  }
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
    None => { handle_err!("Property not set: 'public_key'", json_string); }
  };

  // get `blinded` values as array
  let blinded = match blinding_context_json["blinded"].as_array() {
    Some(blinded) => blinded,
    None => { handle_err!("Property not set: 'blinded'", json_string); }
  };

  // get `messages` values as array
  let messages_to_blind = match blinding_context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", json_string); }
  };

  if blinded.len() != messages_to_blind.len() {
    handle_err!(format!(
      "hidden length is not the same as messages length: {} != {}",
      blinded.len(),
      messages_to_blind.len()
    ), json_string);
  }

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match blinding_context_json["nonce"].as_str() {
    Some(nonce) => ProofNonce::hash(base64::decode(nonce).unwrap().as_slice()),
    None => ProofNonce::hash(b"bbs+rustffiwrapper".to_vec())
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

/// Verify Blind Signature Commitment Context
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_verify_blind_signature_proof(
  commitment_context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let commitment_context_json: Value = match String::from_utf8(commitment_context.to_vec()) {
    Ok(commitment_context_string) => {
      match serde_json::from_str(&commitment_context_string) {
        Ok(commitment_context) => commitment_context,
        Err(_) => { handle_err!("Failed parsing JSON for commitment context", json_string); }
      }
    },
    Err(_) => { handle_err!("Commitment context not set", json_string); }
  };

  // convert 'commitment' base64 string to `Commitment` instance
  let commitment;
  match commitment_context_json["commitment"].as_str() {
    Some(commitment_b64) => {
      let commitment_b64 = base64::decode(commitment_b64).unwrap().to_vec();
      commitment = Commitment::from(*array_ref![
        commitment_b64,
        0,
        G1_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'commitment'", json_string); }
  }

  // convert 'challenge_hash' base64 string to `ProofChallenge` instance
  let challenge_hash;
  match commitment_context_json["challenge_hash"].as_str() {
    Some(challenge_hash_b64) => {
      let challenge_hash_b64 = base64::decode(challenge_hash_b64).unwrap().to_vec();
      challenge_hash = ProofChallenge::from(*array_ref![
        challenge_hash_b64,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'challenge_hash'", json_string); }
  }

  // convert public key base64 string to `PublicKey` instance
  let public_key = match commitment_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", json_string); }
  };

  // convert public key base64 string to `PublicKey` instance
  let proof_of_hidden_messages = match commitment_context_json["proof_of_hidden_messages"].as_str() {
    Some(proof_of_hidden_messages) => ProofG1::from_bytes_compressed_form(base64::decode(proof_of_hidden_messages).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'proof_of_hidden_messages'", json_string); }
  };
  
  // map `blinded` serde array values to Vec
  let blinded: Vec<u64> = match commitment_context_json["blinded"].as_array() {
    Some(blinded) => blinded.into_iter().map(|b| match b.as_u64() {
      Some(index) => index,
      None => { handle_err!("Blinded message indexes must be unsigned integer", json_string); }
    }).collect(),
    None => { handle_err!("Blinded message indexes array not set", json_string); }
  };

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match commitment_context_json["nonce"].as_str() {
    Some(nonce) => ProofNonce::hash(base64::decode(nonce).unwrap().as_slice()),
    None => ProofNonce::hash(b"bbs+rustffiwrapper".to_vec())
  };

  let commitment_context = BlindSignatureContext {
    commitment,
    proof_of_hidden_messages,
    challenge_hash,
  };

  match rust_bbs_verify_blind_signature_proof(&commitment_context, public_key, blinded, nonce) {
    Ok(verified) => {
      let verification_outcome = json!({
        "verified": verified
      });

      // Serialize verification outcome to JSON string
      match serde_json::to_string(&verification_outcome) {
        Ok(mut verification_outcome_string) => {
          // add null terminator (for C-string)
          verification_outcome_string.push('\0');
    
          // box the string, so string isn't de-allocated on leaving the scope of this fn
          let boxed: Box<str> = verification_outcome_string.into_boxed_str();
        
          // set json_string pointer to boxed verification_outcome_string
          json_string.ptr = Box::into_raw(boxed).cast();
    
          0
        },
        Err(_) => { handle_err!("Failed to stringify verification outcome", json_string); }
      }
    },
    Err(_) => { handle_err!("Unable to verify commitment context", json_string); }
  }
}

/// Blind Sign Messages
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_blind_sign(
  blind_sign_context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let blind_sign_context_json: Value = match String::from_utf8(blind_sign_context.to_vec()) {
    Ok(blind_sign_context_string) => {
      match serde_json::from_str(&blind_sign_context_string) {
        Ok(blind_sign_context) => blind_sign_context,
        Err(_) => { handle_err!("Failed parsing JSON for blind sign context", json_string); }
      }
    },
    Err(_) => { handle_err!("Blind sign context not set", json_string); }
  };

  // convert 'secret_key' base64 string to `SecretKey` instance
  let secret_key;
  match blind_sign_context_json["secret_key"].as_str() {
    Some(secret_key_b64) => {
      let secret_key_b64 = base64::decode(secret_key_b64).unwrap().to_vec();
      secret_key = SecretKey::from(*array_ref![
        secret_key_b64,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'secret_key'", json_string); }
  }

  // convert public key base64 string to `PublicKey` instance
  let public_key = match blind_sign_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", json_string); }
  };
  
  // map `known` serde array values to Vec
  let known: Vec<u64> = match blind_sign_context_json["known"].as_array() {
    Some(known) => known.into_iter().map(|b| match b.as_u64() {
      Some(index) => index,
      None => { handle_err!("Known message indexes must be unsigned integer", json_string); }
    }).collect(),
    None => { handle_err!("Known message indexes array not set", json_string); }
  };

  // get `messages` values as array
  let messages_visible = match blind_sign_context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Messages data array not set", json_string); }
  };

  if known.len() != messages_visible.len() {
    handle_err!(format!(
      "known length is not the same as messages length: {} != {}",
      known.len(),
      messages_visible.len()
    ), json_string);
  }

  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = BTreeMap::new();
  let message_count = public_key.message_count() as u64;

  for i in 0..known.len() {
      let index = known[i];
      if index > message_count {
        handle_err!(format!(
          "Index is out of bounds. Must be between {} and {}: found {}",
          0,
          public_key.message_count(),
          index
        ), json_string);
      }

      // add message to tree map
      messages.insert(index as usize, SignatureMessage::hash(base64::decode(messages_visible[i].as_str().unwrap()).unwrap().as_slice()));
  }

  // convert 'commitment' base64 string to `Commitment` instance
  let commitment;
  match blind_sign_context_json["commitment"].as_str() {
    Some(commitment_b64) => {
      let commitment_b64 = base64::decode(commitment_b64).unwrap().to_vec();
      commitment = Commitment::from(*array_ref![
        commitment_b64,
        0,
        G1_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'commitment'", json_string); }
  }

  match rust_bbs_blind_sign(&commitment, &messages, &secret_key, &public_key) {
    Ok(signature) => {
      let signature_outcome = json!({
        "blind_signature": base64::encode(signature.to_bytes_compressed_form().as_slice()),
      });

      // Serialize verification outcome to JSON string
      match serde_json::to_string(&signature_outcome) {
        Ok(mut signature_outcome_string) => {
          // add null terminator (for C-string)
          signature_outcome_string.push('\0');
    
          // box the string, so string isn't de-allocated on leaving the scope of this fn
          let boxed: Box<str> = signature_outcome_string.into_boxed_str();
        
          // set json_string pointer to boxed signature_outcome_string
          json_string.ptr = Box::into_raw(boxed).cast();
    
          0
        },
        Err(_) => { handle_err!("Failed to stringify blind signature", json_string); }
      }
    },
    Err(_) => { handle_err!("Unable to blind sign messages", json_string); }
  }
}

/// Unblind blinded signature
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_get_unblinded_signature(
  blind_signature_context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let blind_signature_context_json: Value = match String::from_utf8(blind_signature_context.to_vec()) {
    Ok(blind_signature_context_string) => {
      match serde_json::from_str(&blind_signature_context_string) {
        Ok(blind_signature_context) => blind_signature_context,
        Err(_) => { handle_err!("Failed parsing JSON for blind signature context", json_string); }
      }
    },
    Err(_) => { handle_err!("Blind signature context not set", json_string); }
  };

  // convert 'blind_signature' base64 string to `BlindSignature` instance
  let blind_signature;
  match blind_signature_context_json["blind_signature"].as_str() {
    Some(blind_signature_b64) => {
      let blind_signature_b64 = base64::decode(blind_signature_b64).unwrap().to_vec();
      blind_signature = BlindSignature::from(*array_ref![
        blind_signature_b64,
        0,
        SIGNATURE_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'blind_signature'", json_string); }
  };

  // convert 'blinding_factor' base64 string to `SignatureBlinding` instance
  let blinding_factor;
  match blind_signature_context_json["blinding_factor"].as_str() {
    Some(blinding_factor_b64) => {
      let blinding_factor_b64 = base64::decode(blinding_factor_b64).unwrap().to_vec();
      blinding_factor = SignatureBlinding::from(*array_ref![
        blinding_factor_b64,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'blinding_factor'", json_string); }
  };

  let unblinded_signature = rust_bbs_unblind_signature(&blind_signature, &blinding_factor);

  let signature_outcome = json!({
    "signature": base64::encode(unblinded_signature.to_bytes_compressed_form().as_slice()),
  });

  // Serialize verification outcome to JSON string
  match serde_json::to_string(&signature_outcome) {
    Ok(mut signature_outcome_string) => {
      // add null terminator (for C-string)
      signature_outcome_string.push('\0');

      // box the string, so string isn't de-allocated on leaving the scope of this fn
      let boxed: Box<str> = signature_outcome_string.into_boxed_str();
    
      // set json_string pointer to boxed signature_outcome_string
      json_string.ptr = Box::into_raw(boxed).cast();

      0
    },
    Err(_) => { handle_err!("Failed to stringify unblinded signature", json_string); }
  }
}

/// Verify signature
///
/// # SAFETY
/// The `json_string.ptr` pointer needs to follow the same safety requirements
/// as Rust's `std::ffi::CStr::from_ptr`
#[no_mangle]
pub unsafe extern "C" fn bbs_verify(
  verify_signature_context: ffi::ByteArray,
  json_string: &mut JsonString,
) -> i32 {
  // convert JSON string to JSON
  let verify_signature_context_json: Value = match String::from_utf8(verify_signature_context.to_vec()) {
    Ok(verify_signature_context_string) => {
      match serde_json::from_str(&verify_signature_context_string) {
        Ok(verify_signature_context) => verify_signature_context,
        Err(_) => { handle_err!("Failed parsing JSON for verify signature context", json_string); }
      }
    },
    Err(_) => { handle_err!("Verify signature context not set", json_string); }
  };

  // convert public key base64 string to `PublicKey` instance
  let public_key = match verify_signature_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", json_string); }
  };

  // convert 'blind_signature' base64 string to `BlindSignature` instance
  let signature;
  match verify_signature_context_json["signature"].as_str() {
    Some(signature_b64) => {
      let signature_b64 = base64::decode(signature_b64).unwrap().to_vec();
      signature = Signature::from(*array_ref![
        signature_b64,
        0,
        SIGNATURE_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'signature'", json_string); }
  };

  // get `messages` values as array
  let messages_array = match verify_signature_context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", json_string); }
  };

  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = Vec::new();

  for i in 0..messages_array.len() {
      // add message to Vec
      messages.push(SignatureMessage::hash(base64::decode(messages_array[i].as_str().unwrap()).unwrap().as_slice()));
  }

  match rust_bbs_verify(&signature, &messages, &public_key) {
    Ok(verified) => {
      let verify_outcome = json!({
        "verified": verified,
      });
    
      // Serialize verification outcome to JSON string
      match serde_json::to_string(&verify_outcome) {
        Ok(mut verify_outcome_string) => {
          // add null terminator (for C-string)
          verify_outcome_string.push('\0');
    
          // box the string, so string isn't de-allocated on leaving the scope of this fn
          let boxed: Box<str> = verify_outcome_string.into_boxed_str();
        
          // set json_string pointer to boxed verify_outcome_string
          json_string.ptr = Box::into_raw(boxed).cast();
    
          0
        },
        Err(_) => { handle_err!("Failed to stringify verification outcome", json_string); }
      }
    },
    Err(_) => { handle_err!("Unable to verify messages", json_string); }
  }
}

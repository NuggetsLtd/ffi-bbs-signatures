#[macro_use]
mod macros;

use neon::prelude::*;
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
use serde_json::{json};

/// Get size of G1 public key
fn node_bls_public_key_g1_size(mut cx: FunctionContext) -> JsResult<JsNumber> {
  let size = rust_bls_public_key_g1_size();
  Ok(cx.number(size))
}

/// Get size of G2 public key
fn node_bls_public_key_g2_size(mut cx: FunctionContext) -> JsResult<JsNumber> {
  let size = rust_bls_public_key_g2_size();
  Ok(cx.number(size))
}

/// Get size of blinding factor
fn node_bbs_blinding_factor_size(mut cx: FunctionContext) -> JsResult<JsNumber> {
  let size = rust_bbs_blinding_factor_size();
  Ok(cx.number(size))
}

/// Get size of bls secret key
fn node_bls_secret_key_size(mut cx: FunctionContext) -> JsResult<JsNumber> {
  let size = rust_bls_secret_key_size();
  Ok(cx.number(size))
}

/// Get size of bbs signature
fn node_bbs_signature_size(mut cx: FunctionContext) -> JsResult<JsNumber> {
  let size = rust_bbs_signature_size();
  Ok(cx.number(size))
}

/// Get size of blind signature
fn node_bbs_blind_signature_size(mut cx: FunctionContext) -> JsResult<JsNumber> {
  let size = rust_bbs_blind_signature_size();
  Ok(cx.number(size))
}

/// Generate Blinded G1 key
fn node_bls_generate_blinded_g1_key(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bls_generate_blinded_g1_key(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to generate blinded G1 key", cx); }
  }
}

/// Generate Blinded G2 key
fn node_bls_generate_blinded_g2_key(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bls_generate_blinded_g2_key(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to generate blinded G2 key", cx); }
  }
}

/// Generate G1 key
fn node_bls_generate_g1_key(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bls_generate_g1_key(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to generate G1 key", cx); }
  }
}

/// Generate G2 key
fn node_bls_generate_g2_key(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bls_generate_g2_key(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to generate G2 key", cx); }
  }
}

/// Convert BLS Secret Key to BBS Public Key
fn node_bls_secret_key_to_bbs_key(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bls_secret_key_to_bbs_key(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to convert to BBS key", cx); }
  }
}

/// Convert BLS Public Key to BBS Public Key
fn node_bls_public_key_to_bbs_key(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bls_public_key_to_bbs_key(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to convert to BBS key", cx); }
  }
}

/// BBS Sign
fn node_bbs_sign(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_sign(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to sign messages", cx); }
  }
}

/// Verify a BBS+ signature
/// The first argument is the domain separation label
/// The second argument is the public key `w` created from bls_generate_key
/// The third argument is the signature to be verified.
/// The remaining values are the messages that were signed
///
/// `signature_context`: `Object` the context for verifying the signature
/// {
///     "publicKey": ArrayBuffer                // The public key
///     "signature": ArrayBuffer                // The signature
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that were signed as strings. They will be Blake2b hashed
/// }
///
/// `return`: true if valid `signature` on `messages`
fn node_bbs_verify(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_verify(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(error) => { handle_err!(format!("Unable to verify signed messages: {:?}", error), cx); }
  }
}

/// BBS Create Proof
fn node_bbs_create_proof(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_create_proof(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to generate proof", cx); }
  }
}

/// BLS Verify Proof
fn node_bls_verify_proof(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bls_verify_proof(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to verify proof", cx); }
  }
}

/// BBS Verify Proof
fn node_bbs_verify_proof(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_verify_proof(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to verify proof", cx); }
  }
}

/// Generate Blind Signature Commitment JSON
fn node_bbs_blind_signature_commitment(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_blind_signature_commitment(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to generate blind signing commitment", cx); }
  }
}

/// Verify Blind Signature Commitment JSON
fn node_bbs_verify_blind_signature_proof(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_verify_blind_signature_proof(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to verify blind signing commitment", cx); }
  }
}

/// Blind Sign Messages
fn node_bbs_blind_sign(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_blind_sign(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to blind sign messages", cx); }
  }
}

/// Unblind blinded signature
fn node_bbs_get_unblinded_signature(mut cx: FunctionContext) -> JsResult<JsString> {
  let context = arg_to_slice!(cx, 0);

  // convert JSON string to JSON
  let context_json: serde_json::Value = match String::from_utf8(context.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context_json) => context_json,
        Err(_) => { handle_err!("Failed parsing JSON for context", cx); }
      }
    },
    Err(_) => { handle_err!("Context not set", cx); }
  };

  match rust_bbs_unblind_signature(context_json) {
    Ok(output_string) => Ok(cx.string(output_string)),
    Err(_) => { handle_err!("Unable to unblind blinded signature", cx); }
  }
}

register_module!(mut cx, {
  cx.export_function("bbs_blind_signature_size", node_bbs_blind_signature_size)?;
  cx.export_function("bbs_blinding_factor_size", node_bbs_blinding_factor_size)?;
  cx.export_function("bls_public_key_g1_size", node_bls_public_key_g1_size)?;
  cx.export_function("bls_public_key_g2_size", node_bls_public_key_g2_size)?;
  cx.export_function("bls_secret_key_size", node_bls_secret_key_size)?;
  cx.export_function("bbs_signature_size", node_bbs_signature_size)?;
  cx.export_function("bls_generate_blinded_g1_key", node_bls_generate_blinded_g1_key)?;
  cx.export_function("bls_generate_blinded_g2_key", node_bls_generate_blinded_g2_key)?;
  cx.export_function("bls_generate_g1_key", node_bls_generate_g1_key)?;
  cx.export_function("bls_generate_g2_key", node_bls_generate_g2_key)?;
  cx.export_function("bls_secret_key_to_bbs_key", node_bls_secret_key_to_bbs_key)?;
  cx.export_function("bls_public_key_to_bbs_key", node_bls_public_key_to_bbs_key)?;
  cx.export_function("bbs_sign", node_bbs_sign)?;
  cx.export_function("bbs_verify", node_bbs_verify)?;
  cx.export_function("bbs_create_proof", node_bbs_create_proof)?;
  cx.export_function("bbs_verify_proof", node_bbs_verify_proof)?;
  cx.export_function("bls_verify_proof", node_bls_verify_proof)?;
  cx.export_function(
      "bbs_blind_signature_commitment",
      node_bbs_blind_signature_commitment,
  )?;
  cx.export_function(
      "bbs_verify_blind_signature_proof",
      node_bbs_verify_blind_signature_proof,
  )?;
  cx.export_function("bbs_blind_sign", node_bbs_blind_sign)?;
  cx.export_function("bbs_get_unblinded_signature", node_bbs_get_unblinded_signature)?;
  Ok(())
});

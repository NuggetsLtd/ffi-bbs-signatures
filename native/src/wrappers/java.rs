#[macro_use]
mod macros;

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
use serde_json::{Value, json};
use std::collections::{BTreeMap,BTreeSet};

// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JClass, JObject, JString};

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jstring, jbyteArray, jint};

// use crate::*;
use crate::{
  bls_generate_blinded_g1_key,
  bls_generate_blinded_g2_key,
  bls_generate_g1_key,
  bls_generate_g2_key,
};
use bbs::keys::{DeterministicPublicKey, KeyGenOption, SecretKey, DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE, PublicKey};
use bbs::{ToVariableLengthBytes, FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE};
use bbs::{
  pm_revealed_raw,
  pm_hidden_raw,
};

use std::cell::RefCell;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_get_1last_1error<'a>(env: JNIEnv<'a>, _: JObject) -> JString<'a> {
    let mut res = env.new_string("").unwrap();
    LAST_ERROR.with(|prev| {
        match &*prev.borrow() {
            Some(s) => res = env.new_string(s).unwrap(),
            None => ()
        };
    });
    res
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bls_1public_1key_1g1_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
  rust_bls_public_key_g1_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bls_1public_1key_1g2_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
  rust_bls_public_key_g2_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_blinding_1factor_1size(_: JNIEnv, _: JObject) -> jint {
  rust_bbs_blinding_factor_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bls_1secret_1key_1size(_: JNIEnv, _: JObject) -> jint {
  rust_bls_secret_key_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bbs_1signature_1size(_: JNIEnv, _: JObject) -> jint {
  rust_bbs_signature_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bbs_1blind_1signature_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
  rust_bbs_blind_signature_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1blinded_1g1_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
      Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
      Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert seed base64 string to slice
  let (bf_bytes, pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_blinded_g1_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'", env); }
      }
    },
    None => bls_generate_blinded_g1_key(None)
  };

  let blinded_g1_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
    "blinding_factor": base64::encode(bf_bytes.as_slice()),
  });

  // Serialize `BlindCommitmentContext` to a JSON string
  match serde_json::to_string(&blinded_g1_key) {
    Ok(blinded_g1_key_string) => {
      let output = env
          .new_string(blinded_g1_key_string)
          .expect("Unable to create string from blinded G1 key data");
    
      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify blinded G1 key", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1blinded_1g2_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert seed base64 string to slice
  let (bf_bytes, pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_blinded_g2_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'", env); }
      }
    },
    None => bls_generate_blinded_g2_key(None)
  };

  let blinded_g2_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
    "blinding_factor": base64::encode(bf_bytes.as_slice()),
  });

  // Serialize `BlindCommitmentContext` to a JSON string
  match serde_json::to_string(&blinded_g2_key) {
    Ok(blinded_g2_key_string) => {
      let output = env
          .new_string(blinded_g2_key_string)
          .expect("Unable to create string from blinded G2 key data");
    
      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify blinded G2 key", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1g1_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert seed base64 string to slice
  let (pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_g1_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'", env); }
      }
    },
    None => bls_generate_g1_key(None)
  };

  let g1_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
  });

  // Serialize `BlindCommitmentContext` to a JSON string
  match serde_json::to_string(&g1_key) {
    Ok(g1_key_string) => {
      let output = env
          .new_string(g1_key_string)
          .expect("Unable to create string from G1 key data");
    
      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify G1 key", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1g2_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert seed base64 string to slice
  let (pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_g2_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'", env); }
      }
    },
    None => bls_generate_g2_key(None)
  };

  let g2_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
  });

  // Serialize `BlindCommitmentContext` to a JSON string
  match serde_json::to_string(&g2_key) {
    Ok(g2_key_string) => {
      let output = env
          .new_string(g2_key_string)
          .expect("Unable to create string from G2 key data");
    
      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify G2 key", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1secret_1key_1to_1bbs_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // get message count
  let message_count = match context_json["message_count"].as_u64() {
    Some(message_count) => message_count,
    None => { handle_err!("Property not set: 'message_count'", env); }
  };

  // convert 'secret_key' base64 string to `SecretKey` instance
  let secret_key;
  match context_json["secret_key"].as_str() {
    Some(secret_key_b64) => {
      let secret_key_bytes = base64::decode(secret_key_b64).unwrap().to_vec();
      secret_key = SecretKey::from(*array_ref![
        secret_key_bytes,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'secret_key'", env); }
  }

  // convert secret key to deterministic public key
  let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(secret_key)));

  // convert deterministic public key to compressed BBS public key
  let pk;
  match dpk.to_public_key(message_count as usize) {
    Ok(p) => pk = p,
    Err(_) => { handle_err!("Failed to convert to BBS public key", env); },
  }
  if pk.validate().is_err() {
    handle_err!("Failed to validate public key", env);
  }

  let pk_bytes = pk.to_bytes_compressed_form();

  let bbs_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice())
  });

  // Serialize `BlindCommitmentContext` to a JSON string
  match serde_json::to_string(&bbs_key) {
    Ok(bbs_key_string) => {
      let output = env
          .new_string(bbs_key_string)
          .expect("Unable to create string from BBS key data");
    
      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify BBS key", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1public_1key_1to_1bbs_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // get message count
  let message_count = match context_json["message_count"].as_u64() {
    Some(message_count) => message_count,
    None => { handle_err!("Property not set: 'message_count'", env); }
  };

  // convert 'public_key' base64 string to `SecretKey` instance
  let dpk;
  match context_json["public_key"].as_str() {
    Some(public_key_b64) => {
      let public_key_bytes = base64::decode(public_key_b64).unwrap().to_vec();
      dpk = DeterministicPublicKey::from(*array_ref![
        public_key_bytes,
        0,
        DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'public_key'", env); }
  }

  // convert deterministic public key to compressed BBS public key
  let pk;
  match dpk.to_public_key(message_count as usize) {
    Ok(p) => pk = p,
    Err(_) => { handle_err!("Failed to convert to BBS public key", env); },
  }
  if pk.validate().is_err() {
    handle_err!("Failed to validate public key", env);
  }

  let pk_bytes = pk.to_bytes_compressed_form();

  let bbs_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice())
  });

  // Serialize `BlindCommitmentContext` to a JSON string
  match serde_json::to_string(&bbs_key) {
    Ok(bbs_key_string) => {
      let output = env
          .new_string(bbs_key_string)
          .expect("Unable to create string from BBS key data");
    
      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify BBS key", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1sign(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert 'secret_key' base64 string to `SecretKey` instance
  let secret_key;
  match context_json["secret_key"].as_str() {
    Some(secret_key_b64) => {
      let secret_key_bytes = base64::decode(secret_key_b64).unwrap().to_vec();
      secret_key = SecretKey::from(*array_ref![
        secret_key_bytes,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'secret_key'", env); }
  }

  // convert 'public_key' base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", env); }
  };

  if public_key.validate().is_err() {
    handle_err!("Invalid public key", env);
  }

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", env); }
  };

  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = Vec::new();

  for i in 0..messages_array.len() {
    // add message to Vec
    messages.push(SignatureMessage::hash(base64::decode(messages_array[i].as_str().unwrap()).unwrap().as_slice()));
  }

  // Serialize `Signature` to a JSON string
  let signature = match Signature::new(messages.as_slice(), &secret_key, &public_key) {
    Ok(signature) => signature,
    Err(_) => { handle_err!("Failed to sign messages", env); }
  };

  let bbs_signature = json!({
    "signature": base64::encode(signature.to_bytes_compressed_form())
  });

  // Serialize `BlindCommitmentContext` to a JSON string
  match serde_json::to_string(&bbs_signature) {
    Ok(bbs_signature_string) => {
      let output = env
          .new_string(bbs_signature_string)
          .expect("Unable to create string from BBS signature data");
    
      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify BBS key", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1create_1proof(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert 'signature' base64 string to `Signature` instance
  let signature;
  match context_json["signature"].as_str() {
    Some(signature_b64) => {
      let signature_b64 = base64::decode(signature_b64).unwrap().to_vec();
      signature = Signature::from(*array_ref![
        signature_b64,
        0,
        SIGNATURE_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'signature'", env); }
  };

  // convert 'public_key' base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", env); }
  };

  if public_key.validate().is_err() {
    handle_err!("Invalid public key", env);
  }

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", env); }
  };

  // map `revealed` serde array values to Vec
  let revealed_indices: Vec<i64> = match context_json["revealed"].as_array() {
    Some(revealed) => revealed.into_iter().map(|b| match b.as_i64() {
      Some(index) => index,
      None => -1,
    }).collect(),
    None => { handle_err!("Property not set: 'revealed'", env); }
  };

  let message_count = messages_array.len() as i64;

  let mut revealed = BTreeSet::new();
  for i in 0..revealed_indices.len() {
    let index = revealed_indices[i];
    if index < 0 {
      handle_err!(format!(
        "Invalid index for 'revealed'. Must be integer between {} and {}",
        0,
        message_count
      ), env);
    }
    if index > message_count {
      handle_err!(format!(
        "Index for 'revealed' is out of bounds. Must be between {} and {}: found {}",
        0,
        message_count,
        index
      ), env);
    }
    revealed.insert(index as usize);
  }

  let mut messages = Vec::new();
  for i in 0..messages_array.len() {
    let message = SignatureMessage::hash(base64::decode(messages_array[i].as_str().unwrap()).unwrap().as_slice());

    if revealed.contains(&i) {
      messages.push(
        pm_revealed_raw!(message)
      );
    } else {
      messages.push(pm_hidden_raw!(message));
    }
  }

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match context_json["nonce"].as_str() {
    Some(nonce) => Some(base64::decode(nonce).unwrap()),
    None => None
  };

  match rust_bbs_create_proof(&signature, &public_key, &messages, &revealed, nonce) {
    Ok(pok) => {
      let proof = json!({
        "proof": base64::encode(pok)
      });
    
      // Serialize proof to a JSON string
      match serde_json::to_string(&proof) {
        Ok(proof_string) => {
          let output = env
              .new_string(proof_string)
              .expect("Unable to create string from BBS proof data");
        
          output.into_inner()
        },
        Err(_) => { handle_err!("Failed to stringify BBS proof", env); }
      }
    },
    Err(error) => { handle_err!(format!("Failed generating proof of knowledge: {}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1verify_1proof(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert proof base64 string to `Proofproof` instance
  let proof = match context_json["proof"].as_str() {
    Some(proof) => base64::decode(proof).unwrap(),
    None => { handle_err!("Property not set: 'proof'", env); }
  };

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match context_json["nonce"].as_str() {
    Some(nonce) => Some(base64::decode(nonce).unwrap()),
    None => None
  };

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", env); }
  };

  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = Vec::new();

  for i in 0..messages_array.len() {
    // add message to Vec
    messages.push(SignatureMessage::hash(base64::decode(messages_array[i].as_str().unwrap()).unwrap().as_slice()));
  }
  
  // convert public key base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", env); }
  };

  match rust_bbs_verify_proof(&proof, public_key, &messages, nonce) {
    Ok(verified) => {
      let verify_outcome = json!({
        "verified": verified,
      });
    
      // Serialize verification outcome to JSON string
      match serde_json::to_string(&verify_outcome) {
        Ok(verify_outcome_string) => {
          let output = env
            .new_string(verify_outcome_string)
            .expect("Unable to create string from proof verification outcome");
  
          output.into_inner()
        },
        Err(_) => { handle_err!("Failed to stringify verification outcome", env); }
      }
    },
    Err(error) => { handle_err!(format!("Failed verifying proof of knowledge: {}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1verify_1proof(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  // convert proof base64 string to `Proofproof` instance
  let proof = match context_json["proof"].as_str() {
    Some(proof) => base64::decode(proof).unwrap(),
    None => { handle_err!("Property not set: 'proof'", env); }
  };
  let message_count = u16::from_be_bytes(*array_ref![proof, 0, 2]) as usize;

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match context_json["nonce"].as_str() {
    Some(nonce) => Some(base64::decode(nonce).unwrap()),
    None => None
  };

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", env); }
  };

  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = Vec::new();

  for i in 0..messages_array.len() {
    // add message to Vec
    messages.push(SignatureMessage::hash(base64::decode(messages_array[i].as_str().unwrap()).unwrap().as_slice()));
  }
  
  // convert 'public_key' base64 string to `DeterministicPublicKey` instance
  let dpk;
  match context_json["public_key"].as_str() {
    Some(public_key_b64) => {
      let public_key_bytes = base64::decode(public_key_b64).unwrap().to_vec();
      dpk = DeterministicPublicKey::from(*array_ref![
        public_key_bytes,
        0,
        DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'public_key'", env); }
  }

  match rust_bbs_verify_proof(&proof, dpk.to_public_key(message_count).unwrap(), &messages, nonce) {
    Ok(verified) => {
      let verify_outcome = json!({
        "verified": verified,
      });
    
      // Serialize verification outcome to JSON string
      match serde_json::to_string(&verify_outcome) {
        Ok(verify_outcome_string) => {
          let output = env
            .new_string(verify_outcome_string)
            .expect("Unable to create string from proof verification outcome");
  
          output.into_inner()
        },
        Err(_) => { handle_err!("Failed to stringify verification outcome", env); }
      }
    },
    Err(error) => { handle_err!(format!("Failed verifying proof of knowledge: {}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1blind_1signature_1commitment(
  env: JNIEnv,
  _class: JClass,
  blinding_commitment: jbyteArray,
) -> jstring {
  let blinding_commitment_bytes;
  match env.convert_byte_array(blinding_commitment) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => blinding_commitment_bytes = bc,
  };
  
  // convert JSON string to JSON
  let blinding_context_json: Value = match String::from_utf8(blinding_commitment_bytes.to_vec()) {
    Ok(blinding_context_string) => {
      match serde_json::from_str(&blinding_context_string) {
        Ok(blinding_context_json) => blinding_context_json,
        Err(_) => { handle_err!("Failed parsing JSON for blinding context", env); }
      }
    },
    Err(_) => { handle_err!("Blinding context not set", env); }
  };

  // convert public key base64 string to `PublicKey` instance
  let public_key = match blinding_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", env); }
  };

  // get `blinded` values as array
  let blinded = match blinding_context_json["blinded"].as_array() {
    Some(blinded) => blinded,
    None => { handle_err!("Property not set: 'blinded'", env); }
  };

  // get `messages` values as array
  let messages_to_blind = match blinding_context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", env); }
  };

  if blinded.len() != messages_to_blind.len() {
    handle_err!(format!(
      "hidden length is not the same as messages length: {} != {}",
      blinded.len(),
      messages_to_blind.len()
    ), env);
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
        ), env);
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
        Ok(blind_commitment_context_string) => {
          let output = env
              .new_string(blind_commitment_context_string)
              .expect("Unable to create string from signed data");
        
          output.into_inner()
        },
        Err(_) => { handle_err!("Failed to stringify 'BlindCommitmentContext'", env); }
      }
    },
    Err(error) => { handle_err!(format!("Failed to generate blind signature commitment: {}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1verify_1blind_1signature_1proof(
  env: JNIEnv,
  _class: JClass,
  commitment_context: jbyteArray,
) -> jstring {
  let commitment_context_bytes;
  match env.convert_byte_array(commitment_context) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => commitment_context_bytes = bc,
  };
  
  // convert JSON string to JSON
  let commitment_context_json: Value = match String::from_utf8(commitment_context_bytes.to_vec()) {
    Ok(blinding_context_string) => {
      match serde_json::from_str(&blinding_context_string) {
        Ok(commitment_context_json) => commitment_context_json,
        Err(_) => { handle_err!("Failed parsing JSON for commitment context", env); }
      }
    },
    Err(_) => { handle_err!("Commitment context not set", env); }
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
    None => { handle_err!("Property not set: 'commitment'", env); }
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
    None => { handle_err!("Property not set: 'challenge_hash'", env); }
  }

  // convert public key base64 string to `PublicKey` instance
  let public_key = match commitment_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", env); }
  };

  // convert public key base64 string to `PublicKey` instance
  let proof_of_hidden_messages = match commitment_context_json["proof_of_hidden_messages"].as_str() {
    Some(proof_of_hidden_messages) => ProofG1::from_bytes_compressed_form(base64::decode(proof_of_hidden_messages).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'proof_of_hidden_messages'", env); }
  };
  
  // map `blinded` serde array values to Vec
  let blinded: Vec<i64> = match commitment_context_json["blinded"].as_array() {
    Some(blinded) => blinded.into_iter().map(|b| match b.as_i64() {
      Some(index) => index,
      None => -1,
    }).collect(),
    None => { handle_err!("Blinded message indexes array not set", env); }
  };

  let message_count = public_key.message_count() as i64;

  for i in 0..blinded.len() {
    let index = blinded[i];
    if index < 0 {
      handle_err!(format!(
        "Invalid index for 'blinded'. Must be integer between {} and {}",
        0,
        message_count
      ), env);
    }
    if index > message_count {
      handle_err!(format!(
        "Index for 'blinded' is out of bounds. Must be between {} and {}: found {}",
        0,
        message_count,
        index
      ), env);
    }
  }

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

  match rust_bbs_verify_blind_signature_proof(&commitment_context, public_key, blinded.into_iter().map(|n| n as _).collect::<Vec<u64>>(), nonce) {
    Ok(verified) => {
      let verification_outcome = json!({
        "verified": verified
      });

      // Serialize verification outcome to JSON string
      match serde_json::to_string(&verification_outcome) {
        Ok(verification_outcome_string) => {
          let output = env
              .new_string(verification_outcome_string)
              .expect("Unable to create string from verification outcome");
        
          output.into_inner()
        },
        Err(_) => { handle_err!("Failed to stringify verification outcome", env); }
      }
    },
    Err(_) => { handle_err!("Unable to verify commitment context", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1blind_1sign(
  env: JNIEnv,
  _class: JClass,
  blind_sign_context: jbyteArray,
) -> jstring {
  let blind_sign_context_bytes;
  match env.convert_byte_array(blind_sign_context) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => blind_sign_context_bytes = bc,
  };

  // convert JSON string to JSON
  let blind_sign_context_json: Value = match String::from_utf8(blind_sign_context_bytes.to_vec()) {
    Ok(blind_sign_context_string) => {
      match serde_json::from_str(&blind_sign_context_string) {
        Ok(blind_sign_context) => blind_sign_context,
        Err(_) => { handle_err!("Failed parsing JSON for blind sign context", env); }
      }
    },
    Err(_) => { handle_err!("Blind sign context not set", env); }
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
    None => { handle_err!("Property not set: 'secret_key'", env); }
  }

  // convert public key base64 string to `PublicKey` instance
  let public_key = match blind_sign_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", env); }
  };

  // map `known` serde array values to Vec
  let known: Vec<i64> = match blind_sign_context_json["known"].as_array() {
    Some(known) => known.into_iter().map(|b| match b.as_i64() {
      Some(index) => index,
      None => -1,
    }).collect(),
    None => { handle_err!("Property not set: 'known'", env); }
  };

  // get `messages` values as array
  let messages_visible = match blind_sign_context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", env); }
  };

  if known.len() != messages_visible.len() {
    handle_err!(format!(
      "known length is not the same as messages length: {} != {}",
      known.len(),
      messages_visible.len()
    ), env);
  }

  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = BTreeMap::new();
  let message_count = public_key.message_count() as i64;

  for i in 0..known.len() {
      let index = known[i];
      if index < 0 {
        handle_err!(format!(
          "Invalid index for 'known'. Must be integer between {} and {}",
          0,
          message_count
        ), env);
      }
      if index > message_count {
        handle_err!(format!(
          "Index for 'known' is out of bounds. Must be between {} and {}: found {}",
          0,
          message_count,
          index
        ), env);
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
    None => { handle_err!("Property not set: 'commitment'", env); }
  }

  match rust_bbs_blind_sign(&commitment, &messages, &secret_key, &public_key) {
    Ok(signature) => {
      let signature_outcome = json!({
        "blind_signature": base64::encode(signature.to_bytes_compressed_form().as_slice()),
      });

      // Serialize verification outcome to JSON string
      match serde_json::to_string(&signature_outcome) {
        Ok(signature_outcome_string) => {
          let output = env
              .new_string(signature_outcome_string)
              .expect("Unable to create string from blind signature outcome");
        
          output.into_inner()
        },
        Err(_) => { handle_err!("Failed to stringify blind signature", env); }
      }
    },
    Err(_) => { handle_err!("Unable to blind sign messages", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1get_1unblinded_1signature(
  env: JNIEnv,
  _class: JClass,
  unblind_signature_context: jbyteArray,
) -> jstring {
  let unblind_signature_context_bytes;
  match env.convert_byte_array(unblind_signature_context) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => unblind_signature_context_bytes = bc,
  };

  // convert JSON string to JSON
  let unblind_signature_context_json: Value = match String::from_utf8(unblind_signature_context_bytes.to_vec()) {
    Ok(unblind_signature_context_string) => {
      match serde_json::from_str(&unblind_signature_context_string) {
        Ok(unblind_signature_context) => unblind_signature_context,
        Err(_) => { handle_err!("Failed parsing JSON for unblind signature context", env); }
      }
    },
    Err(_) => { handle_err!("Unblind signature context not set", env); }
  };

  // convert 'blind_signature' base64 string to `BlindSignature` instance
  let blind_signature;
  match unblind_signature_context_json["blind_signature"].as_str() {
    Some(blind_signature_b64) => {
      let blind_signature_b64 = base64::decode(blind_signature_b64).unwrap().to_vec();
      blind_signature = BlindSignature::from(*array_ref![
        blind_signature_b64,
        0,
        SIGNATURE_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'blind_signature'", env); }
  };

  // convert 'blinding_factor' base64 string to `SignatureBlinding` instance
  let blinding_factor;
  match unblind_signature_context_json["blinding_factor"].as_str() {
    Some(blinding_factor_b64) => {
      let blinding_factor_b64 = base64::decode(blinding_factor_b64).unwrap().to_vec();
      blinding_factor = SignatureBlinding::from(*array_ref![
        blinding_factor_b64,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'blinding_factor'", env); }
  };

  let unblinded_signature = rust_bbs_unblind_signature(&blind_signature, &blinding_factor);

  let signature_outcome = json!({
    "signature": base64::encode(unblinded_signature.to_bytes_compressed_form().as_slice()),
  });

  // Serialize verification outcome to JSON string
  match serde_json::to_string(&signature_outcome) {
    Ok(signature_outcome_string) => {
      let output = env
        .new_string(signature_outcome_string)
        .expect("Unable to create string from unblind signature outcome");

      output.into_inner()
    },
    Err(_) => { handle_err!("Failed to stringify signature", env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1verify(
  env: JNIEnv,
  _class: JClass,
  verify_signature_context: jbyteArray,
) -> jstring {
  let verify_signature_context_bytes;
  match env.convert_byte_array(verify_signature_context) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => verify_signature_context_bytes = bc,
  };

  // convert JSON string to JSON
  let verify_signature_context_json: Value = match String::from_utf8(verify_signature_context_bytes.to_vec()) {
    Ok(verify_signature_context_string) => {
      match serde_json::from_str(&verify_signature_context_string) {
        Ok(verify_signature_context) => verify_signature_context,
        Err(_) => { handle_err!("Failed parsing JSON for unblind signature context", env); }
      }
    },
    Err(_) => { handle_err!("Unblind signature context not set", env); }
  };

  // convert public key base64 string to `PublicKey` instance
  let public_key = match verify_signature_context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'", env); }
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
    None => { handle_err!("Property not set: 'signature'", env); }
  };

  // get `messages` values as array
  let messages_array = match verify_signature_context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'", env); }
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
        Ok(verify_outcome_string) => {
          let output = env
            .new_string(verify_outcome_string)
            .expect("Unable to create string from signature verification outcome");
  
          output.into_inner()
        },
        Err(_) => { handle_err!("Failed to stringify verification outcome", env); }
      }
    },
    Err(error) => { handle_err!(format!("Unable to verify messages: {}", error), env); }
  }
}

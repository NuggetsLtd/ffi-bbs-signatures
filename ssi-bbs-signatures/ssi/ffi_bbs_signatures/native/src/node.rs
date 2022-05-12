#[macro_use]
mod macros;

use bbs::prelude::*;
use neon::prelude::*;
use neon::result::Throw;
use std::collections::{BTreeMap,BTreeSet};

use crate::{
  bls_generate_blinded_g1_key,
  bls_generate_blinded_g2_key,
  bls_generate_g1_key,
  bls_generate_g2_key,
};
use bbs::keys::{
  PublicKey
};
use bbs::{
  pm_revealed_raw,
  pm_hidden_raw,
};

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g1` ^ `x` * `blinding_g1` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn node_bls_generate_blinded_g1_key(mut cx: FunctionContext) -> JsResult<JsObject> {
  let seed = arg_to_opt_slice!(cx, 0);

  let (bf_bytes, pk_bytes, sk_bytes) = bls_generate_blinded_g1_key(seed);

  Ok(blinded_key_values_to_object!(cx, sk_bytes, pk_bytes, bf_bytes))
}

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g2` ^ `x` * `blinding_g2` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn node_bls_generate_blinded_g2_key(mut cx: FunctionContext) -> JsResult<JsObject> {
  let seed = arg_to_opt_slice!(cx, 0);

  let (bf_bytes, pk_bytes, sk_bytes) = bls_generate_blinded_g2_key(seed);

  Ok(blinded_key_values_to_object!(cx, sk_bytes, pk_bytes, bf_bytes))
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g1` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn node_bls_generate_g1_key(mut cx: FunctionContext) -> JsResult<JsObject> {
  let seed = arg_to_opt_slice!(cx, 0);

  let (pk_bytes, sk_bytes) = bls_generate_g1_key(seed);

  Ok(key_values_to_object!(cx, sk_bytes, pk_bytes))
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g2` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn node_bls_generate_g2_key(mut cx: FunctionContext) -> JsResult<JsObject> {
  let seed = arg_to_opt_slice!(cx, 0);

  let (pk_bytes, sk_bytes) = bls_generate_g2_key(seed);

  Ok(key_values_to_object!(cx, sk_bytes, pk_bytes))
}

/// Get the BBS public key associated with the private key
/// the context object model is as follows:
/// {
///     "secretKey": ArrayBuffer           // the private key of signer
///     "messageCount": Number,            // the number of messages that can be signed
/// }
/// `return`: `publickey` `arraybuffer`
fn node_bls_secret_key_to_bbs_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
  let bad_res = cx.array_buffer(0);
  let js_obj = cx.argument::<JsObject>(0)?;

  // load message count
  let message_count = obj_property_to_unsigned_int!(&mut cx, js_obj, "messageCount");

  // load secret key
  let sk_bytes = obj_property_to_slice!(&mut cx, js_obj, "secretKey");
  let sk = SecretKey::from(*array_ref![
    sk_bytes,
    0,
    FR_COMPRESSED_SIZE
  ]);
  
  // convert secret key to deterministic public key
  let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));

  // convert deterministic public key to compressed BBS public key
  let pk;
  match dpk.to_public_key(message_count as usize) {
      Err(_) => return bad_res,
      Ok(p) => pk = p,
  }
  if pk.validate().is_err() {
      return bad_res;
  }

  let pk_bytes = pk.to_bytes_compressed_form();

  Ok(slice_to_js_array_buffer!(&pk_bytes, cx))
}

/// Get the BBS public key associated with the public key
/// /// the context object model is as follows:
/// {
///     "publicKey": ArrayBuffer           // the public key of signer
///     "messageCount": Number,            // the number of messages that can be signed
/// }
/// `return`: `publicKey` `ArrayBuffer`
fn node_bls_public_key_to_bbs_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
  let bad_res = cx.array_buffer(0);
  let js_obj = cx.argument::<JsObject>(0)?;

  let message_count = obj_property_to_unsigned_int!(&mut cx, js_obj, "messageCount");

  let dpk_bytes = obj_property_to_slice!(&mut cx, js_obj, "publicKey");
  let dpk = DeterministicPublicKey::from(*array_ref![
    dpk_bytes,
    0,
    DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
  ]);

  let pk;
  match dpk.to_public_key(message_count as usize) {
      Err(_) => return bad_res,
      Ok(p) => pk = p,
  }
  if pk.validate().is_err() {
      return bad_res;
  }

  let pk_bytes = pk.to_bytes_compressed_form();

  Ok(slice_to_js_array_buffer!(&pk_bytes, cx))
}

/// Generate a BBS+ signature
/// The first argument is the domain separation label
/// The second argument is the private key `x` created from bls_generate_key.
/// The remaining values are the messages to be signed.
/// If no messages are supplied, an error is thrown.
///
/// `signature_context`: `Object` the context for the signature creation
/// The context object model is as follows:
/// {
///     "secretKey": ArrayBuffer                // The private key of signer
///     "publicKey": ArrayBuffer                // The public key of signer
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages to be signed as ArrayBuffers. They will be hashed with Blake2b
/// }
///
/// `return`: `ArrayBuffer` the signature
fn node_bbs_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
  let js_obj = cx.argument::<JsObject>(0)?;

  let sk = SecretKey::from(obj_property_to_fixed_array!(
      &mut cx,
      js_obj,
      "secretKey",
      0,
      FR_COMPRESSED_SIZE
  ));

  let pk_bytes = obj_property_to_slice!(&mut cx, js_obj, "publicKey");
  let pk = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();

  if pk.validate().is_err() {
      panic!("Invalid key");
  }

  let message_bytes = obj_property_to_vec!(&mut cx, js_obj, "messages");
  let mut messages = Vec::new();
  for i in 0..message_bytes.len() {
      let message = js_array_buffer_to_slice!(&mut cx, message_bytes[i]);
      messages.push(SignatureMessage::hash(message));
  }

  let signature = handle_err!(Signature::new(messages.as_slice(), &sk, &pk));
  let result = slice_to_js_array_buffer!(&signature.to_bytes_compressed_form()[..], cx);

  Ok(result)
}

register_module!(mut cx, {
  cx.export_function("bls_generate_blinded_g1_key", node_bls_generate_blinded_g1_key)?;
  cx.export_function("bls_generate_blinded_g2_key", node_bls_generate_blinded_g2_key)?;
  cx.export_function("bls_generate_g1_key", node_bls_generate_g1_key)?;
  cx.export_function("bls_generate_g2_key", node_bls_generate_g2_key)?;
  cx.export_function("bls_secret_key_to_bbs_key", node_bls_secret_key_to_bbs_key)?;
  cx.export_function("bls_public_key_to_bbs_key", node_bls_public_key_to_bbs_key)?;
  cx.export_function("bbs_sign", node_bbs_sign)?;
  Ok(())
});

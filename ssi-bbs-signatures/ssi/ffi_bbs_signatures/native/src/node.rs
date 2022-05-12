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
fn node_bbs_verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  let js_obj = cx.argument::<JsObject>(0)?;

  let signature = Signature::from(obj_property_to_fixed_array!(
      &mut cx,
      js_obj,
      "signature",
      0,
      SIGNATURE_COMPRESSED_SIZE
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

  match signature.verify(messages.as_slice(), &pk) {
      Ok(b) => Ok(cx.boolean(b)),
      Err(_) => Ok(cx.boolean(false)),
  }
}

/// Create a signature proof of knowledge. This includes revealing some messages
/// and retaining others. Not revealed attributes will have a proof of committed values
/// instead of revealing the values.
///
/// `create_proof_context`: `Object` the context for creating a proof
/// The context object model is as follows:
/// {
///     "signature": ArrayBuffer,               // The signature to be proved
///     "publicKey": ArrayBuffer,               // The public key of the signer
///     "messages": [ArrayBuffer, ArrayBuffer]  // All messages that were signed in the order they correspond to the generators in the public key. They will be Blake2b hashed
///     "revealed": [Number, Number]            // The zero based indices to the generators in the public key for the messages to be revealed. All other messages will be hidden from the verifier.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
///
/// `return`: `ArrayBuffer` the proof to send to the verifier
fn node_bbs_create_proof(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
  let (mut bitvector, pcx) = extract_create_proof_context(&mut cx)?;
  let proof = generate_proof(pcx)?;

  bitvector.extend_from_slice(proof.to_bytes_compressed_form().as_slice());

  Ok(slice_to_js_array_buffer!(
      bitvector.as_slice(),
      cx
  ))
}

fn generate_proof(pcx: CreateProofContext) -> Result<PoKOfSignatureProof, Throw> {
    let pok = handle_err!(PoKOfSignature::init(
        &pcx.signature,
        &pcx.public_key,
        &pcx.messages.as_slice()
    ));
    let mut challenge_bytes = pok.to_bytes();
    if let Some(b) = pcx.nonce {
        challenge_bytes.extend_from_slice(&ProofNonce::hash(b.as_slice()).to_bytes_compressed_form());
    } else {
        challenge_bytes.extend_from_slice(&[0u8; FR_COMPRESSED_SIZE]);
    }

    let challenge_hash = ProofChallenge::hash(&challenge_bytes);
    Ok(handle_err!(pok.gen_proof(&challenge_hash)))
}

fn extract_create_proof_context(cx: &mut FunctionContext) -> Result<(Vec<u8>, CreateProofContext), Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let signature = Signature::from(obj_property_to_fixed_array!(
        cx,
        js_obj,
        "signature",
        0,
        SIGNATURE_COMPRESSED_SIZE
    ));
    let pk_bytes = obj_property_to_slice!(cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }

    let nonce = obj_property_to_opt_slice!(cx, js_obj, "nonce");

    let revealed_indices = obj_property_to_vec!(cx, js_obj, "revealed");
    let message_bytes = obj_property_to_vec!(cx, js_obj, "messages");

    let mut revealed = BTreeSet::new();
    for i in 0..revealed_indices.len() {
        let index = cast_to_number!(cx, revealed_indices[i]);
        if index < 0f64 || index as usize > message_bytes.len() {
            panic!(
                "Index is out of bounds. Must be between 0 and {}: {}",
                message_bytes.len(),
                index
            );
        }
        revealed.insert(index as usize);
    }

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = js_array_buffer_to_slice!(cx, message_bytes[i]);
        let message = SignatureMessage::hash(message);

        if revealed.contains(&i) {
            messages.push(pm_revealed_raw!(message));
        } else {
            messages.push(pm_hidden_raw!(message));
        }
    }

    let mut bitvector = (messages.len() as u16).to_be_bytes().to_vec();
    bitvector.append(&mut revealed_to_bitvector(messages.len(), &revealed));

    Ok((bitvector, CreateProofContext {
        signature,
        public_key,
        messages,
        nonce,
    }))
}

struct CreateProofContext {
    signature: Signature,
    public_key: PublicKey,
    messages: Vec<ProofMessage>,
    nonce: Option<Vec<u8>>,
}

/// Expects `revealed` to be sorted
fn revealed_to_bitvector(total: usize, revealed: &BTreeSet<usize>) -> Vec<u8> {
    let mut bytes = vec![0u8; (total / 8) + 1];

    for r in revealed {
        let idx = *r / 8;
        let bit = (*r % 8) as u8;
        bytes[idx] |= 1u8 << bit;
    }

    // Convert to big endian
    bytes.reverse();
    bytes
}

register_module!(mut cx, {
  cx.export_function("bls_generate_blinded_g1_key", node_bls_generate_blinded_g1_key)?;
  cx.export_function("bls_generate_blinded_g2_key", node_bls_generate_blinded_g2_key)?;
  cx.export_function("bls_generate_g1_key", node_bls_generate_g1_key)?;
  cx.export_function("bls_generate_g2_key", node_bls_generate_g2_key)?;
  cx.export_function("bls_secret_key_to_bbs_key", node_bls_secret_key_to_bbs_key)?;
  cx.export_function("bls_public_key_to_bbs_key", node_bls_public_key_to_bbs_key)?;
  cx.export_function("bbs_sign", node_bbs_sign)?;
  cx.export_function("bbs_verify", node_bbs_verify)?;
  cx.export_function("bbs_create_proof", node_bbs_create_proof)?;
  Ok(())
});

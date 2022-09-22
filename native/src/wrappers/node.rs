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

/// Verify a signature proof of knowledge. This includes checking some revealed messages.
/// The proof will have been created by `bbs_create_proof`
///
/// `verify_proof_context`: `Object` the context for verifying a proof
/// The context object model is as follows:
/// {
///     "proof": ArrayBuffer,                   // The proof from `bbs_create_proof`
///     "publicKey": ArrayBuffer,               // The public key of the signer in BLS form
///     "messages": [ArrayBuffer, ArrayBuffer]  // The revealed messages as ArrayBuffers. They will be Blake2b hashed.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
///
/// `return`: true if valid
fn node_bls_verify_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  let vcx = extract_verify_proof_context(&mut cx, true)?;

  match verify_proof(vcx) {
      Ok(_) => Ok(cx.boolean(true)),
      Err(_) => Ok(cx.boolean(false)),
  }
}

/// Verify a signature proof of knowledge. This includes checking some revealed messages.
/// The proof will have been created by `bbs_create_proof`
///
/// `verify_proof_context`: `Object` the context for verifying a proof
/// The context object model is as follows:
/// {
///     "proof": ArrayBuffer,                   // The proof from `bbs_create_proof`
///     "publicKey": ArrayBuffer,               // The public key of the signer
///     "messages": [ArrayBuffer, ArrayBuffer]  // The revealed messages as ArrayBuffers. They will be Blake2b hashed.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the verifier and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
///
/// `return`: true if valid
fn node_bbs_verify_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  let vcx = extract_verify_proof_context(&mut cx, false)?;

  match verify_proof(vcx) {
    Ok(_) => Ok(cx.boolean(true)),
    Err(_) => Ok(cx.boolean(false)),
  }
}

fn verify_proof(vcx: VerifyProofContext) -> Result<Vec<SignatureMessage>, Throw> {
    let nonce = match vcx.nonce {
        Some(ref s) => ProofNonce::hash(s.as_slice()),
        None => ProofNonce::from([0u8; FR_COMPRESSED_SIZE]),
    };
    let proof_request = ProofRequest {
        revealed_messages: vcx.revealed.clone(),
        verification_key: vcx.public_key.clone(),
    };

    let revealed = vcx.revealed.iter().collect::<Vec<&usize>>();
    let mut revealed_messages = BTreeMap::new();
    for i in 0..vcx.revealed.len() {
        revealed_messages.insert(*revealed[i], vcx.messages[i].clone());
    }

    let signature_proof = SignatureProof {
        revealed_messages,
        proof: vcx.proof.clone(),
    };

    Ok(handle_err!(Verifier::verify_signature_pok(
        &proof_request,
        &signature_proof,
        &nonce,
    )))
}

fn extract_verify_proof_context(cx: &mut FunctionContext, is_bls: bool) -> Result<VerifyProofContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let proof = obj_property_to_slice!(cx, js_obj, "proof");
    let message_count = u16::from_be_bytes(*array_ref![proof, 0, 2]) as usize;
    let bitvector_length = (message_count / 8) + 1;
    let offset = 2 + bitvector_length;
    let revealed = bitvector_to_revealed(&proof[2..offset]);

    let proof = handle_err!(PoKOfSignatureProof::from_bytes_compressed_form(&proof[offset..]));

    let nonce = obj_property_to_opt_slice!(cx, js_obj, "nonce");
    let message_bytes = obj_property_to_vec!(cx, js_obj, "messages");

    if message_bytes.len() != revealed.len() {
        panic!("Given messages count ({}) is different from revealed messages count ({}) for this proof",
            message_bytes.len(), revealed.len());
    }

    let mut messages = Vec::new();
    for i in 0..message_bytes.len() {
        let message = js_array_buffer_to_slice!(cx, message_bytes[i]);
        messages.push(SignatureMessage::hash(message));
    }

    let public_key = if is_bls {
        let dpk = DeterministicPublicKey::from(obj_property_to_fixed_array!(
            cx,
            js_obj,
            "publicKey",
            0,
            DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
        ));
        dpk.to_public_key(message_count).unwrap()
    } else {
        let pk_bytes = obj_property_to_slice!(cx, js_obj, "publicKey");
        PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap()
    };
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }

    Ok(VerifyProofContext {
        proof,
        public_key,
        messages,
        revealed,
        nonce,
    })
}

struct VerifyProofContext {
    messages: Vec<SignatureMessage>,
    proof: PoKOfSignatureProof,
    public_key: PublicKey,
    revealed: BTreeSet<usize>,
    nonce: Option<Vec<u8>>,
}

/// Convert big-endian vector to u32
fn bitvector_to_revealed(data: &[u8]) -> BTreeSet<usize> {
    let mut revealed_messages = BTreeSet::new();
    let mut scalar = 0;

    for b in data.iter().rev() {
        let mut v = *b;
        let mut remaining = 8;
        while v > 0 {
            let revealed = v & 1u8;
            if revealed == 1 {
                revealed_messages.insert(scalar);
            }
            v >>= 1;
            scalar += 1;
            remaining -= 1;
        }
        scalar += remaining;
    }
    revealed_messages
}

/// This method should be called by the signature recipient and not the signer.
///
/// Creates the commitment and proof to be used in a blinded signature.
/// First, caller's should extract the blinding factor and use this to unblind
/// the signature once the other party has generated the signature. Everything
/// else should be sent to the signer. The signer needs the commitment to finish
/// the signature and the proof of knowledge of committed values. The blinding
/// requires the public key and the message indices to be blinded.
///
/// `blind_signature_context`: `Object` the context for the blind signature creation
/// The context object model is as follows:
/// {
///     "publicKey": ArrayBuffer                // The public key of signer
///     "messages": [ArrayBuffer, ArrayBuffer], // The messages that will be blinded as ArrayBuffers. They will be Blake2b hashed
///     "blinded": [Number, Number],            // The zero based indices to the generators in the public key for the messages.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
///
/// `return`: `Object` with the following fields
/// {
///     "commitment": ArrayBuffer,
///     "proofOfHiddenMessages": ArrayBuffer,
///     "challengeHash": ArrayBuffer,
///     "blindingFactor": ArrayBuffer
/// }
///
/// The caller must make sure that "blinding_factor" is not passed to the signer. This
/// would allow the issuer to unblind the signature but would still not know the hidden message
/// values.
fn node_bbs_blind_signature_commitment(mut cx: FunctionContext) -> JsResult<JsObject> {
  let bcx = extract_blinding_context(&mut cx)?;
  let (bcx, bf) =
      Prover::new_blind_signature_context(&bcx.public_key, &bcx.messages, &bcx.nonce).unwrap();
  get_blind_commitment(cx, bcx, bf)
}

fn get_blind_commitment(
  mut cx: FunctionContext,
  bcx: BlindSignatureContext,
  bf: SignatureBlinding,
) -> JsResult<JsObject> {
  let commitment = slice_to_js_array_buffer!(&bcx.commitment.to_bytes_compressed_form()[..], cx);
  let challenge_hash =
      slice_to_js_array_buffer!(&bcx.challenge_hash.to_bytes_compressed_form()[..], cx);
  let blinding_factor = slice_to_js_array_buffer!(&bf.to_bytes_compressed_form()[..], cx);
  let proof = slice_to_js_array_buffer!(
      bcx.proof_of_hidden_messages
          .to_bytes_compressed_form()
          .as_slice(),
      cx
  );

  let result = JsObject::new(&mut cx);
  result.set(&mut cx, "commitment", commitment)?;
  result.set(&mut cx, "challengeHash", challenge_hash)?;
  result.set(&mut cx, "blindingFactor", blinding_factor)?;
  result.set(&mut cx, "proofOfHiddenMessages", proof)?;
  Ok(result)
}

fn extract_blinding_context(cx: &mut FunctionContext) -> Result<BlindingContext, Throw> {
  let js_obj = cx.argument::<JsObject>(0)?;

  let pk_bytes = obj_property_to_slice!(cx, js_obj, "publicKey");
  let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();

  if public_key.validate().is_err() {
      panic!("Invalid key");
  }
  let nonce = obj_property_to_opt_slice!(cx, js_obj, "nonce");

  let hidden = obj_property_to_vec!(cx, js_obj, "blinded");
  let message_bytes = obj_property_to_vec!(cx, js_obj, "messages");

  if hidden.len() != message_bytes.len() {
      panic!(
          "hidden length is not the same as messages: {} != {}",
          hidden.len(),
          message_bytes.len()
      );
  }

  let mut messages = BTreeMap::new();
  let message_count = public_key.message_count() as f64;

  for i in 0..hidden.len() {
      let index = cast_to_number!(cx, hidden[i]);
      if index < 0f64 || index > message_count {
          panic!(
              "Index is out of bounds. Must be between {} and {}: found {}",
              0,
              public_key.message_count(),
              index
          );
      }

      let message = js_array_buffer_to_slice!(cx, message_bytes[i]);
      messages.insert(index as usize, SignatureMessage::hash(message));
  }

  let nonce = ProofNonce::hash(
      &(nonce.map_or_else(
          || b"bbs+nodejswrapper".to_vec(),
          |m| m,
      )),
  );

  Ok(BlindingContext {
      public_key,
      messages,
      nonce,
  })
}

struct BlindingContext {
  public_key: PublicKey,
  messages: BTreeMap<usize, SignatureMessage>,
  nonce: ProofNonce,
}

/// Verify the proof of hidden messages and commitment send from calling
/// `bbs_blind_signature_commitment`. Signer should call this before creating a blind signature
///
/// `blind_signature_context`: `Object` the context for the blind signature creation
/// The context object model is as follows:
/// {
///     "commitment": ArrayBuffer,              // Commitment of hidden messages
///     "proofOfHiddenMessages": ArrayBuffer,   // Proof of commitment to hidden messages
///     "challengeHash": ArrayBuffer,           // Fiat-Shamir Challenge
///     "publicKey": ArrayBuffer                // The public key of signer
///     "blinded": [Number, Number],            // The zero based indices to the generators in the public key for the blinded messages.
///     "nonce": ArrayBuffer                    // This is an optional nonce from the signer and will be used in the proof of committed messages if present. It is strongly recommend that this be used.
/// }
/// `return`: true if valid `signature` on `messages`
fn node_bbs_verify_blind_signature_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  let js_obj = cx.argument::<JsObject>(0)?;
  let pk_bytes = obj_property_to_slice!(&mut cx, js_obj, "publicKey");
  let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();
  if public_key.validate().is_err() {
      panic!("Invalid key");
  }
  let nonce_str = obj_property_to_opt_slice!(&mut cx, js_obj, "nonce");
  let nonce = ProofNonce::hash(
      &(nonce_str.map_or_else(
          || b"bbs+nodejswrapper".to_vec(),
          |m| m,
      )),
  );
  let commitment = Commitment::from(obj_property_to_fixed_array!(
      &mut cx,
      js_obj,
      "commitment",
      0,
      G1_COMPRESSED_SIZE
  ));
  let challenge_hash = ProofChallenge::from(obj_property_to_fixed_array!(
      &mut cx,
      js_obj,
      "challengeHash",
      0,
      FR_COMPRESSED_SIZE
  ));

  let proof_of_hidden_messages = handle_err!(ProofG1::from_bytes_compressed_form(
      &obj_property_to_slice!(&mut cx, js_obj, "proofOfHiddenMessages")
  ));

  let hidden = obj_property_to_vec!(&mut cx, js_obj, "blinded");
  let mut messages: BTreeSet<usize> = (0..public_key.message_count()).collect();
  let message_count = public_key.message_count() as f64;

  for i in 0..hidden.len() {
      let index = cast_to_number!(cx, hidden[i]);
      if index < 0f64 || index > message_count {
          panic!(
              "Index is out of bounds. Must be between {} and {}: found {}",
              0,
              public_key.message_count(),
              index
          );
      }
      messages.remove(&(index as usize));
  }

  let ctx = BlindSignatureContext {
      commitment,
      challenge_hash,
      proof_of_hidden_messages,
  };

  match ctx.verify(&messages, &public_key, &nonce) {
      Ok(b) => Ok(cx.boolean(b)),
      Err(_) => Ok(cx.boolean(false)),
  }
}

/// Generate a BBS+ blind signature.
/// This should be called by the signer and not the signature recipient
/// 1 or more messages have been hidden by the signature recipient.
/// The hidden and known messages are signed. This also verifies a
/// proof of committed messages sent by the signature recipient.
///
/// `blind_signature_context`: `Object` the context for the blind signature creation
/// The context object model is as follows:
/// {
///     "commitment": ArrayBuffer               // The commitment received from the intended recipient
///     "publicKey": ArrayBuffer                // The public key of signer
///     "secretKey": ArrayBuffer                // The secret key used for generating the signature
///     "messages": [ArrayBuffer, ArrayBuffer]  // The messages that will be signed as strings. They will be hashed with Blake2b
///     "known": [Number, Number],              // The zero based indices to the generators in the public key for the known messages.
/// }
///
/// `return`: `ArrayBuffer` the blinded signature. Recipient must unblind before it is valid
fn node_bbs_blind_sign(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
  let bcx = extract_blind_signature_context(&mut cx)?;
  let signature = handle_err!(BlindSignature::new(
      &bcx.commitment,
      &bcx.messages,
      &bcx.secret_key,
      &bcx.public_key
  ));
  let result = slice_to_js_array_buffer!(&signature.to_bytes_compressed_form()[..], cx);
  Ok(result)
}

fn extract_blind_signature_context(cx: &mut FunctionContext) -> Result<BlindSignContext, Throw> {
    let js_obj = cx.argument::<JsObject>(0)?;

    let secret_key = SecretKey::from(obj_property_to_fixed_array!(
        cx,
        js_obj,
        "secretKey",
        0,
        FR_COMPRESSED_SIZE
    ));

    let pk_bytes = obj_property_to_slice!(cx, js_obj, "publicKey");
    let public_key = PublicKey::from_bytes_compressed_form(pk_bytes.as_slice()).unwrap();
    if public_key.validate().is_err() {
        panic!("Invalid key");
    }
    let message_bytes = obj_property_to_vec!(cx, js_obj, "messages");

    let known = obj_property_to_vec!(cx, js_obj, "known");
    if known.len() != message_bytes.len() {
        panic!(
            "known length != messages: {} != {}",
            known.len(),
            message_bytes.len()
        );
    }

    let message_count = public_key.message_count() as f64;
    let mut messages = BTreeMap::new();

    for i in 0..known.len() {
        let index = cast_to_number!(cx, known[i]);
        if index < 0f64 || index > message_count {
            panic!(
                "Index is out of bounds. Must be between {} and {}: found {}",
                0,
                public_key.message_count(),
                index
            );
        }

        let message = js_array_buffer_to_slice!(cx, message_bytes[i]);
        messages.insert(index as usize, SignatureMessage::hash(message));
    }

    let commitment = Commitment::from(obj_property_to_fixed_array!(
        cx,
        js_obj,
        "commitment",
        0,
        G1_COMPRESSED_SIZE
    ));

    Ok(BlindSignContext {
        commitment,
        messages,
        public_key,
        secret_key,
    })
}

struct BlindSignContext {
    commitment: Commitment,
    public_key: PublicKey,
    messages: BTreeMap<usize, SignatureMessage>,
    /// This is automatically zeroed on drop
    secret_key: SecretKey,
}

/// Takes a blinded signature and makes it unblinded
///
/// inputs are the signature and the blinding factor generated from
/// `bbs_blind_signature_commitment`
///
/// `signature`: `ArrayBuffer` length must be `SIGNATURE_SIZE`
/// `blindingFactor`: `ArrayBuffer` length must be `MESSAGE_SIZE`
/// `return`: `ArrayBuffer` the unblinded signature
fn node_bbs_get_unblinded_signature(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let sig = BlindSignature::from(arg_to_fixed_array!(cx, 0, 0, SIGNATURE_COMPRESSED_SIZE));
    let bf = SignatureBlinding::from(arg_to_fixed_array!(
        cx,
        1,
        0,
        FR_COMPRESSED_SIZE
    ));

    let sig = sig.to_unblinded(&bf);

    let result = slice_to_js_array_buffer!(&sig.to_bytes_compressed_form()[..], cx);
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
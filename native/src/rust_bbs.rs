#[macro_use]
mod macros;

use std::collections::{BTreeMap,BTreeSet};
use serde_json::{Value, json};
use bbs::prelude::*;
use bbs::errors::BBSError;
use bbs::{
  FR_COMPRESSED_SIZE,
  pm_revealed_raw,
  pm_hidden_raw,
};
use pairing_plus::{
    bls12_381::{Bls12, Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};
use rand::prelude::*;

const BLINDING_G1: &[u8] = &[
    185, 201, 5, 142, 138, 68, 184, 112, 20, 249, 139, 228, 225, 129, 141, 183, 24, 248, 178, 213,
    16, 31, 200, 158, 105, 131, 98, 95, 50, 31, 20, 184, 77, 124, 246, 225, 85, 0, 73, 135, 162,
    21, 238, 66, 109, 241, 115, 201,
];
const BLINDING_G2: &[u8] = &[
    169, 99, 222, 42, 223, 177, 22, 60, 244, 190, 210, 77, 112, 140, 228, 116, 50, 116, 45, 32,
    128, 178, 87, 62, 190, 46, 25, 168, 105, 143, 96, 197, 65, 206, 192, 0, 252, 177, 151, 131,
    233, 190, 115, 52, 19, 86, 223, 95, 17, 145, 205, 222, 199, 196, 118, 215, 116, 43, 204, 66,
    26, 252, 93, 80, 94, 99, 55, 60, 98, 126, 160, 31, 218, 4, 240, 228, 1, 89, 210, 91, 221, 18,
    244, 90, 1, 13, 133, 128, 167, 143, 106, 125, 38, 34, 114, 243,
];

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g2` ^ `x` * `blinding_g2` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn bls_generate_blinded_g2_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (r, pk, sk) = bls_generate_keypair::<G2>(ikm, Some(BLINDING_G2));
    (r.unwrap(), pk, sk)
}

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g1` ^ `x` * `blinding_g1` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn bls_generate_blinded_g1_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (r, pk, sk) = bls_generate_keypair::<G1>(ikm, Some(BLINDING_G1));
    (r.unwrap(), pk, sk)
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g2` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_g2_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
    let (_, pk, sk) = bls_generate_keypair::<G2>(ikm, None);
    (pk, sk)
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g1` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_g1_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
    let (_, pk, sk) = bls_generate_keypair::<G1>(ikm, None);
    (pk, sk)
}

fn bls_generate_keypair<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes>(
    ikm: Option<Vec<u8>>,
    blinded: Option<&[u8]>,
) -> (Option<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let passed_seed = ikm.is_some();
    let seed = ikm.unwrap_or_else(|| {
        let mut rng = thread_rng();
        let mut seed_data = vec![0u8, 32];
        rng.fill_bytes(seed_data.as_mut_slice());
        seed_data
    });

    let sk = gen_sk(seed.as_slice());
    let mut pk = G::one();
    pk.mul_assign(sk);

    let r = match blinded {
        Some(g) => {
            let mut data = g.to_vec();
            let mut gg = g;
            if passed_seed {
                data.extend_from_slice(seed.as_slice());
            } else {
                let mut rng = thread_rng();
                let mut blinding_factor = vec![0u8, 32];
                rng.fill_bytes(blinding_factor.as_mut_slice());
                data.extend_from_slice(blinding_factor.as_slice());
            }
            let mut blinding_g = G::deserialize(&mut gg, true).unwrap();
            let r = gen_sk(data.as_slice());
            blinding_g.mul_assign(r);
            pk.add_assign(&blinding_g);
            let mut r_bytes = Vec::new();
            r.serialize(&mut r_bytes, true).unwrap();
            Some(r_bytes)
        }
        None => None,
    };

    let mut sk_bytes = Vec::new();
    let mut pk_bytes = Vec::new();
    sk.serialize(&mut sk_bytes, true).unwrap();
    pk.serialize(&mut pk_bytes, true).unwrap();

    (r, pk_bytes, sk_bytes)
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
        .expand(&[0, 48], &mut result)
        .is_ok());
    Fr::from_okm(&result)
}

#[allow(dead_code)]
pub fn rust_bbs_blind_signature_size() -> i32 {
  SIGNATURE_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub fn rust_bbs_blinding_factor_size() -> i32 {
  FR_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub fn rust_bls_secret_key_size() -> i32 {
    FR_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub fn rust_bls_public_key_g2_size() -> i32 {
    G2_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub fn rust_blinding_factor_size() -> i32 {
    FR_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub fn rust_bls_public_key_g1_size() -> i32 {
    G1_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub fn rust_bbs_signature_size() -> i32 {
    SIGNATURE_COMPRESSED_SIZE as i32
}

#[allow(dead_code)]
pub fn rust_bls_generate_blinded_g1_key(
  context_json: Value
) -> Result<String, BBSError> {
  // convert seed base64 string to slice
  let (bf_bytes, pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_blinded_g1_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'"); }
      }
    },
    None => bls_generate_blinded_g1_key(None)
  };

  let blinded_g1_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
    "blinding_factor": base64::encode(bf_bytes.as_slice()),
  });

  // Serialize blinded G1 key to a JSON string
  match serde_json::to_string(&blinded_g1_key) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify Blinded G1 key"); },
  }
}

#[allow(dead_code)]
pub fn rust_bls_generate_blinded_g2_key(
  context_json: Value
) -> Result<String, BBSError> {
  // convert seed base64 string to slice
  let (bf_bytes, pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_blinded_g2_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'"); },
      }
    },
    None => bls_generate_blinded_g2_key(None)
  };

  let blinded_g2_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
    "blinding_factor": base64::encode(bf_bytes.as_slice()),
  });

  // Serialize blinded G2 key to a JSON string
  match serde_json::to_string(&blinded_g2_key) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify Blinded G2 key"); },
  }
}

#[allow(dead_code)]
pub fn rust_bls_generate_g1_key(
  context_json: Value
) -> Result<String, BBSError> {
  // convert seed base64 string to slice
  let (pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_g1_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'"); },
      }
    },
    None => bls_generate_g1_key(None)
  };

  let g1_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
  });

  // Serialize blinded G1 key to a JSON string
  match serde_json::to_string(&g1_key) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify G1 key"); },
  }
}

#[allow(dead_code)]
pub fn rust_bls_generate_g2_key(
  context_json: Value
) -> Result<String, BBSError> {
  // convert seed base64 string to slice
  let (pk_bytes, sk_bytes) = match context_json["seed"].as_str() {
    Some(seed) => {
      match base64::decode(seed) {
        Ok(seed_bytes) => bls_generate_g2_key(Some(seed_bytes)),
        Err(_) => { handle_err!("Failed decoding base64 for: 'seed'"); },
      }
    },
    None => bls_generate_g2_key(None)
  };

  let g2_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice()),
    "secret_key": base64::encode(sk_bytes.as_slice()),
  });

  // Serialize blinded G1 key to a JSON string
  match serde_json::to_string(&g2_key) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify G2 key"); },
  }
}

#[allow(dead_code)]
pub fn rust_bls_secret_key_to_bbs_key(
  context_json: Value
) -> Result<String, BBSError> {
  // get message count
  let message_count = match context_json["message_count"].as_u64() {
    Some(message_count) => message_count,
    None => { handle_err!("Property not set: 'message_count'"); }
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
    None => { handle_err!("Property not set: 'secret_key'"); }
  }

  // convert secret key to deterministic public key
  let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(secret_key)));

  // convert deterministic public key to compressed BBS public key
  let pk;
  match dpk.to_public_key(message_count as usize) {
    Ok(p) => pk = p,
    Err(_) => { handle_err!("Failed to convert to BBS public key"); },
  }
  if pk.validate().is_err() {
    handle_err!("Failed to validate public key");
  }

  let pk_bytes = pk.to_bytes_compressed_form();

  let bbs_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice())
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&bbs_key) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify BBS key"); },
  }
}

#[allow(dead_code)]
pub fn rust_bls_public_key_to_bbs_key(
  context_json: Value
) -> Result<String, BBSError> {
  // get message count
  let message_count = match context_json["message_count"].as_u64() {
    Some(message_count) => message_count,
    None => { handle_err!("Property not set: 'message_count'"); }
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
    None => { handle_err!("Property not set: 'public_key'"); }
  }

  // convert deterministic public key to compressed BBS public key
  let pk;
  match dpk.to_public_key(message_count as usize) {
    Ok(p) => pk = p,
    Err(_) => { handle_err!("Failed to convert to BBS public key"); },
  }
  if pk.validate().is_err() {
    handle_err!("Failed to validate public key");
  }

  let pk_bytes = pk.to_bytes_compressed_form();

  let bbs_key = json!({
    "public_key": base64::encode(pk_bytes.as_slice())
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&bbs_key) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify BBS key"); },
  }
}

#[allow(dead_code)]
pub fn rust_bbs_sign(
  context_json: Value
) -> Result<String, BBSError> {
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
    None => { handle_err!("Property not set: 'secret_key'"); }
  }

  // convert 'public_key' base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'"); }
  };

  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'"); }
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
    Err(_) => { handle_err!("Failed to sign messages"); }
  };

  let bbs_signature = json!({
    "signature": base64::encode(signature.to_bytes_compressed_form())
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&bbs_signature) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify BBS Signature"); },
  }
}

#[allow(dead_code)]
pub fn rust_bbs_create_proof(
  context_json: Value
) -> Result<String, BBSError> {
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
    None => { handle_err!("Property not set: 'signature'"); }
  };

  // convert 'public_key' base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'"); }
  };

  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'"); }
  };

  // map `revealed` serde array values to Vec
  let revealed_indices: Vec<i64> = match context_json["revealed"].as_array() {
    Some(revealed) => revealed.into_iter().map(|b| match b.as_i64() {
      Some(index) => index,
      None => -1,
    }).collect(),
    None => { handle_err!("Property not set: 'revealed'"); }
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
      ));
    }
    if index > message_count {
      handle_err!(format!(
        "Index for 'revealed' is out of bounds. Must be between {} and {}: found {}",
        0,
        message_count,
        index
      ));
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

  // check public key is valid
  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }

  let mut bitvector = (messages.len() as u16).to_be_bytes().to_vec();
  bitvector.append(&mut revealed_to_bitvector(messages.len(), &revealed));
  
  let pok = match PoKOfSignature::init(
    &signature,
    &public_key,
    &messages.as_slice()
  ) {
    Ok(pok) => pok,
    Err(error) => {
      handle_err!(format!("Failed generating proof of knowledge: {}", error));
    }
  };

  let mut challenge_bytes = pok.to_bytes();
  if let Some(b) = nonce {
    challenge_bytes.extend_from_slice(&ProofNonce::hash(b.as_slice()).to_bytes_compressed_form());
  } else {
    challenge_bytes.extend_from_slice(&[0u8; FR_COMPRESSED_SIZE]);
  }

  let challenge_hash = ProofChallenge::hash(&challenge_bytes);
  let pok = match pok.gen_proof(&challenge_hash) {
    Ok(proof) => {
      bitvector.extend_from_slice(proof.to_bytes_compressed_form().as_slice());
      bitvector
    },
    Err(_) => { handle_err!("Failed generating proof"); }
  };
  
  let proof = json!({
    "proof": base64::encode(pok)
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&proof) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify BBS Proof"); },
  }
}

#[allow(dead_code)]
pub fn rust_bbs_verify_proof(
  context_json: Value
) -> Result<String, BBSError> {
  // convert proof base64 string to `Proofproof` instance
  let proof = match context_json["proof"].as_str() {
    Some(proof) => base64::decode(proof).unwrap(),
    None => { handle_err!("Property not set: 'proof'"); }
  };

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match context_json["nonce"].as_str() {
    Some(nonce) => Some(base64::decode(nonce).unwrap()),
    None => None
  };

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'"); }
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
    None => { handle_err!("Property not set: 'public_key'"); }
  };

  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }

  let message_count = u16::from_be_bytes(*array_ref![proof, 0, 2]) as usize;
  let bitvector_length = (message_count / 8) + 1;
  let offset = 2 + bitvector_length;
  let revealed = bitvector_to_revealed(&proof[2..offset]);

  if messages.len() != revealed.len() {
    handle_err!(format!("Given messages count ({}) is different from revealed messages count ({}) for this proof", messages.len(), revealed.len()));
  }

  let proof = match PoKOfSignatureProof::from_bytes_compressed_form(&proof[offset..]) {
    Ok(proof) => proof,
    Err(error) => {
      handle_err!(format!("Failed generating proof of knowledge: {}", error));
    }
  };

  let nonce = match nonce {
    Some(ref s) => ProofNonce::hash(s.as_slice()),
    None => ProofNonce::from([0u8; FR_COMPRESSED_SIZE]),
  };
  
  let proof_request = ProofRequest {
    revealed_messages: revealed.clone(),
    verification_key: public_key,
  };

  let revealed = revealed.iter().collect::<Vec<&usize>>();
  let mut revealed_messages = BTreeMap::new();
  for i in 0..revealed.len() {
    revealed_messages.insert(*revealed[i], messages[i].clone());
  }

  let signature_proof = SignatureProof {
    revealed_messages,
    proof,
  };

  let verified = match Verifier::verify_signature_pok(
    &proof_request,
    &signature_proof,
    &nonce,
  ) {
    Ok(_) => true,
    Err(_) => false
  };

  let verify_outcome = json!({
    "verified": verified,
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&verify_outcome) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify BBS Proof Verification"); },
  }
}

#[allow(dead_code)]
pub fn rust_bls_verify_proof(
  mut context_json: Value
) -> Result<String, BBSError> {
  // convert proof base64 string to `Proofproof` instance
  let proof = match context_json["proof"].as_str() {
    Some(proof) => base64::decode(proof).unwrap(),
    None => { handle_err!("Property not set: 'proof'"); }
  };
  let message_count = u16::from_be_bytes(*array_ref![proof, 0, 2]) as usize;
  
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
    None => { handle_err!("Property not set: 'public_key'"); }
  }

  // convert deterministic public key to compressed BBS public key
  let pk;
  match dpk.to_public_key(message_count as usize) {
    Ok(p) => pk = p,
    Err(_) => { handle_err!("Failed to convert to BBS public key"); },
  }
  if pk.validate().is_err() {
    handle_err!("Failed to validate public key");
  }

  let pk_bytes = pk.to_bytes_compressed_form();
  
  context_json["public_key"] = Value::String(base64::encode(pk_bytes.as_slice()));

  rust_bbs_verify_proof(context_json)
}

#[allow(dead_code)]
pub fn rust_bbs_blind_signature_commitment(
  context_json: Value
) -> Result<String, BBSError> {
  // convert public key base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'"); }
  };

  // get `blinded` values as array
  let blinded = match context_json["blinded"].as_array() {
    Some(blinded) => blinded,
    None => { handle_err!("Property not set: 'blinded'"); }
  };

  // get `messages` values as array
  let messages_to_blind = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'"); }
  };

  if blinded.len() != messages_to_blind.len() {
    handle_err!(format!(
      "hidden length is not the same as messages length: {} != {}",
      blinded.len(),
      messages_to_blind.len()
    ));
  }

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match context_json["nonce"].as_str() {
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
        ));
      }

      // add message to tree map
      messages.insert(index as usize, SignatureMessage::hash(base64::decode(messages_to_blind[i].as_str().unwrap()).unwrap().as_slice()));
  }

  // check public key is valid
  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }

  let (blinding_context, blinding_factor) = Prover::new_blind_signature_context(&public_key, &messages, &nonce).unwrap();

  let blind_commitment_context = json!({
    "commitment": base64::encode(blinding_context.commitment.to_bytes_compressed_form().as_slice()),
    "challenge_hash": base64::encode(blinding_context.challenge_hash.to_bytes_compressed_form().as_slice()),
    "blinding_factor": base64::encode(blinding_factor.to_bytes_compressed_form().as_slice()),
    "proof_of_hidden_messages": base64::encode(blinding_context.proof_of_hidden_messages.to_bytes_compressed_form().as_slice()),
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&blind_commitment_context) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify Blind Commitment Context"); },
  }
}

#[allow(dead_code)]
pub fn rust_bbs_verify_blind_signature_proof(
  context_json: Value
) -> Result<String, BBSError> {
  // convert 'commitment' base64 string to `Commitment` instance
  let commitment;
  match context_json["commitment"].as_str() {
    Some(commitment_b64) => {
      let commitment_b64 = base64::decode(commitment_b64).unwrap().to_vec();
      commitment = Commitment::from(*array_ref![
        commitment_b64,
        0,
        G1_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'commitment'"); }
  }

  // convert 'challenge_hash' base64 string to `ProofChallenge` instance
  let challenge_hash;
  match context_json["challenge_hash"].as_str() {
    Some(challenge_hash_b64) => {
      let challenge_hash_b64 = base64::decode(challenge_hash_b64).unwrap().to_vec();
      challenge_hash = ProofChallenge::from(*array_ref![
        challenge_hash_b64,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'challenge_hash'"); }
  }

  // convert public key base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'"); }
  };

  // convert public key base64 string to `PublicKey` instance
  let proof_of_hidden_messages = match context_json["proof_of_hidden_messages"].as_str() {
    Some(proof_of_hidden_messages) => ProofG1::from_bytes_compressed_form(base64::decode(proof_of_hidden_messages).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'proof_of_hidden_messages'"); }
  };
  
  // map `blinded` serde array values to Vec
  let blinded: Vec<i64> = match context_json["blinded"].as_array() {
    Some(blinded) => blinded.into_iter().map(|b| match b.as_i64() {
      Some(index) => index,
      None => -1
    }).collect(),
    None => { handle_err!("Blinded message indexes array not set"); }
  };

  // convert nonce base64 string to `ProofNonce` instance
  let nonce = match context_json["nonce"].as_str() {
    Some(nonce) => ProofNonce::hash(base64::decode(nonce).unwrap().as_slice()),
    None => ProofNonce::hash(b"bbs+rustffiwrapper".to_vec())
  };

  let commitment_context = BlindSignatureContext {
    commitment,
    proof_of_hidden_messages,
    challenge_hash,
  };

  // check public key is valid
  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }

  let mut messages: BTreeSet<usize> = (0..public_key.message_count()).collect();
  let message_count = public_key.message_count() as i64;

  for i in 0..blinded.len() {
      let index = blinded[i];
      if index < 0 {
        handle_err!(format!(
          "Invalid index for 'blinded'. Must be integer between {} and {}",
          0,
          message_count
        ));
      }
      if index > message_count {
        handle_err!(format!(
          "Index is out of bounds. Must be between {} and {}: found {}",
          0,
          public_key.message_count(),
          index
        ));
      }
      messages.remove(&(index as usize));
  }
  
  let verified = match commitment_context.verify(&messages, &public_key, &nonce) {
    Ok(b) => b,
    Err(_) => false,
  };

  let verify_outcome = json!({
    "verified": verified,
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&verify_outcome) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify Blind Commitment Verification"); },
  }
}

#[allow(dead_code)]
pub fn rust_bbs_blind_sign(
  context_json: Value
) -> Result<String, BBSError> {
  // convert 'secret_key' base64 string to `SecretKey` instance
  let secret_key;
  match context_json["secret_key"].as_str() {
    Some(secret_key_b64) => {
      let secret_key_b64 = base64::decode(secret_key_b64).unwrap().to_vec();
      secret_key = SecretKey::from(*array_ref![
        secret_key_b64,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'secret_key'"); }
  }

  // convert public key base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'"); }
  };

  // check public key is valid
  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }
  
  // map `known` serde array values to Vec
  let known: Vec<i64> = match context_json["known"].as_array() {
    Some(known) => known.into_iter().map(|b| match b.as_i64() {
      Some(index) => index,
      None => -1
    }).collect(),
    None => { handle_err!("Known message indexes array not set"); }
  };

  // get `messages` values as array
  let messages_visible = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Messages data array not set"); }
  };

  if known.len() != messages_visible.len() {
    handle_err!(format!(
      "known length is not the same as messages length: {} != {}",
      known.len(),
      messages_visible.len()
    ));
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
        ));
      }
      if index > message_count {
        handle_err!(format!(
          "Index is out of bounds. Must be between {} and {}: found {}",
          0,
          public_key.message_count(),
          index
        ));
      }

      // add message to tree map
      messages.insert(index as usize, SignatureMessage::hash(base64::decode(messages_visible[i].as_str().unwrap()).unwrap().as_slice()));
  }

  // convert 'commitment' base64 string to `Commitment` instance
  let commitment;
  match context_json["commitment"].as_str() {
    Some(commitment_b64) => {
      let commitment_b64 = base64::decode(commitment_b64).unwrap().to_vec();
      commitment = Commitment::from(*array_ref![
        commitment_b64,
        0,
        G1_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'commitment'"); }
  }

  let blind_signature = match BlindSignature::new(
    &commitment,
    &messages,
    &secret_key,
    &public_key
  ) {
    Ok(blind_signature) => blind_signature,
    Err(_) => { handle_err!("Failed to generate Blind Signature"); },
  };

  let signature_outcome = json!({
    "blind_signature": base64::encode(blind_signature.to_bytes_compressed_form().as_slice()),
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&signature_outcome) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify Blind Signature"); },
  }
}

#[allow(dead_code)]
pub fn rust_bbs_unblind_signature(
  context_json: Value
) -> Result<String, BBSError> {
  // convert 'blind_signature' base64 string to `BlindSignature` instance
  let blind_signature;
  match context_json["blind_signature"].as_str() {
    Some(blind_signature_b64) => {
      let blind_signature_b64 = base64::decode(blind_signature_b64).unwrap().to_vec();
      blind_signature = BlindSignature::from(*array_ref![
        blind_signature_b64,
        0,
        SIGNATURE_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'blind_signature'"); }
  };

  // convert 'blinding_factor' base64 string to `SignatureBlinding` instance
  let blinding_factor;
  match context_json["blinding_factor"].as_str() {
    Some(blinding_factor_b64) => {
      let blinding_factor_b64 = base64::decode(blinding_factor_b64).unwrap().to_vec();
      blinding_factor = SignatureBlinding::from(*array_ref![
        blinding_factor_b64,
        0,
        FR_COMPRESSED_SIZE
      ]);
    },
    None => { handle_err!("Property not set: 'blinding_factor'"); }
  };

  let unblinded_signature = blind_signature.to_unblinded(&blinding_factor);

  let signature_outcome = json!({
    "signature": base64::encode(unblinded_signature.to_bytes_compressed_form().as_slice()),
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&signature_outcome) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify Unblinded Signature"); },
  }
}

#[allow(dead_code)]
pub fn rust_bbs_verify(
  context_json: Value
) -> Result<String, BBSError> {
  // convert public key base64 string to `PublicKey` instance
  let public_key = match context_json["public_key"].as_str() {
    Some(public_key) => PublicKey::from_bytes_compressed_form(base64::decode(public_key).unwrap().as_slice()).unwrap(),
    None => { handle_err!("Property not set: 'public_key'"); }
  };

  // check public key is valid
  if public_key.validate().is_err() {
    handle_err!("Invalid public key");
  }

  // convert 'blind_signature' base64 string to `BlindSignature` instance
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
    None => { handle_err!("Property not set: 'signature'"); }
  };

  // get `messages` values as array
  let messages_array = match context_json["messages"].as_array() {
    Some(messages) => messages,
    None => { handle_err!("Property not set: 'messages'"); }
  };

  // convert messages base64 string to array of `SignatureMessage` instances
  let mut messages = Vec::new();

  for i in 0..messages_array.len() {
      // add message to Vec
      messages.push(SignatureMessage::hash(base64::decode(messages_array[i].as_str().unwrap()).unwrap().as_slice()));
  }

  let verified = match signature.verify(messages.as_slice(), &public_key) {
    Ok(verified) => verified,
    Err(_) => { handle_err!("Failed to verify Signature"); },
  };

  let verify_outcome = json!({
    "verified": verified,
  });

  // Serialize return object to JSON string
  match serde_json::to_string(&verify_outcome) {
    Ok(json_string) => Ok(json_string),
    Err(_) => { handle_err!("Failed to stringify Signature verification"); },
  }
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

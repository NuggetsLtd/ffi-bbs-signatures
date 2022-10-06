use std::collections::{BTreeMap,BTreeSet};
use serde::{Deserialize, Serialize};
use bbs::prelude::*;
use bbs::{FR_COMPRESSED_SIZE};

#[derive(Serialize, Deserialize)]
pub struct BlindingContext {
  pub public_key: PublicKey,
  pub messages: BTreeMap<usize, SignatureMessage>,
  pub nonce: ProofNonce,
}

#[allow(dead_code)]
pub fn rust_bbs_blind_signature_commitment(
  context: &BlindingContext
) -> Result<(BlindSignatureContext, SignatureBlinding), BBSError> {
  // check public key is valid
  if context.public_key.validate().is_err() {
      panic!("Invalid public key");
  }

  Ok(Prover::new_blind_signature_context(&context.public_key, &context.messages, &context.nonce).unwrap())
}

#[allow(dead_code)]
pub fn rust_bbs_verify_blind_signature_proof(
  commitment_context: &BlindSignatureContext,
  public_key: PublicKey,
  blinded: Vec<u64>,
  nonce: ProofNonce,
) -> Result<bool, BBSError> {
  // check public key is valid
  if public_key.validate().is_err() {
      panic!("Invalid public key");
  }

  let mut messages: BTreeSet<usize> = (0..public_key.message_count()).collect();
  let message_count = public_key.message_count() as u64;

  for i in 0..blinded.len() {
      let index = blinded[i];
      if index > message_count {
          panic!(
              "Index is out of bounds. Must be between {} and {}: found {}",
              0,
              public_key.message_count(),
              index
          );
      }
      messages.remove(&(index as usize));
  }
  
  match commitment_context.verify(&messages, &public_key, &nonce) {
    Ok(b) => Ok(b),
    Err(_) => Ok(false),
  }
}

#[allow(dead_code)]
pub fn rust_bbs_blind_sign(
  commitment: &Commitment,
  messages: &BTreeMap<usize, SignatureMessage>,
  secret_key: &SecretKey,
  public_key: &PublicKey,
) -> Result<BlindSignature, BBSError> {
  // check public key is valid
  if public_key.validate().is_err() {
      panic!("Invalid public key");
  }

  BlindSignature::new(
    commitment,
    messages,
    secret_key,
    public_key
  )
}

#[allow(dead_code)]
pub fn rust_bbs_unblind_signature(
  blind_signature: &BlindSignature,
  blinding_factor: &SignatureBlinding,
) -> Signature {
  blind_signature.to_unblinded(&blinding_factor)
}

#[allow(dead_code)]
pub fn rust_bbs_verify(
  signature: &Signature,
  messages: &Vec<SignatureMessage>,
  public_key: &PublicKey,
) -> Result<bool, BBSError> {
  // check public key is valid
  if public_key.validate().is_err() {
      panic!("Invalid key");
  }

  signature.verify(messages.as_slice(), public_key)
}

#[allow(dead_code)]
pub fn rust_bbs_create_proof(
  signature: &Signature,
  public_key: &PublicKey,
  messages: &Vec<ProofMessage>,
  revealed: &BTreeSet<usize>,
  nonce: Option<Vec<u8>>,
) -> Result<Vec<u8>, BBSError> {
  // check public key is valid
  if public_key.validate().is_err() {
      panic!("Invalid public key");
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
      return Err(BBSError::from(BBSErrorKind::GeneralError {
        msg: format!("Failed generating proof of knowledge: {}", error),
      }))
    }
  };

  let mut challenge_bytes = pok.to_bytes();
  if let Some(b) = nonce {
    challenge_bytes.extend_from_slice(&ProofNonce::hash(b.as_slice()).to_bytes_compressed_form());
  } else {
    challenge_bytes.extend_from_slice(&[0u8; FR_COMPRESSED_SIZE]);
  }

  let challenge_hash = ProofChallenge::hash(&challenge_bytes);
  match pok.gen_proof(&challenge_hash) {
    Ok(proof) => {
      bitvector.extend_from_slice(proof.to_bytes_compressed_form().as_slice());
      Ok(bitvector)
    },
    Err(_) => Err(BBSError::from(BBSErrorKind::GeneralError {
      msg: "Failed generating proof".to_string(),
    }))
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

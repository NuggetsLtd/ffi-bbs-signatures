use std::collections::{BTreeMap,BTreeSet};
use serde::{Deserialize, Serialize};
use bbs::prelude::{
  ProofNonce,
  SignatureMessage,
  SecretKey,
  PublicKey,
  Prover,
  BBSError,
  BlindSignatureContext,
  SignatureBlinding,
  Commitment,
  BlindSignature,
};

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

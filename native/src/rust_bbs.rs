use std::collections::{BTreeMap};
use serde::{Deserialize, Serialize};
use bbs::prelude::{
  ProofNonce,
  SignatureMessage,
  PublicKey,
  Prover,
  BBSError,
  BlindSignatureContext,
  SignatureBlinding,
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

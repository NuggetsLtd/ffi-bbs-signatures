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

register_module!(mut cx, {
  cx.export_function("bls_generate_blinded_g1_key", node_bls_generate_blinded_g1_key)?;
  cx.export_function("bls_generate_blinded_g2_key", node_bls_generate_blinded_g2_key)?;
  cx.export_function("bls_generate_g1_key", node_bls_generate_g1_key)?;
  cx.export_function("bls_generate_g2_key", node_bls_generate_g2_key)?;
  Ok(())
});

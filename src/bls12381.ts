import { BlsKeyPair, BlindedBlsKeyPair } from "./types";
import { wrapFFI, base64ToUint8Array, arrayBufferToBase64 } from "./util";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bbs = require(path.resolve(path.join(__dirname, "../native/index.node")));

/**
 * Generates a BLS12-381 key pair where the public key is a commitment in G1
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlsKeyPair
 */
export const generateBls12381G1KeyPair = async (seed?: Uint8Array): Promise<Required<BlsKeyPair>> => {
  const result = wrapFFI(bbs.bls_generate_g1_key, seed ? { seed: arrayBufferToBase64(seed?.buffer) } : {});
  return {
    publicKey: base64ToUint8Array(result.public_key),
    secretKey: base64ToUint8Array(result.secret_key),
  };
};

/**
 * Generates a blinded BLS12-381 key pair where the public key is a commitment in G1 to the private key
 * along with a further commitment of a blinding factor to the blinding factor generator point in G1
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlindedBlsKeyPair
 */
export const generateBlindedBls12381G1KeyPair = async (seed?: Uint8Array): Promise<Required<BlindedBlsKeyPair>> => {
  const result = wrapFFI(bbs.bls_generate_blinded_g1_key, seed ? { seed: arrayBufferToBase64(seed?.buffer) } : {});
  return {
    publicKey: base64ToUint8Array(result.public_key),
    secretKey: base64ToUint8Array(result.secret_key),
    blindingFactor: base64ToUint8Array(result.blinding_factor),
  };
};

/**
 * Generates a BLS12-381 key pair where the public key is a commitment in G2
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlsKeyPair
 */
export const generateBls12381G2KeyPair = async (seed?: Uint8Array): Promise<Required<BlsKeyPair>> => {
  const result = wrapFFI(bbs.bls_generate_g2_key, seed ? { seed: arrayBufferToBase64(seed?.buffer) } : {});

  return {
    publicKey: base64ToUint8Array(result.public_key),
    secretKey: base64ToUint8Array(result.secret_key),
  };
};

/**
 * Generates a blinded BLS12-381 key pair where the public key is a commitment in G2 to the private key
 * along with a further commitment of a blinding factor to the blinding factor generator point in G2
 * @param seed [Optional] To derive the key pair from
 *
 * @returns A BlindedBlsKeyPair
 */
export const generateBlindedBls12381G2KeyPair = async (seed?: Uint8Array): Promise<Required<BlindedBlsKeyPair>> => {
  const result = wrapFFI(bbs.bls_generate_blinded_g2_key, seed ? { seed: arrayBufferToBase64(seed?.buffer) } : {});
  return {
    publicKey: base64ToUint8Array(result.public_key),
    secretKey: base64ToUint8Array(result.secret_key),
    blindingFactor: base64ToUint8Array(result.blinding_factor),
  };
};

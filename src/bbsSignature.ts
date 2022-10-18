import { bls12381toBbs } from "./bls12381toBbs";
import {
  BbsBlindSignRequest,
  BlsBlindSignRequest,
  BbsCreateProofRequest,
  BbsSignRequest,
  BlsBbsSignRequest,
  BbsVerifyProofRequest,
  BlsVerifyRequest,
  BbsVerifyRequest,
  BbsBlindSignContextRequest,
  BlsBlindSignContextRequest,
  BbsVerifyBlindSignContextRequest,
  BlsVerifyBlindSignContextRequest,
  BbsBlindSignContext,
  BbsVerifyResult,
} from "./types";
import { wrapFFI, base64ToUint8Array, arrayBufferToBase64 } from "./util";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bbs = require(path.resolve(path.join(__dirname, "../native/index.node")));

/**
 * Default BBS Signature Length
 */
export const BBS_SIGNATURE_LENGTH = 112;

/**
 * Signs a set of messages with a BBS key pair and produces a BBS signature
 * @param request Request for the sign operation
 *
 * @returns The raw signature value
 */
export const sign = async (request: BbsSignRequest): Promise<Uint8Array> => {
  const { keyPair, messages } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { signature, error } = wrapFFI(bbs.bbs_sign, {
      public_key: arrayBufferToBase64(keyPair.publicKey.buffer),
      secret_key: arrayBufferToBase64(keyPair.secretKey?.buffer as ArrayBuffer),
      messages: messagesBase64,
    })

    if(error) {
      throw new Error(error.message)
    }
    
    return base64ToUint8Array(signature)
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Signs a set of messages with a BLS 12-381 key pair and produces a BBS signature
 * @param request Request for the sign operation
 *
 * @returns The raw signature value
 */
export const blsSign = async (request: BlsBbsSignRequest): Promise<Uint8Array> => {
  const { keyPair, messages } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { signature, error } = wrapFFI(bbs.bls_sign, {
      public_key: arrayBufferToBase64(keyPair.publicKey.buffer),
      secret_key: arrayBufferToBase64(keyPair.secretKey?.buffer as ArrayBuffer),
      messages: messagesBase64,
    })

    if(error) {
      throw new Error(error.message)
    }
    
    return base64ToUint8Array(signature)
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Verifies a BBS+ signature for a set of messages with a BBS public key
 * @param request Request for the signature verification operation
 *
 * @returns A result indicating if the signature was verified
 */
export const verify = async (request: BbsVerifyRequest): Promise<BbsVerifyResult> => {
  const { publicKey, signature, messages } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { verified, error } = wrapFFI(bbs.bbs_verify, {
      public_key: arrayBufferToBase64(publicKey.buffer),
      signature: arrayBufferToBase64(signature.buffer),
      messages: messagesBase64,
    });

    if(error) {
      throw new Error(error.message)
    }

    return { verified }
  } catch (e: any) {
    return { verified: false, error: `${e.name}: ${e.message}` }
  }
};

/**
 * Verifies a BBS+ signature for a set of messages with a with a BLS 12-381 public key
 * @param request Request for the signature verification operation
 *
 * @returns A result indicating if the signature was verified
 */
export const blsVerify = async (request: BlsVerifyRequest): Promise<BbsVerifyResult> => {
  try {
    const { publicKey, signature, messages } = request;
    const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

    const { verified, error } = wrapFFI(bbs.bls_verify, {
      public_key: arrayBufferToBase64(publicKey.buffer),
      signature: arrayBufferToBase64(signature.buffer),
      messages: messagesBase64,
    });

    if(error) {
      throw new Error(error.message)
    }

    return { verified }
  } catch (e: any) {
    return { verified: false, error: `${e.name}: ${e.message}` };
  }
};

/**
 * Creates a BBS+ proof for a set of messages from a BBS public key and a BBS signature
 * @param request Request for the create proof operation
 *
 * @returns The raw proof value
 */
export const createProof = async (request: BbsCreateProofRequest): Promise<Uint8Array> => {
  const { publicKey, signature, messages, nonce, revealed } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { proof, error } = wrapFFI(bbs.bbs_create_proof, {
        nonce: arrayBufferToBase64(nonce.buffer),
        revealed,
        public_key: arrayBufferToBase64(publicKey.buffer),
        signature: arrayBufferToBase64(signature.buffer),
        messages: messagesBase64,
      })

      if(error) {
        throw new Error(error.message)
      }
  
      return base64ToUint8Array(proof)
  } catch (ex) {
    throw new Error("Failed to create proof");
  }
};

/**
 * Creates a BBS+ proof for a set of messages from a BLS12-381 public key and a BBS signature
 * @param request Request for the create proof operation
 *
 * @returns The raw proof value
 */
export const blsCreateProof = async (request: BbsCreateProofRequest): Promise<Uint8Array> => {
  const { publicKey, signature, messages, nonce, revealed } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { proof, error } = wrapFFI(bbs.bls_create_proof, {
      nonce: arrayBufferToBase64(nonce.buffer),
      revealed,
      public_key: arrayBufferToBase64(publicKey.buffer),
      signature: arrayBufferToBase64(signature.buffer),
      messages: messagesBase64,
    })

    if(error) {
      throw new Error(error.message)
    }

    return base64ToUint8Array(proof)
  } catch (ex) {
    throw new Error("Failed to create proof");
  }
};

/**
 * Verifies a BBS+ proof with a BBS public key
 * @param request Request for the verify proof operation
 *
 * @returns A result indicating if the proof was verified
 */
export const verifyProof = async (request: BbsVerifyProofRequest): Promise<BbsVerifyResult> => {
  const { publicKey, proof, messages, nonce } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { verified, error } = wrapFFI(bbs.bbs_verify_proof, {
      nonce: arrayBufferToBase64(nonce.buffer),
      public_key: arrayBufferToBase64(publicKey.buffer),
      proof: arrayBufferToBase64(proof.buffer),
      messages: messagesBase64,
    });

    if(error) {
      throw new Error(error.message)
    }

    return { verified }
  } catch (e: any) {
    return { verified: false, error: `${e.name}: ${e.message}` };
  }
};

/**
 * Verifies a BBS+ proof with a BLS12-381 public key
 * @param request Request for the verify proof operation
 *
 * @returns A result indicating if the proof was verified
 */
export const blsVerifyProof = async (request: BbsVerifyProofRequest): Promise<BbsVerifyResult> => {
  try {
    const { publicKey, proof, messages, nonce } = request;
    const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

    const { verified, error } = wrapFFI(bbs.bls_verify_proof, {
      nonce: arrayBufferToBase64(nonce.buffer),
      public_key: arrayBufferToBase64(publicKey.buffer),
      proof: arrayBufferToBase64(proof.buffer),
      messages: messagesBase64,
    });

    if(error) {
      throw new Error(error.message)
    }

    return { verified }
  } catch (e: any) {
    return { verified: false, error: `${e.name}: ${e.message}` };
  }
};

/**
 * Create a blinded commitment of messages for use in producing a blinded BBS+ signature
 * @param request Request for producing the blinded commitment
 *
 * @returns A commitment context
 */
export const commitmentForBlindSignRequest = async (
  request: BbsBlindSignContextRequest
): Promise<BbsBlindSignContext> => {
  const { publicKey, messages, blinded, nonce } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { commitment, challenge_hash, blinding_factor, proof_of_hidden_messages, error } = wrapFFI(bbs.bbs_blind_signature_commitment, {
      public_key: arrayBufferToBase64(publicKey.buffer),
      messages: messagesBase64,
      blinded,
      nonce: arrayBufferToBase64(nonce.buffer),
    })

    if(error) {
      throw new Error(error.message)
    }

    return {
      commitment: base64ToUint8Array(commitment),
      challengeHash: base64ToUint8Array(challenge_hash),
      blindingFactor: base64ToUint8Array(blinding_factor),
      proofOfHiddenMessages: base64ToUint8Array(proof_of_hidden_messages),
    }
  } catch {
    throw new Error("Failed to generate commitment");
  }
};

/**
 * Create a blinded commitment of messages for use in producing a blinded BBS+ signature
 * @param request Request for producing the blinded commitment
 *
 * @returns A commitment context
 */
export const blsCommitmentForBlindSignRequest = async (
  request: BlsBlindSignContextRequest
): Promise<BbsBlindSignContext> => {
  const { publicKey, messages, blinded, nonce, knownMessageCount } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { commitment, challenge_hash, blinding_factor, proof_of_hidden_messages, error } = wrapFFI(bbs.bls_blind_signature_commitment, {
      public_key: arrayBufferToBase64(publicKey.buffer),
      messages: messagesBase64,
      blinded,
      nonce: arrayBufferToBase64(nonce.buffer),
      known_message_count: knownMessageCount,
    })

    if(error) {
      throw new Error(error.message)
    }

    return {
      commitment: base64ToUint8Array(commitment),
      challengeHash: base64ToUint8Array(challenge_hash),
      blindingFactor: base64ToUint8Array(blinding_factor),
      proofOfHiddenMessages: base64ToUint8Array(proof_of_hidden_messages),
    }
  } catch {
    throw new Error("Failed to generate commitment");
  }
};

/**
 * Verifies a blind commitment of messages
 * @param request Request for the commitment verification
 *
 * @returns A boolean indicating if the context was verified
 */
export const verifyBlindSignContext = async (request: BbsVerifyBlindSignContextRequest): Promise<boolean> => {
  const { commitment, proofOfHiddenMessages, challengeHash, publicKey, blinded, nonce } = request;

  const { verified, error } = wrapFFI(bbs.bbs_verify_blind_signature_proof, {
    commitment: arrayBufferToBase64(commitment.buffer),
    proof_of_hidden_messages: arrayBufferToBase64(proofOfHiddenMessages.buffer),
    challenge_hash: arrayBufferToBase64(challengeHash.buffer),
    public_key: arrayBufferToBase64(publicKey.buffer),
    blinded,
    nonce: arrayBufferToBase64(nonce.buffer),
  })

  if(error) {
    return false
  }

  return verified
};

/**
 * Verifies a blind commitment of messages
 * @param request Request for the commitment verification
 *
 * @returns A boolean indicating if the context was verified
 */
export const blsVerifyBlindSignContext = async (request: BlsVerifyBlindSignContextRequest): Promise<boolean> => {
  const { commitment, proofOfHiddenMessages, challengeHash, publicKey, blinded, nonce, knownMessageCount } = request;

  const { verified, error } = wrapFFI(bbs.bls_verify_blind_signature_proof, {
    commitment: arrayBufferToBase64(commitment.buffer),
    proof_of_hidden_messages: arrayBufferToBase64(proofOfHiddenMessages.buffer),
    challenge_hash: arrayBufferToBase64(challengeHash.buffer),
    public_key: arrayBufferToBase64(publicKey.buffer),
    blinded,
    nonce: arrayBufferToBase64(nonce.buffer),
    known_message_count: knownMessageCount,
  })

  if(error) {
    return false
  }

  return verified
};

/**
 * Signs a set of messages featuring both known and blinded messages to the signer and produces a BBS+ signature
 * @param request Request for the blind sign operation
 *
 * @returns The raw signature value
 */
export const blindSign = async (request: BbsBlindSignRequest): Promise<Uint8Array> => {
  const { commitment, publicKey, secretKey, messages, known } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { blind_signature, error } = wrapFFI(bbs.bbs_blind_sign, {
      commitment: arrayBufferToBase64(commitment.buffer),
      public_key: arrayBufferToBase64(publicKey.buffer),
      secret_key: arrayBufferToBase64(secretKey.buffer),
      messages: messagesBase64,
      known
    })

    if(error) {
      throw new Error(error.message)
    }

    return base64ToUint8Array(blind_signature)
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Signs a set of messages featuring both known and blinded messages to the signer and produces a BBS+ signature
 * @param request Request for the blind sign operation
 *
 * @returns The raw signature value
 */
export const blsBlindSign = async (request: BlsBlindSignRequest): Promise<Uint8Array> => {
  const { commitment, publicKey, secretKey, messages, known, blindedMessageCount } = request;
  const messagesBase64 = messages.map((_) => arrayBufferToBase64(_.buffer))

  try {
    const { blind_signature, error } = wrapFFI(bbs.bls_blind_sign, {
      commitment: arrayBufferToBase64(commitment.buffer),
      public_key: arrayBufferToBase64(publicKey.buffer),
      secret_key: arrayBufferToBase64(secretKey.buffer),
      messages: messagesBase64,
      known,
      blinded_message_count: blindedMessageCount,
    })

    if(error) {
      throw new Error(error.message)
    }

    return base64ToUint8Array(blind_signature)
  } catch {
    throw new Error("Failed to sign");
  }
};

/**
 * Unblind a blinded BBS+ Signature (featuring both known and blinded messages)
 * @param blindSignature Blinded signature to unblind
 * @param blindingFactor Blinding factor returned as part of commitment context from `commitmentForBlindSignRequest`
 *
 * @returns The raw signature value
 */
export const unblindSignature = async (blindSignature: Uint8Array, blindingFactor: Uint8Array): Promise<Uint8Array> => {
  try {
    const { signature, error } = wrapFFI(bbs.bbs_get_unblinded_signature, {
      blind_signature: arrayBufferToBase64(blindSignature.buffer),
      blinding_factor: arrayBufferToBase64(blindingFactor.buffer)
    })

    if(error) {
      throw new Error(error.message)
    }

    return base64ToUint8Array(signature)
  } catch {
    throw new Error("Failed to unblind signature");
  }
};

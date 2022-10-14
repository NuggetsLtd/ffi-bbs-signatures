import { Bls12381ToBbsRequest, BbsKeyPair } from "./types";
import { wrapFFI, arrayBufferToBase64, base64ToUint8Array } from "./util";

/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bbs = require(path.resolve(path.join(__dirname, "../native/index.node")));

/**
 * Converts a BLS12-381 key to a BBS+ key
 * @param request Request for the key conversion
 *
 * @returns A BbsKeyPair
 */
export const bls12381toBbs = async (request: Bls12381ToBbsRequest): Promise<BbsKeyPair> => {
  try {
    if(!request.messageCount || request.messageCount <= 0){
      throw new RangeError('Message count should be greater than 0')
    }

    if(request.keyPair.secretKey) {
      const result = wrapFFI(bbs.bls_secret_key_to_bbs_key, {
        secret_key: arrayBufferToBase64(request.keyPair.secretKey.buffer),
        message_count: request.messageCount,
      });

      return {
        publicKey: base64ToUint8Array(result.public_key),
        secretKey: request.keyPair.secretKey,
        messageCount: request.messageCount,
      };
    }

    const result = wrapFFI(bbs.bls_public_key_to_bbs_key, {
      public_key: arrayBufferToBase64(request.keyPair.publicKey.buffer),
      message_count: request.messageCount,
    });

    return {
      publicKey: base64ToUint8Array(result.public_key),
      secretKey: request.keyPair.secretKey,
      messageCount: request.messageCount,
    };
    
  } catch {
    throw new Error("Failed to convert key");
  }
};

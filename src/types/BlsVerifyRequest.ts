/**
 * A request verify a BBS signature for a set of messages
 */
export interface BlsVerifyRequest {
  /**
   * BLS12-381 public key of the signer of the signature
   */
  readonly publicKey: Uint8Array;
  /**
   * Raw signature value
   */
  readonly signature: Uint8Array;
  /**
   * Messages that were signed to produce the signature
   */
  readonly messages: readonly Uint8Array[];
}

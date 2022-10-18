/**
 * A request to create a BBS signature that features blinded/committed messages
 *
 */
export interface BlsBlindSignContextRequest {
  /**
   * The resulting commitment of the blinded messages to sign
   */
  readonly publicKey: Uint8Array;
  /**
   * The zero based indices of which messages to hide
   */
  readonly blinded: readonly number[];
  /**
   * A nonce for the resulting proof
   */
  readonly nonce: Uint8Array;
  /**
   * Messages for the blind commitment
   */
  readonly messages: readonly Uint8Array[];
  /**
   * The known messages to sign
   */
  readonly knownMessageCount: number;
}

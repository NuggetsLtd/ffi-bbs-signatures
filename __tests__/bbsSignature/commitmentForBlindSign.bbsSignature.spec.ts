import {
  generateBls12381G2KeyPair,
  BbsBlindSignContextRequest,
  commitmentForBlindSignRequest,
  BbsVerifyBlindSignContextRequest,
  verifyBlindSignContext,
  BbsKeyPair,
  bls12381toBbs,
  BlsKeyPair,
} from "../../src";
import { stringToBytes } from "../utilities";
import { randomBytes } from "@stablelib/random";

const base64ToArrayBuffer = (value: string) =>
  Uint8Array.from(Buffer.from(value, 'base64'))

const seed = base64ToArrayBuffer('H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=')

describe("bbsSignature", () => {
  let blsKeyPair: Required<BlsKeyPair>;

  beforeAll(async () => {
    blsKeyPair = await generateBls12381G2KeyPair(seed);
  });

  describe("commitmentForBlindSignRequest", () => {

    describe('should create blind commitment context', () => {

      it("for single hidden (blinded) message", async () => {
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 3 });
        const request: BbsBlindSignContextRequest = {
          blinded: [ 0 ],
          messages: [ stringToBytes("HiddenMessage1") ],
          nonce: randomBytes(10),
          publicKey: bbsKeyPair.publicKey,
        };
  
        const { commitment, challengeHash, blindingFactor, proofOfHiddenMessages } = await commitmentForBlindSignRequest(request);
        
        expect(commitment).toBeInstanceOf(Uint8Array);
        expect(commitment.length).toEqual(48);
        expect(challengeHash).toBeInstanceOf(Uint8Array);
        expect(challengeHash.length).toEqual(32);
        expect(blindingFactor).toBeInstanceOf(Uint8Array);
        expect(blindingFactor.length).toEqual(32);
        expect(proofOfHiddenMessages).toBeInstanceOf(Uint8Array);
        expect(proofOfHiddenMessages.length).toEqual(116);
      });

      it("for multiple hidden (blinded) messages", async () => {
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 3 });
        const request: BbsBlindSignContextRequest = {
          blinded:  [ 0, 1, 2 ],
          messages: [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2"), stringToBytes("HiddenMessage3") ],
          nonce: randomBytes(10),
          publicKey: bbsKeyPair.publicKey,
        };
  
        const { commitment, challengeHash, blindingFactor, proofOfHiddenMessages } = await commitmentForBlindSignRequest(request);
        
        expect(commitment).toBeInstanceOf(Uint8Array);
        expect(commitment.length).toEqual(48);
        expect(challengeHash).toBeInstanceOf(Uint8Array);
        expect(challengeHash.length).toEqual(32);
        expect(blindingFactor).toBeInstanceOf(Uint8Array);
        expect(blindingFactor.length).toEqual(32);
        expect(proofOfHiddenMessages).toBeInstanceOf(Uint8Array);
        expect(proofOfHiddenMessages.length).toEqual(180);
      });

    })
  });

  describe("verifyBlindSignContext", () => {

    describe('should verify blind commitment context', () => {

      it("for single hidden (blinded) message", async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 3 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0 ];
        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1") ],
          nonce,
          publicKey
        };
  
        const { commitment, challengeHash, proofOfHiddenMessages } = await commitmentForBlindSignRequest(request);
        
        const verifyBlindSignContextRequest: BbsVerifyBlindSignContextRequest = {
          commitment,
          proofOfHiddenMessages,
          challengeHash,
          publicKey,
          blinded,
          nonce
        };
  
        const verified = await verifyBlindSignContext(verifyBlindSignContextRequest);
  
        expect(verified).toBe(true);
      });

      it("for multiple hidden (blinded) messages", async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 3 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0, 1, 2 ];
        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2"), stringToBytes("HiddenMessage3") ],
          nonce,
          publicKey
        };
  
        const { commitment , challengeHash, proofOfHiddenMessages } = await commitmentForBlindSignRequest(request);
        
        const verifyBlindSignContextRequest: BbsVerifyBlindSignContextRequest = {
          commitment,
          proofOfHiddenMessages,
          challengeHash,
          publicKey,
          blinded,
          nonce
        };
  
        const verified = await verifyBlindSignContext(verifyBlindSignContextRequest);
  
        expect(verified).toBe(true);
      });

    });

    describe('should NOT verify blind commitment context', () => {

      it('where incorrect blinded message indexes supplied', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 3 });
        const publicKey = bbsKeyPair.publicKey;
        const request: BbsBlindSignContextRequest = {
          blinded: [ 0, 1, 2 ],
          messages: [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2"), stringToBytes("HiddenMessage3") ],
          nonce,
          publicKey
        };
  
        const { commitment, challengeHash, proofOfHiddenMessages } = await commitmentForBlindSignRequest(request);
        
        const verifyBlindSignContextRequest: BbsVerifyBlindSignContextRequest = {
          commitment,
          proofOfHiddenMessages,
          challengeHash,
          publicKey,
          blinded: [ 0, 1 ],
          nonce
        };
  
        const verified = await verifyBlindSignContext(verifyBlindSignContextRequest);
  
        expect(verified).toBe(false);
      });

      it('where incorrect nonce supplied', async () => {
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 3 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0, 1, 2 ];
        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2"), stringToBytes("HiddenMessage3") ],
          nonce: randomBytes(10),
          publicKey
        };
  
        const { commitment, challengeHash, proofOfHiddenMessages } = await commitmentForBlindSignRequest(request);
        
        const verifyBlindSignContextRequest: BbsVerifyBlindSignContextRequest = {
          commitment,
          proofOfHiddenMessages,
          challengeHash,
          publicKey,
          blinded,
          nonce: randomBytes(10)
        };
  
        const verified = await verifyBlindSignContext(verifyBlindSignContextRequest);
  
        expect(verified).toBe(false);
      });

    });

  });

});

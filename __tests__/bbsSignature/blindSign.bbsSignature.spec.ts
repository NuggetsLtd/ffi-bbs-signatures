import {
  generateBls12381G2KeyPair,
  BbsBlindSignContextRequest,
  commitmentForBlindSignRequest,
  BbsBlindSignRequest,
  blindSign,
  unblindSignature,
  BbsKeyPair,
  bls12381toBbs,
  BBS_SIGNATURE_LENGTH,
  BlsKeyPair,
  BbsVerifyRequest,
  verify,
  createProof,
  verifyProof
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

  describe('blindSign', () => {

    describe('should sign with blinded messages', () => {

      it('where a single blinded message is to be signed', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 1 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0 ];
        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1") ],
          nonce,
          publicKey
        };
  
        const { commitment } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: [],
          known: []
        };

        const blindSignature = await blindSign(blindSignRequest);

        expect(blindSignature).toBeInstanceOf(Uint8Array);
        expect(blindSignature.length).toBe(BBS_SIGNATURE_LENGTH);
      });

      it('where a single blinded and single unblinded messages are to be signed', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 2 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0 ];
        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1") ],
          nonce,
          publicKey
        };
  
        const { commitment } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: [ stringToBytes("Message1") ],
          known: [ 1 ]
        };

        const blindSignature = await blindSign(blindSignRequest);

        expect(blindSignature).toBeInstanceOf(Uint8Array);
        expect(blindSignature.length).toBe(BBS_SIGNATURE_LENGTH);
      });

      it('where multiple blinded and multiple unblinded messages are to be signed', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 4 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0, 1 ];
        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2") ],
          nonce,
          publicKey
        };
  
        const { commitment } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: [ stringToBytes("Message1"), stringToBytes("Message2") ],
          known: [ 2, 3 ]
        };

        const blindSignature = await blindSign(blindSignRequest);

        expect(blindSignature).toBeInstanceOf(Uint8Array);
        expect(blindSignature.length).toBe(BBS_SIGNATURE_LENGTH);
      });

    })

  });

  describe('unblindSignature', () => {

    describe('should unblind blinded signature', () => {

      it('for signature of single blinded message', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 1 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0 ];

        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1") ],
          nonce,
          publicKey
        };
        const { commitment, blindingFactor } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: [],
          known: []
        };
        const blindSignature = await blindSign(blindSignRequest);

        const signature = await unblindSignature(blindSignature, blindingFactor);

        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(BBS_SIGNATURE_LENGTH);
      });

      it('for signature of single blinded and unblinded messages', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 2 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0 ];

        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1") ],
          nonce,
          publicKey
        };
        const { commitment, blindingFactor } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: [ stringToBytes("Message1") ],
          known: [ 1 ]
        };
        const blindSignature = await blindSign(blindSignRequest);

        const signature = await unblindSignature(blindSignature, blindingFactor);

        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(BBS_SIGNATURE_LENGTH);
      });

      it('for signature of multiple blinded and unblinded messages', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 4 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0, 1 ];

        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2") ],
          nonce,
          publicKey
        };
        const { commitment, blindingFactor } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: [ stringToBytes("Message1"), stringToBytes("Message2") ],
          known: [ 2, 3 ]
        };
        const blindSignature = await blindSign(blindSignRequest);

        const signature = await unblindSignature(blindSignature, blindingFactor);

        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(BBS_SIGNATURE_LENGTH);
      });

    });

    describe('should verify unblinded signature', () => {

      it('for signature of single blinded message', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 1 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0 ];
        const blindedMessages = [ stringToBytes("HiddenMessage1") ];

        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: blindedMessages,
          nonce,
          publicKey
        };
        const { commitment, blindingFactor } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: [], // no visible messages
          known: [] // no visible messages to expose
        };
        const blindSignature = await blindSign(blindSignRequest);

        const signature = await unblindSignature(blindSignature, blindingFactor);

        const verificationRequest: BbsVerifyRequest = {
          publicKey,
          signature,
          messages: blindedMessages
        }

        const { verified } = await verify(verificationRequest);

        expect(verified).toBe(true);
      });

      it('for signature of single blinded and unblinded messages', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 2 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0 ];
        const blindedMessages = [ stringToBytes("HiddenMessage1") ];
        const unblindedMessages = [ stringToBytes("Message1") ];

        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: blindedMessages,
          nonce,
          publicKey
        };
        const { commitment, blindingFactor } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: unblindedMessages,
          known: [ 1 ]
        };
        const blindSignature = await blindSign(blindSignRequest);

        const signature = await unblindSignature(blindSignature, blindingFactor);

        const verificationRequest: BbsVerifyRequest = {
          publicKey,
          signature,
          messages: [ ...blindedMessages, ...unblindedMessages ]
        }

        const { verified } = await verify(verificationRequest);

        expect(verified).toBe(true);
      });

      it('for signature of multiple blinded and unblinded messages', async () => {
        const nonce = randomBytes(10);
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 4 });
        const publicKey = bbsKeyPair.publicKey;
        const blinded = [ 0, 1 ];
        const blindedMessages = [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2") ];
        const unblindedMessages = [ stringToBytes("Message1"), stringToBytes("Message2") ];

        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: blindedMessages,
          nonce,
          publicKey
        };
        const { commitment, blindingFactor } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: unblindedMessages,
          known: [ 2, 3 ]
        };
        const blindSignature = await blindSign(blindSignRequest);

        const signature = await unblindSignature(blindSignature, blindingFactor);

        const verificationRequest: BbsVerifyRequest = {
          publicKey,
          signature,
          messages: [ ...blindedMessages, ...unblindedMessages ]
        }

        const { verified } = await verify(verificationRequest);

        expect(verified).toBe(true);
      });

    });

    describe('should generate proof from unblinded signature', () => {
      const blindedMessages = [ stringToBytes("HiddenMessage1"), stringToBytes("HiddenMessage2") ];
      const unblindedMessages = [ stringToBytes("Message1"), stringToBytes("Message2") ];
      let signature: Uint8Array, publicKey: Uint8Array, nonce: Uint8Array

      beforeAll(async () => {
        const blinded = [ 0, 1 ];
        const bbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: { publicKey: blsKeyPair.publicKey }, messageCount: 4 });
        nonce = randomBytes(10);
        publicKey = bbsKeyPair.publicKey;

        const request: BbsBlindSignContextRequest = {
          blinded,
          messages: blindedMessages,
          nonce,
          publicKey
        };
        const { commitment, blindingFactor } = await commitmentForBlindSignRequest(request);

        const blindSignRequest: BbsBlindSignRequest = {
          commitment,
          publicKey,
          secretKey: blsKeyPair.secretKey,
          messages: unblindedMessages,
          known: [ 2, 3 ]
        };
        const blindSignature = await blindSign(blindSignRequest);

        signature = await unblindSignature(blindSignature, blindingFactor);
      });

      it('where 1 unblinded message revealed', async () => {
        // derive proof for 1 (unblinded) message
        const proof = await createProof({ signature, publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], revealed: [ 2 ], nonce });

        // verify proof with unblinded message
        const { verified } = await verifyProof({ proof, publicKey, messages: [ unblindedMessages[0] ], nonce });

        expect(verified).toBe(true);
      });

      it('where 1 blinded message revealed', async () => {
        // derive proof for 1 (blinded) message
        const proof = await createProof({ signature, publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], revealed: [ 0 ], nonce });

        // verify proof with unblinded message
        const { verified } = await verifyProof({ proof, publicKey, messages: [ blindedMessages[0] ], nonce });

        expect(verified).toBe(true);
      });

      it('where all messages revealed (2x blinded & 2x unblinded)', async () => {
        // derive proof for all messages
        const proof = await createProof({ signature, publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], revealed: [ 0, 1, 2, 3 ], nonce });

        // verify proof with all messages
        const { verified } = await verifyProof({ proof, publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], nonce });

        expect(verified).toBe(true);
      });

      describe('should fail to verify proof', () => {

        it('where messages are incorrect', async () => {
          const proof = await createProof({ signature, publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], revealed: [ 0, 1, 2 ], nonce });

          const outcome = await verifyProof({ proof, publicKey, messages: [ unblindedMessages[0], unblindedMessages[0], unblindedMessages[0] ], nonce });

          expect(outcome.verified).toBe(false);
        });

        it('where messages public key is incorrect', async () => {
          const proof = await createProof({ signature, publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], revealed: [ 0, 1, 2, 3 ], nonce });

          const randomSeed = base64ToArrayBuffer('JhRwDXovpCVDEhrG/SAsjEaUGbsty2Lu/AdywOHnNPrz7r4phYXvLNmvAHSdosgqbZA=');
          const randomBlsKey = await generateBls12381G2KeyPair(randomSeed);

          const randomBbsKeyPair: BbsKeyPair = await bls12381toBbs({ keyPair: randomBlsKey, messageCount: 4 });

          const outcome = await verifyProof({ proof, publicKey: randomBbsKeyPair.publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], nonce });

          expect(outcome.verified).toBe(false);
        });

        it('where nonce is incorrect', async () => {
          // derive proof for 1 (unblinded) message
          const proof = await createProof({ signature, publicKey, messages: [ ...blindedMessages, ...unblindedMessages ], revealed: [ 2 ], nonce });
  
          // verify proof with unblinded message
          const outcome = await verifyProof({ proof, publicKey, messages: [ unblindedMessages[0] ], nonce: randomBytes(32) });
  
          expect(outcome.verified).toBe(false);
        });

      });

    });

  });

});

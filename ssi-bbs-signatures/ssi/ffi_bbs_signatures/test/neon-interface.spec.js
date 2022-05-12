const bbs = require('../native')
const crypto = require('crypto')

const base64ToArrayBuffer = (value) =>
  Uint8Array.from(Buffer.from(value, 'base64')).buffer

const seed = base64ToArrayBuffer('H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=')

const messages = [
  base64ToArrayBuffer('bWVzc2FnZTE'), // "message1"
  base64ToArrayBuffer('bWVzc2FnZTI'), // "message2"
  base64ToArrayBuffer('bWVzc2FnZTM') // "message3"
]

const nonce = Uint8Array.from(crypto.randomBytes(32)).buffer

describe('NEON NodeJS Interface:', () => {

  it('should export the expected items', () => {
    expect(Object.keys(bbs)).toEqual([
      'bls_generate_blinded_g1_key',
      'bls_generate_blinded_g2_key',
      'bls_generate_g1_key',
      'bls_generate_g2_key',
      'bls_secret_key_to_bbs_key',
      'bls_public_key_to_bbs_key',
      'bbs_sign',
      'bbs_verify',
      'bbs_create_proof',
      'bbs_verify_proof',
      'bls_verify_proof',
      'bbs_blind_signature_commitment',
      'bbs_verify_blind_signature_proof',
      'bbs_blind_sign',
      'bbs_get_unblinded_signature'
    ])
  })

  it('should export foreign function interface functions', () => {
    expect(typeof bbs.bls_generate_blinded_g1_key).toBe('function')
    expect(typeof bbs.bls_generate_blinded_g2_key).toBe('function')
    expect(typeof bbs.bls_generate_g1_key).toBe('function')
    expect(typeof bbs.bls_generate_g2_key).toBe('function')
    expect(typeof bbs.bls_secret_key_to_bbs_key).toBe('function')
    expect(typeof bbs.bls_public_key_to_bbs_key).toBe('function')
    expect(typeof bbs.bbs_sign).toBe('function')
    expect(typeof bbs.bbs_verify).toBe('function')
    expect(typeof bbs.bbs_create_proof).toBe('function')
    expect(typeof bbs.bbs_verify_proof).toBe('function')
    expect(typeof bbs.bls_verify_proof).toBe('function')
    expect(typeof bbs.bbs_blind_signature_commitment).toBe('function')
    expect(typeof bbs.bbs_verify_blind_signature_proof).toBe('function')
    expect(typeof bbs.bbs_blind_sign).toBe('function')
    expect(typeof bbs.bbs_get_unblinded_signature).toBe('function')
  })

  describe('Functions', () => {

    describe('bls_generate_g1_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = bbs.bls_generate_g1_key(seed)

        expect(Buffer.from(blsKey.publicKey).toString('hex')).toBe('b9f1c727063dff18ebb47806c900f517dccd449aa2078ce14970c4042fcc26b36e5c917023e20bc6edae3c04b277955f')
        expect(Buffer.from(blsKey.secretKey).toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = bbs.bls_generate_g1_key()

        expect(Buffer.from(blsKey.publicKey).length).toBe(48)
        expect(Buffer.from(blsKey.secretKey).length).toBe(32)
      })

    })

    describe('bls_generate_g2_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = bbs.bls_generate_g2_key(seed)

        expect(Buffer.from(blsKey.publicKey).toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfa')
        expect(Buffer.from(blsKey.secretKey).toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = bbs.bls_generate_g2_key()

        expect(Buffer.from(blsKey.publicKey).length).toBe(96)
        expect(Buffer.from(blsKey.secretKey).length).toBe(32)
      })

    })

    describe('bls_generate_blinded_g1_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = bbs.bls_generate_blinded_g1_key(seed)

        expect(Buffer.from(blsKey.publicKey).toString('hex')).toBe('af108e14a93936f1d966a518d1be83770bc11a0caa6509a62fdbc1dedf2202f63620438117c975ac1576dc1482955e7a')
        expect(Buffer.from(blsKey.secretKey).toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
        expect(Buffer.from(blsKey.blindingFactor).toString('hex')).toBe('4d8b083090288f084d723012f6117bff8440096bb8b56402d31bdf1ba1d88655')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = bbs.bls_generate_blinded_g1_key()

        expect(Buffer.from(blsKey.publicKey).length).toBe(48)
        expect(Buffer.from(blsKey.secretKey).length).toBe(32)
        expect(Buffer.from(blsKey.blindingFactor).length).toBe(32)
      })

    })

    describe('bls_generate_blinded_g2_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = bbs.bls_generate_blinded_g2_key(seed)

        expect(Buffer.from(blsKey.publicKey).toString('hex')).toBe('9062c81ce87bf8d1cd7fc25662dc4fb6236f103739110e95d1389f1dff6f6c29b8f08c333423b005f513668cf62458601837594c01e0f419f86210079858fb7563de15c24797a1dd5aab4bc49ebfc00cecea2edbaa831cf7c224503492257ae6')
        expect(Buffer.from(blsKey.secretKey).toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
        expect(Buffer.from(blsKey.blindingFactor).toString('hex')).toBe('636b9b1314a2877ee6236ffb4d9d57f8a88ac6ee1ce5650e057b0ae87d13703e')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = bbs.bls_generate_blinded_g2_key()

        expect(Buffer.from(blsKey.publicKey).length).toBe(96)
        expect(Buffer.from(blsKey.secretKey).length).toBe(32)
        expect(Buffer.from(blsKey.blindingFactor).length).toBe(32)
      })

    })

    describe('bls_secret_key_to_bbs_key()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
      })

      it('where "messageCount" = 1', () => {
        const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: 1, secretKey: blsKey.secretKey })

        expect(Buffer.from(bbsPublicKey).toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfa8a76e5cbe5214abfd637099582772dc25c4a6871edd33559f92db6de6bd1671bca4a4883d930c31423727a342c85636100000001b9541258be3921882ba181b8fe7eb08d8c6db3d47e21b04f6eae506ee9746826d4597e83c0b95b9fe7bc4495ec3efcbd')
      })

      it('where "messageCount" = 3', () => {
        const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: 3, secretKey: blsKey.secretKey })

        expect(Buffer.from(bbsPublicKey).toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfaac09fba8a049fb3a098e2483c45881960ca33ca450cf0f11e951d127ad9c50f101531c7c9a4d45a6e0c175e5c0f0da600000000393c8623f78f956458832ca9a06721e6c4e94eec4a2d196c6e4a1efa779d60dcb85f2e0cff66f63ae3b0220e0850c2e198e5609e93673e6a0e3878a6674acdea5d40b3459b0aa3eaf66b1de2668695234fb2ed4e2fd53f9a93a08dc222c4c13beb1eff39abb05eb978804603cfb23b46b8e2a91e0b9461f4603c69c02f0e946164f0a6a870a36feebf9211aa3560c0490')
      })

    })

    describe('bls_public_key_to_bbs_key()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
      })

      it('where "messageCount" = 1', () => {
        const bbsPublicKey = bbs.bls_public_key_to_bbs_key({ messageCount: 1, publicKey: blsKey.publicKey })

        expect(Buffer.from(bbsPublicKey).toString('hex')).toBe('9062c81ce87bf8d1cd7fc25662dc4fb6236f103739110e95d1389f1dff6f6c29b8f08c333423b005f513668cf62458601837594c01e0f419f86210079858fb7563de15c24797a1dd5aab4bc49ebfc00cecea2edbaa831cf7c224503492257ae6b401adb52f2ef35fb07f647c0b1eecf9436b4ccdd7aab242daf380548247b5d4fa51097a1bd3544ebf6b872eebc2cd6600000001b224a86d0771dd62e98ffcb8fe7b75313a6fb27a0fc8c7f11e213a9734f2a171932295a2ce515dfaac465c461530f2c4')
      })

      it('where "messageCount" = 3', () => {
        const bbsPublicKey = bbs.bls_public_key_to_bbs_key({ messageCount: 3, publicKey: blsKey.publicKey })

        expect(Buffer.from(bbsPublicKey).toString('hex')).toBe('9062c81ce87bf8d1cd7fc25662dc4fb6236f103739110e95d1389f1dff6f6c29b8f08c333423b005f513668cf62458601837594c01e0f419f86210079858fb7563de15c24797a1dd5aab4bc49ebfc00cecea2edbaa831cf7c224503492257ae68bd722df7e300a4b15eb3f18cfa04330a040056168d95631b592f93580b9f14aacaca78bcdc9ec6de645e3c01c4b1a9b00000003a692734fb179129164d1c65e709ecdaf2da2b0e4a1c88c4451233506c1d495a5d2608439f6578238e7fc2d8315437d57af332465365de1d97c3ef44223072e1a268ea5136e4d79367fa8e560a8750de27b02224f41dec006acdb51bd6b6d8b35a6308236aa97d9a15088dd4559fe24ea46088127099e7763e935e8175ebc5a817fd85041bfdc6d2c0f2bbfa713f117bd')
      })

    })

    describe('bbs_sign()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
      })

      describe('should generate signature of the correct length', () => {

        it('where number of messages = 1', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: 1, secretKey: blsKey.secretKey })
          const signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages: [ messages[0] ] })

          expect(Buffer.from(signature).length).toBe(112)
        })

        it('where number of messages = 3', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
          const signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages })

          expect(Buffer.from(signature).length).toBe(112)
        })

      })

      it('should error where "messageCount" below number of messages', () => {
        const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: 1, secretKey: blsKey.secretKey })

        expect(() => bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages }))
          .toThrow(/Public key to message mismatch. Expected 1, found 1/)
      })

    })

    describe('bbs_blind_signature_commitment()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
        bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
      })

      it('should generate blind commitment context correctly', () => {

        const { commitment, challengeHash, blindingFactor, proofOfHiddenMessages } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

        expect(Buffer.from(commitment).length).toBe(48)
        expect(Buffer.from(challengeHash).length).toBe(32)
        expect(Buffer.from(blindingFactor).length).toBe(32)
        expect(Buffer.from(proofOfHiddenMessages).length).toBe(148)
      })

    })

    describe('bbs_verify_blind_signature_proof()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
        bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
      })

      describe('should verify blind commitment context correctly', () => {

        it('with 1 hidden message in commitment context', () => {
          const { commitment, challengeHash, proofOfHiddenMessages } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[1] ], blinded: [ 1 ], nonce })
          const verified = bbs.bbs_verify_blind_signature_proof({ commitment, challengeHash, proofOfHiddenMessages, publicKey: bbsPublicKey, blinded: [ 1 ], nonce })

          expect(verified).toBe(true)
        })

        it('with 3 hidden messages in commitment context', () => {
          const { commitment, challengeHash, proofOfHiddenMessages } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages, blinded: [ 0, 1, 2 ], nonce })
          const verified = bbs.bbs_verify_blind_signature_proof({ commitment, challengeHash, proofOfHiddenMessages, publicKey: bbsPublicKey, blinded: [ 0, 1, 2 ], nonce })

          expect(verified).toBe(true)
        })

      })

      describe('should NOT verify blind commitment context', () => {

        it('where incorrect blinded message indexes supplied', () => {
          const { commitment, challengeHash, proofOfHiddenMessages } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
          const verified = bbs.bbs_verify_blind_signature_proof({ commitment, challengeHash, proofOfHiddenMessages, publicKey: bbsPublicKey, blinded: [ 0 ], nonce })

          expect(verified).toBe(false)
        })

        it('where incorrect nonce supplied', () => {
          const randomNonce = Uint8Array.from(crypto.randomBytes(32)).buffer
          const { commitment, challengeHash, proofOfHiddenMessages } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
          const verified = bbs.bbs_verify_blind_signature_proof({ commitment, challengeHash, proofOfHiddenMessages, publicKey: bbsPublicKey, blinded: [ 0 ], nonce: randomNonce })

          expect(verified).toBe(false)
        })

      })

    })

    describe('bbs_blind_sign()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
        bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
      })

      it('should generate blind signature of the correct length', () => {
        const { commitment } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
        const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ messages[2] ], known: [ 2 ] })

        expect(Buffer.from(blindSignature).length).toBe(112)
      })

    })

    describe('bbs_get_unblinded_signature()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
        bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
      })

      it('should retrieve unblinded signature of the correct length', () => {
        const { commitment, blindingFactor } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
        const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ messages[2] ], known: [ 2 ] })

        expect(Buffer.from(blindSignature).length).toBe(112)

        const unblindedSignature = bbs.bbs_get_unblinded_signature(blindSignature, blindingFactor)

        expect(Buffer.from(unblindedSignature).length).toBe(112)
      })

    })

    describe('bbs_verify()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
      })

      describe('should verify a standard signature', () => {

        it('where 1 message is signed', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: 1, secretKey: blsKey.secretKey })
          const signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages: [ messages[0] ] })

          const verified = bbs.bbs_verify({ signature, publicKey: bbsPublicKey, messages: [ messages[0] ] })

          expect(verified).toBe(true)
        })

        it('where 3 messages are signed', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
          const signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages })

          const verified = bbs.bbs_verify({ signature, publicKey: bbsPublicKey, messages })

          expect(verified).toBe(true)
        })

      })

      describe('should verify blinded signature', () => {

        it('where 1 blinded message is signed', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: 1, secretKey: blsKey.secretKey })

          // single blinded message commitment
          const { commitment, blindingFactor } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0] ], blinded: [ 0 ], nonce })

          // blind sign with no unblinded messages
          const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ ], known: [ ] })
          const unblindedSignature = bbs.bbs_get_unblinded_signature(blindSignature, blindingFactor)

          // verify unblinded signature
          const verified = bbs.bbs_verify({ signature: unblindedSignature, publicKey: bbsPublicKey, messages: [ messages[0] ] })

          expect(verified).toBe(true)
        })

        it('where 2 blinded messages, and 1 unblinded are signed', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })

          // 2x blinded message commitment
          const { commitment, blindingFactor } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ messages[2] ], known: [ 2 ] })
          const unblindedSignature = bbs.bbs_get_unblinded_signature(blindSignature, blindingFactor)

          // verify unblinded signature
          const verified = bbs.bbs_verify({ signature: unblindedSignature, publicKey: bbsPublicKey, messages })

          expect(verified).toBe(true)
        })

      })

      describe('should fail to verify a signature', () => {

        it('where messages are incorrect', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
          const signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages })

          const verified = bbs.bbs_verify({ signature, publicKey: bbsPublicKey, messages: [ messages[0], messages[0], messages[0] ] })

          expect(verified).toBe(false)
        })

        it('where public key is incorrect', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })

          const signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages })

          const randomSeed = base64ToArrayBuffer('JhRwDXovpCVDEhrG/SAsjEaUGbsty2Lu/AdywOHnNPrz7r4phYXvLNmvAHSdosgqbZA=')
          const randomBlsKey = bbs.bls_generate_blinded_g2_key(randomSeed)
          const randomBbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: randomBlsKey.secretKey })

          const verified = bbs.bbs_verify({ signature, publicKey: randomBbsPublicKey, messages })

          expect(verified).toBe(false)
        })

        it('where messages are incorrect for unblinded signature', () => {
          const bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })

          // 2x blinded message commitment
          const { commitment, blindingFactor } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ messages[2] ], known: [ 2 ] })
          const unblindedSignature = bbs.bbs_get_unblinded_signature(blindSignature, blindingFactor)

          // verify unblinded signature
          const verified = bbs.bbs_verify({ signature: unblindedSignature, publicKey: bbsPublicKey, messages: [ messages[0], messages[0], messages[0] ] })

          expect(verified).toBe(false)
        })

      })

    })

    describe('bbs_create_proof()', () => {
      let blsKey, bbsPublicKey, signature

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
        bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
        signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages })
      })

      describe('should generate proof of the correct length', () => {

        it('where 1 message revealed', () => {
          const proof = bbs.bbs_create_proof({ signature, publicKey: bbsPublicKey, messages, revealed: [ 1 ], nonce })

          expect(Buffer.from(proof).length).toBe(447)
        })

        it('where 3 messages revealed', () => {
          const proof = bbs.bbs_create_proof({ signature, publicKey: bbsPublicKey, messages, revealed: [ 0, 1, 2 ], nonce })

          expect(Buffer.from(proof).length).toBe(383)
        })

        it('where signature contains blinded messages', () => {
          // 2x blinded message commitment
          const { commitment, blindingFactor } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ messages[2] ], known: [ 2 ] })
          const unblindedSignature = bbs.bbs_get_unblinded_signature(blindSignature, blindingFactor)

          // generate proof with blinded & unblinded messages
          const proof = bbs.bbs_create_proof({ signature: unblindedSignature, publicKey: bbsPublicKey, messages, revealed: [ 0, 1, 2 ], nonce })

          expect(Buffer.from(proof).length).toBe(383)
        })

      })

    })

    describe('bbs_verify_proof()', () => {
      let blsKey, bbsPublicKey, signature

      beforeAll(() => {
        blsKey = bbs.bls_generate_blinded_g2_key(seed)
        bbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: blsKey.secretKey })
        signature = bbs.bbs_sign({ secretKey: blsKey.secretKey, publicKey: bbsPublicKey, messages })
      })

      describe('should verify a proof', () => {

        it('where 1 message revealed', () => {
          const proof = bbs.bbs_create_proof({ signature, publicKey: bbsPublicKey, messages, revealed: [ 1 ], nonce })

          const verified = bbs.bbs_verify_proof({ proof, publicKey: bbsPublicKey, messages: [ messages[1] ], nonce })

          expect(verified).toBe(true)
        })

        it('where 3 messages revealed', () => {
          const proof = bbs.bbs_create_proof({ signature, publicKey: bbsPublicKey, messages, revealed: [ 0, 1, 2 ], nonce })

          const verified = bbs.bbs_verify_proof({ proof, publicKey: bbsPublicKey, messages, nonce })

          expect(verified).toBe(true)
        })

        describe('with blinded messages', () => {
          let unblindedSignature

          beforeAll(() => {
            // 2x blinded message commitment
            const { commitment, blindingFactor } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

            // blind sign with 1 unblinded message
            const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ messages[2] ], known: [ 2 ] })
            unblindedSignature = bbs.bbs_get_unblinded_signature(blindSignature, blindingFactor)
          })

          it('where 1 unblinded message revealed', () => {
            // derive proof for 1 (unblinded) message
            const proof = bbs.bbs_create_proof({ signature: unblindedSignature, publicKey: bbsPublicKey, messages, revealed: [ 2 ], nonce })

            // verify proof with unblinded message
            const verified = bbs.bbs_verify_proof({ proof, publicKey: bbsPublicKey, messages: [ messages[2] ], nonce })

            expect(verified).toBe(true)
          })

          it('where 1 blinded message revealed', () => {
            // derive proof for 1 (blinded) message
            const proof = bbs.bbs_create_proof({ signature: unblindedSignature, publicKey: bbsPublicKey, messages, revealed: [ 0 ], nonce })

            // verify proof with unblinded message
            const verified = bbs.bbs_verify_proof({ proof, publicKey: bbsPublicKey, messages: [ messages[0] ], nonce })

            expect(verified).toBe(true)
          })

          it('where all messages revealed (2x blinded & 1x unblinded)', () => {
            // derive proof for all messages
            const proof = bbs.bbs_create_proof({ signature: unblindedSignature, publicKey: bbsPublicKey, messages, revealed: [ 0, 1, 2 ], nonce })

            // verify proof with all messages
            const verified = bbs.bbs_verify_proof({ proof, publicKey: bbsPublicKey, messages, nonce })

            expect(verified).toBe(true)
          })

        })

      })

      describe('should fail to verify a proof', () => {

        it('where messages are incorrect', () => {
          const proof = bbs.bbs_create_proof({ signature, publicKey: bbsPublicKey, messages, revealed: [ 0, 1, 2 ], nonce })

          expect(() => bbs.bbs_verify_proof({ proof, publicKey: bbsPublicKey, messages: [ messages[0], messages[0], messages[0] ], nonce }))
            .toThrow(/The proof failed due to a revealed message was supplied that was not signed or a message was revealed that was initially hidden/)
        })

        it('where messages public key is incorrect', () => {
          const proof = bbs.bbs_create_proof({ signature, publicKey: bbsPublicKey, messages, revealed: [ 0, 1, 2 ], nonce })

          const randomSeed = base64ToArrayBuffer('JhRwDXovpCVDEhrG/SAsjEaUGbsty2Lu/AdywOHnNPrz7r4phYXvLNmvAHSdosgqbZA=')
          const randomBlsKey = bbs.bls_generate_blinded_g2_key(randomSeed)
          const randomBbsPublicKey = bbs.bls_secret_key_to_bbs_key({ messageCount: messages.length, secretKey: randomBlsKey.secretKey })

          expect(() => bbs.bbs_verify_proof({ proof, publicKey: randomBbsPublicKey, messages, nonce }))
            .toThrow(/The proof failed due to An invalid signature was supplied/)
        })

        it('with blinded messages, where messages are incorrect', () => {
          // 2x blinded message commitment
          const { commitment, blindingFactor } = bbs.bbs_blind_signature_commitment({ publicKey: bbsPublicKey, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const blindSignature = bbs.bbs_blind_sign({ commitment, publicKey: bbsPublicKey, secretKey: blsKey.secretKey, messages: [ messages[2] ], known: [ 2 ] })
          const unblindedSignature = bbs.bbs_get_unblinded_signature(blindSignature, blindingFactor)

          // derive proof for all messages
          const proof = bbs.bbs_create_proof({ signature: unblindedSignature, publicKey: bbsPublicKey, messages, revealed: [ 0, 1, 2 ], nonce })

          // attempt to verify with incorrect messages
          expect(() => bbs.bbs_verify_proof({ proof, publicKey: bbsPublicKey, messages: [ messages[2], messages[2], messages[2] ], nonce }))
            .toThrow(/The proof failed due to a revealed message was supplied that was not signed or a message was revealed that was initially hidden/)
        })

      })

    })

  })

})

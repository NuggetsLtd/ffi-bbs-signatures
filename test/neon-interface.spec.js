const bbs = require('../native')
const crypto = require('crypto')

const objectToArrayBuffer = (value) =>
  Uint8Array.from(Buffer.from(JSON.stringify(value))).buffer

const wrapFFI = (func, context) => JSON.parse(func(objectToArrayBuffer(context)))

const seed = 'H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ='

const messages = [
  'bWVzc2FnZTE', // "message1"
  'bWVzc2FnZTI', // "message2"
  'bWVzc2FnZTM' // "message3"
]

const nonce = Uint8Array.from(crypto.randomBytes(32)).buffer

describe('NEON NodeJS Interface:', () => {

  it('should export the expected items', () => {
    expect(Object.keys(bbs)).toEqual([
      'bbs_blind_signature_size',
      'bbs_blinding_factor_size',
      'bls_public_key_g1_size',
      'bls_public_key_g2_size',
      'bls_secret_key_size',
      'bbs_signature_size',
      'bls_generate_blinded_g1_key',
      'bls_generate_blinded_g2_key',
      'bls_generate_g1_key',
      'bls_generate_g2_key',
      'bls_secret_key_to_bbs_key',
      'bls_public_key_to_bbs_key',
      'bbs_sign',
      'bls_sign',
      'bbs_verify',
      'bls_verify',
      'bbs_create_proof',
      'bls_create_proof',
      'bbs_verify_proof',
      'bls_verify_proof',
      'bbs_blind_signature_commitment',
      'bls_blind_signature_commitment',
      'bbs_verify_blind_signature_proof',
      'bls_verify_blind_signature_proof',
      'bbs_blind_sign',
      'bls_blind_sign',
      'bbs_get_unblinded_signature'
    ])
  })

  it('should export foreign function interface functions', () => {
    expect(typeof bbs.bbs_blind_signature_size).toBe('function')
    expect(typeof bbs.bbs_blinding_factor_size).toBe('function')
    expect(typeof bbs.bls_public_key_g1_size).toBe('function')
    expect(typeof bbs.bls_public_key_g2_size).toBe('function')
    expect(typeof bbs.bls_secret_key_size).toBe('function')
    expect(typeof bbs.bbs_signature_size).toBe('function')
    expect(typeof bbs.bls_generate_blinded_g1_key).toBe('function')
    expect(typeof bbs.bls_generate_blinded_g2_key).toBe('function')
    expect(typeof bbs.bls_generate_g1_key).toBe('function')
    expect(typeof bbs.bls_generate_g2_key).toBe('function')
    expect(typeof bbs.bls_secret_key_to_bbs_key).toBe('function')
    expect(typeof bbs.bls_public_key_to_bbs_key).toBe('function')
    expect(typeof bbs.bbs_sign).toBe('function')
    expect(typeof bbs.bls_sign).toBe('function')
    expect(typeof bbs.bbs_verify).toBe('function')
    expect(typeof bbs.bls_verify).toBe('function')
    expect(typeof bbs.bbs_create_proof).toBe('function')
    expect(typeof bbs.bls_create_proof).toBe('function')
    expect(typeof bbs.bbs_verify_proof).toBe('function')
    expect(typeof bbs.bls_verify_proof).toBe('function')
    expect(typeof bbs.bbs_blind_signature_commitment).toBe('function')
    expect(typeof bbs.bls_blind_signature_commitment).toBe('function')
    expect(typeof bbs.bbs_verify_blind_signature_proof).toBe('function')
    expect(typeof bbs.bls_verify_blind_signature_proof).toBe('function')
    expect(typeof bbs.bbs_blind_sign).toBe('function')
    expect(typeof bbs.bls_blind_sign).toBe('function')
    expect(typeof bbs.bbs_get_unblinded_signature).toBe('function')
  })

  describe('Functions', () => {

    describe('bls_generate_g1_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_g1_key, { seed })

        expect(Buffer.from(blsKey.public_key, 'base64').toString('hex')).toBe('b9f1c727063dff18ebb47806c900f517dccd449aa2078ce14970c4042fcc26b36e5c917023e20bc6edae3c04b277955f')
        expect(Buffer.from(blsKey.secret_key, 'base64').toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_g1_key, { })

        expect(Buffer.from(blsKey.public_key, 'base64').length).toBe(48)
        expect(Buffer.from(blsKey.secret_key, 'base64').length).toBe(32)
      })

    })

    describe('bls_generate_g2_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })

        expect(Buffer.from(blsKey.public_key, 'base64').toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfa')
        expect(Buffer.from(blsKey.secret_key, 'base64').toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_g2_key, { })

        expect(Buffer.from(blsKey.public_key, 'base64').length).toBe(96)
        expect(Buffer.from(blsKey.secret_key, 'base64').length).toBe(32)
      })

    })

    describe('bls_generate_blinded_g1_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_blinded_g1_key, { seed })

        expect(Buffer.from(blsKey.public_key, 'base64').toString('hex')).toBe('af108e14a93936f1d966a518d1be83770bc11a0caa6509a62fdbc1dedf2202f63620438117c975ac1576dc1482955e7a')
        expect(Buffer.from(blsKey.secret_key, 'base64').toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
        expect(Buffer.from(blsKey.blinding_factor, 'base64').toString('hex')).toBe('4d8b083090288f084d723012f6117bff8440096bb8b56402d31bdf1ba1d88655')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_blinded_g1_key, { })

        expect(Buffer.from(blsKey.public_key, 'base64').length).toBe(48)
        expect(Buffer.from(blsKey.secret_key, 'base64').length).toBe(32)
        expect(Buffer.from(blsKey.blinding_factor, 'base64').length).toBe(32)
      })

    })

    describe('bls_generate_blinded_g2_key()', () => {

      it('where "seed" is provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_blinded_g2_key, { seed })

        expect(Buffer.from(blsKey.public_key, 'base64').toString('hex')).toBe('9062c81ce87bf8d1cd7fc25662dc4fb6236f103739110e95d1389f1dff6f6c29b8f08c333423b005f513668cf62458601837594c01e0f419f86210079858fb7563de15c24797a1dd5aab4bc49ebfc00cecea2edbaa831cf7c224503492257ae6')
        expect(Buffer.from(blsKey.secret_key, 'base64').toString('hex')).toBe('0a6e79d1d1deaa8e48fdd542fdb5c3f6ce42c7cbe7ca157f826eca3b952ebe21')
        expect(Buffer.from(blsKey.blinding_factor, 'base64').toString('hex')).toBe('636b9b1314a2877ee6236ffb4d9d57f8a88ac6ee1ce5650e057b0ae87d13703e')
      })

      it('where "seed" is NOT provided', async () => {
        const blsKey = wrapFFI(bbs.bls_generate_blinded_g2_key, { })

        expect(Buffer.from(blsKey.public_key, 'base64').length).toBe(96)
        expect(Buffer.from(blsKey.secret_key, 'base64').length).toBe(32)
        expect(Buffer.from(blsKey.blinding_factor, 'base64').length).toBe(32)
      })

    })

    describe('bls_secret_key_to_bbs_key()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
      })

      describe('should convert BLS secret key to BBS public key', () => {

        it('where "message_count" = 1', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: 1, secret_key: blsKey.secret_key })

          expect(Buffer.from(bbsPublicKey.public_key, 'base64').toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfa8a76e5cbe5214abfd637099582772dc25c4a6871edd33559f92db6de6bd1671bca4a4883d930c31423727a342c85636100000001b9541258be3921882ba181b8fe7eb08d8c6db3d47e21b04f6eae506ee9746826d4597e83c0b95b9fe7bc4495ec3efcbd')
        })

        it('where "message_count" = 3', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: 3, secret_key: blsKey.secret_key })

          expect(Buffer.from(bbsPublicKey.public_key, 'base64').toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfaac09fba8a049fb3a098e2483c45881960ca33ca450cf0f11e951d127ad9c50f101531c7c9a4d45a6e0c175e5c0f0da600000000393c8623f78f956458832ca9a06721e6c4e94eec4a2d196c6e4a1efa779d60dcb85f2e0cff66f63ae3b0220e0850c2e198e5609e93673e6a0e3878a6674acdea5d40b3459b0aa3eaf66b1de2668695234fb2ed4e2fd53f9a93a08dc222c4c13beb1eff39abb05eb978804603cfb23b46b8e2a91e0b9461f4603c69c02f0e946164f0a6a870a36feebf9211aa3560c0490')
        })

      })

    })

    describe('bls_public_key_to_bbs_key()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
      })

      describe('should convert BLS public key to BBS public key', () => {

        it('where "message_count" = 1', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_public_key_to_bbs_key, { message_count: 1, public_key: blsKey.public_key })

          expect(Buffer.from(bbsPublicKey.public_key, 'base64').toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfa8a76e5cbe5214abfd637099582772dc25c4a6871edd33559f92db6de6bd1671bca4a4883d930c31423727a342c85636100000001b9541258be3921882ba181b8fe7eb08d8c6db3d47e21b04f6eae506ee9746826d4597e83c0b95b9fe7bc4495ec3efcbd')
        })

        it('where "message_count" = 3', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_public_key_to_bbs_key, { message_count: 3, public_key: blsKey.public_key })

          expect(Buffer.from(bbsPublicKey.public_key, 'base64').toString('hex')).toBe('a50ae8d6eaa9bd43ccdf5b2bfa31df7f3efe2892290379057a7e12a0a013511460a3ba64e7cd9a6aa2314a29d6b201c307d8fd770c5845b0b7ab6666202476395317dc51d6f4b655d9001ab936059fb804adad4149e2a174a0e9cc1c4f8c8dfaac09fba8a049fb3a098e2483c45881960ca33ca450cf0f11e951d127ad9c50f101531c7c9a4d45a6e0c175e5c0f0da600000000393c8623f78f956458832ca9a06721e6c4e94eec4a2d196c6e4a1efa779d60dcb85f2e0cff66f63ae3b0220e0850c2e198e5609e93673e6a0e3878a6674acdea5d40b3459b0aa3eaf66b1de2668695234fb2ed4e2fd53f9a93a08dc222c4c13beb1eff39abb05eb978804603cfb23b46b8e2a91e0b9461f4603c69c02f0e946164f0a6a870a36feebf9211aa3560c0490')
        })

      })

    })

    describe('bbs_sign()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
      })

      describe('should generate signature of the correct length', () => {

        it('where number of messages = 1', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: 1, secret_key: blsKey.secret_key })
          const { signature } = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages: [ messages[0] ] })

          expect(Buffer.from(signature, 'base64').length).toBe(112)
        })

        it('where number of messages = 3', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
          const { signature } = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })

          expect(Buffer.from(signature, 'base64').length).toBe(112)
        })

      })

      it('should error where "message_count" below number of messages', () => {
        const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: 1, secret_key: blsKey.secret_key })

        const { error } = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })

        expect(error.name).toBe('RustError')
        expect(error.message).toBe('Unable to sign messages')
      })

    })

    describe('bbs_blind_signature_commitment()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
        bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
      })

      it('should generate blind commitment context correctly', () => {

        const { commitment, challenge_hash, blinding_factor, proof_of_hidden_messages } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

        expect(Buffer.from(commitment, 'base64').length).toBe(48)
        expect(Buffer.from(challenge_hash, 'base64').length).toBe(32)
        expect(Buffer.from(blinding_factor, 'base64').length).toBe(32)
        expect(Buffer.from(proof_of_hidden_messages, 'base64').length).toBe(148)
      })

    })

    describe('bbs_verify_blind_signature_proof()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
        bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
      })

      describe('should verify blind commitment context correctly', () => {

        it('with 1 hidden message in commitment context', () => {
          const { commitment, challenge_hash, proof_of_hidden_messages } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[1] ], blinded: [ 1 ], nonce })
          const { verified } = wrapFFI(bbs.bbs_verify_blind_signature_proof, { commitment, challenge_hash, proof_of_hidden_messages, public_key: bbsPublicKey.public_key, blinded: [ 1 ], nonce })

          expect(verified).toBe(true)
        })

        it('with 3 hidden messages in commitment context', () => {
          const { commitment, challenge_hash, proof_of_hidden_messages } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages, blinded: [ 0, 1, 2 ], nonce })
          const { verified } = wrapFFI(bbs.bbs_verify_blind_signature_proof, { commitment, challenge_hash, proof_of_hidden_messages, public_key: bbsPublicKey.public_key, blinded: [ 0, 1, 2 ], nonce })

          expect(verified).toBe(true)
        })

      })

      describe('should NOT verify blind commitment context', () => {

        it('where incorrect blinded message indexes supplied', () => {
          const { commitment, challenge_hash, proof_of_hidden_messages } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
          const { verified } = wrapFFI(bbs.bbs_verify_blind_signature_proof, { commitment, challenge_hash, proof_of_hidden_messages, public_key: bbsPublicKey.public_key, blinded: [ 0 ], nonce })

          expect(verified).toBe(false)
        })

        it('where incorrect nonce supplied', () => {
          const randomNonce = Uint8Array.from(crypto.randomBytes(32)).buffer

          const { commitment, challenge_hash, proof_of_hidden_messages } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
          const { verified } = wrapFFI(bbs.bbs_verify_blind_signature_proof, { commitment, challenge_hash, proof_of_hidden_messages, public_key: bbsPublicKey.public_key, blinded: [ 0 ], nonce: randomNonce })

          expect(verified).toBe(false)
        })

      })

    })

    describe('bbs_blind_sign()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
        bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
      })

      it('should generate blind signature of the correct length', () => {
        const { commitment } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
        const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })

        expect(Buffer.from(blind_signature, 'base64').length).toBe(112)
      })

    })

    describe('bbs_get_unblinded_signature()', () => {
      let blsKey, bbsPublicKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
        bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
      })

      it('should retrieve unblinded signature of the correct length', () => {
        const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })
        const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })

        expect(Buffer.from(blind_signature, 'base64').length).toBe(112)

        const { signature } = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })

        expect(Buffer.from(signature, 'base64').length).toBe(112)
      })

    })

    describe('bbs_verify()', () => {
      let blsKey

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
      })

      describe('should verify a standard signature', () => {

        it('where 1 message is signed', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: 1, secret_key: blsKey.secret_key })
          const { signature } = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages: [ messages[0] ] })

          const { verified } = wrapFFI(bbs.bbs_verify, { signature, public_key: bbsPublicKey.public_key, messages: [ messages[0] ] })

          expect(verified).toBe(true)
        })

        it('where 3 messages are signed', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
          const { signature } = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })

          const { verified } = wrapFFI(bbs.bbs_verify, { signature, public_key: bbsPublicKey.public_key, messages })

          expect(verified).toBe(true)
        })

      })

      describe('should verify blinded signature', () => {

        it('where 1 blinded message is signed', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: 1, secret_key: blsKey.secret_key })

          // single blinded message commitment
          const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0] ], blinded: [ 0 ], nonce })

          // blind sign with no unblinded messages
          const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ ], known: [ ] })
          const { signature } = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })

          // verify unblinded signature
          const { verified } = wrapFFI(bbs.bbs_verify, { signature, public_key: bbsPublicKey.public_key, messages: [ messages[0] ] })

          expect(verified).toBe(true)
        })

        it('where 2 blinded messages, and 1 unblinded are signed', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })

          // 2x blinded message commitment
          const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })
          const { signature } = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })

          // verify unblinded signature
          const { verified } = wrapFFI(bbs.bbs_verify, { signature, public_key: bbsPublicKey.public_key, messages })

          expect(verified).toBe(true)
        })

      })

      describe('should fail to verify a signature', () => {

        it('where messages are incorrect', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
          const { signature } = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })

          const { verified } = wrapFFI(bbs.bbs_verify, { signature, public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[0], messages[0] ] })

          expect(verified).toBe(false)
        })

        it('where public key is incorrect', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })

          const { signature } = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })

          const randomBlsKey = wrapFFI(bbs.bls_generate_g2_key, { seed: 'JhRwDXovpCVDEhrG/SAsjEaUGbsty2Lu/AdywOHnNPrz7r4phYXvLNmvAHSdosgqbZA=' })
          const randomBbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: randomBlsKey.secret_key })

          const { verified } = wrapFFI(bbs.bbs_verify, { signature, public_key: randomBbsPublicKey.public_key, messages })

          expect(verified).toBe(false)
        })

        it('where messages are incorrect for unblinded signature', () => {
          const bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })

          // 2x blinded message commitment
          const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })
          const { signature } = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })

          // verify unblinded signature
          const { verified } = wrapFFI(bbs.bbs_verify, { signature, public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[0], messages[0] ] })

          expect(verified).toBe(false)
        })

      })

    })

    describe('bbs_create_proof()', () => {
      let blsKey, bbsPublicKey, standardSignature

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
        bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
        standardSignature = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })
      })

      describe('should generate proof of the correct length', () => {

        it('where 1 message revealed', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: standardSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 1 ], nonce })

          expect(Buffer.from(proof, 'base64').length).toBe(447)
        })

        it('where 3 messages revealed', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: standardSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          expect(Buffer.from(proof, 'base64').length).toBe(383)
        })

        it('where signature contains blinded messages', () => {
          // 2x blinded message commitment
          const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })
          const { signature } = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })

          // generate proof with blinded & unblinded messages
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          expect(Buffer.from(proof, 'base64').length).toBe(383)
        })

      })

    })

    describe('bbs_verify_proof()', () => {
      let blsKey, bbsPublicKey, standardSignature

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
        bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
        standardSignature = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })
      })

      describe('should verify a proof', () => {

        it('where 1 message revealed', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: standardSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 1 ], nonce })

          const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: bbsPublicKey.public_key, messages: [ messages[1] ], nonce })

          expect(verified).toBe(true)
        })

        it('where 3 messages revealed', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: standardSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: bbsPublicKey.public_key, messages, nonce })

          expect(verified).toBe(true)
        })

        describe('with blinded messages', () => {
          let unblindedSignature

          beforeAll(() => {
            // 2x blinded message commitment
            const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

            // blind sign with 1 unblinded message
            const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })
            unblindedSignature = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })
          })

          it('where 1 unblinded message revealed', () => {
            // derive proof for 1 (unblinded) message
            const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: unblindedSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 2 ], nonce })

            // verify proof with unblinded message
            const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: bbsPublicKey.public_key, messages: [ messages[2] ], nonce })

            expect(verified).toBe(true)
          })

          it('where 1 blinded message revealed', () => {
            // derive proof for 1 (blinded) message
            const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: unblindedSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0 ], nonce })

            // verify proof with unblinded message
            const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: bbsPublicKey.public_key, messages: [ messages[0] ], nonce })

            expect(verified).toBe(true)
          })

          it('where all messages revealed (2x blinded & 1x unblinded)', () => {
            // derive proof for all messages
            const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: unblindedSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

            // verify proof with all messages
            const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: bbsPublicKey.public_key, messages, nonce })

            expect(verified).toBe(true)
          })

        })

      })

      describe('should fail to verify a proof', () => {

        it('where messages are incorrect', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: standardSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[0], messages[0] ], nonce })

          expect(verified).toBe(false)
        })

        it('where messages public key is incorrect', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: standardSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          const randomBlsKey = wrapFFI(bbs.bls_generate_g2_key, { seed: 'JhRwDXovpCVDEhrG/SAsjEaUGbsty2Lu/AdywOHnNPrz7r4phYXvLNmvAHSdosgqbZA=' })
          const randomBbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: randomBlsKey.secret_key })

          const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: randomBbsPublicKey.public_key, messages, nonce })

          expect(verified).toBe(false)
        })

        it('with blinded messages, where messages are incorrect', () => {
          // 2x blinded message commitment
          const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })
          const { signature } = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })

          // derive proof for all messages
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          // attempt to verify with incorrect messages
          const { verified } = wrapFFI(bbs.bbs_verify_proof, { proof, public_key: bbsPublicKey.public_key, messages: [ messages[2], messages[2], messages[2] ], nonce })

          expect(verified).toBe(false)
        })

      })

    })

    describe('bls_verify_proof()', () => {
      let blsKey, bbsPublicKey, signature

      beforeAll(() => {
        blsKey = wrapFFI(bbs.bls_generate_g2_key, { seed })
        bbsPublicKey = wrapFFI(bbs.bls_secret_key_to_bbs_key, { message_count: messages.length, secret_key: blsKey.secret_key })
        signature = wrapFFI(bbs.bbs_sign, { secret_key: blsKey.secret_key, public_key: bbsPublicKey.public_key, messages })
      })

      describe('should verify a proof', () => {

        it('where 1 message revealed', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: signature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 1 ], nonce })
          const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: blsKey.public_key, messages: [ messages[1] ], nonce })

          expect(verified).toBe(true)
        })

        it('where 3 messages revealed', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: signature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: blsKey.public_key, messages, nonce })

          expect(verified).toBe(true)
        })

        describe('with blinded messages', () => {
          let unblindedSignature

          beforeAll(() => {
            // 2x blinded message commitment
            const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

            // blind sign with 1 unblinded message
            const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })
            unblindedSignature = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })
          })

          it('where 1 unblinded message revealed', () => {
            // derive proof for 1 (unblinded) message
            const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: unblindedSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 2 ], nonce })

            // verify proof with unblinded message
            const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: blsKey.public_key, messages: [ messages[2] ], nonce })

            expect(verified).toBe(true)
          })

          it('where 1 blinded message revealed', () => {
            // derive proof for 1 (blinded) message
            const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: unblindedSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0 ], nonce })

            // verify proof with unblinded message
            const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: blsKey.public_key, messages: [ messages[0] ], nonce })

            expect(verified).toBe(true)
          })

          it('where all messages revealed (2x blinded & 1x unblinded)', () => {
            // derive proof for all messages
            const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: unblindedSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

            // verify proof with all messages
            const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: blsKey.public_key, messages, nonce })

            expect(verified).toBe(true)
          })

        })

      })

      describe('should fail to verify a proof', () => {

        it('where messages are incorrect', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: signature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: blsKey.public_key, messages: [ messages[0], messages[0], messages[0] ], nonce })

          expect(verified).toBe(false)
        })

        it('where messages public key is incorrect', () => {
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: signature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          const randomBlsKey = wrapFFI(bbs.bls_generate_g2_key, { seed: 'JhRwDXovpCVDEhrG/SAsjEaUGbsty2Lu/AdywOHnNPrz7r4phYXvLNmvAHSdosgqbZA=' })

          const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: randomBlsKey.public_key, messages, nonce })

          expect(verified).toBe(false)
        })

        it('with blinded messages, where messages are incorrect', () => {
          // 2x blinded message commitment
          const { commitment, blinding_factor } = wrapFFI(bbs.bbs_blind_signature_commitment, { public_key: bbsPublicKey.public_key, messages: [ messages[0], messages[1] ], blinded: [ 0, 1 ], nonce })

          // blind sign with 1 unblinded message
          const { blind_signature } = wrapFFI(bbs.bbs_blind_sign, { commitment, public_key: bbsPublicKey.public_key, secret_key: blsKey.secret_key, messages: [ messages[2] ], known: [ 2 ] })
          const unblindedSignature = wrapFFI(bbs.bbs_get_unblinded_signature, { blind_signature, blinding_factor })

          // derive proof for all messages
          const { proof } = wrapFFI(bbs.bbs_create_proof, { signature: unblindedSignature.signature, public_key: bbsPublicKey.public_key, messages, revealed: [ 0, 1, 2 ], nonce })

          // attempt to verify with incorrect messages
          const { verified } = wrapFFI(bbs.bls_verify_proof, { proof, public_key: blsKey.public_key, messages: [ messages[2], messages[2], messages[2] ], nonce })

          expect(verified).toBe(false)
        })

      })

    })

  })

})

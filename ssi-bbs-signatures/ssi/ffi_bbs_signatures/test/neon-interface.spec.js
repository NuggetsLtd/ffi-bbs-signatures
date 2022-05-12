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
    ])
  })

  it('should export foreign function interface functions', () => {
    expect(typeof bbs.bls_generate_blinded_g1_key).toBe('function')
    expect(typeof bbs.bls_generate_blinded_g2_key).toBe('function')
    expect(typeof bbs.bls_generate_g1_key).toBe('function')
    expect(typeof bbs.bls_generate_g2_key).toBe('function')
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
  })

})

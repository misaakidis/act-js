import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { describe, expect, it } from 'vitest'
import fixtures from './fixtures/cipher.json'
import { decrypt, encrypt } from '../src/crypto/cipher.js'

describe('cipher', () => {
  it('roundtrips a 32-byte reference', () => {
    const key = hexToBytes('8abf1502f557f15026716030fb6384792583daf39608a3cd02ff2f47e9bc6e49')
    const plaintext = hexToBytes('39a5ea87b141fe44aa609c3327ecd896c0e2122897f5f4bbacf74db1033c5559')

    const ct = encrypt(plaintext, key, 0)
    const pt = decrypt(ct, key, 0)

    expect(bytesToHex(pt)).toBe(bytesToHex(plaintext))
    expect(ct).not.toEqual(plaintext)
  })

  it('is deterministic', () => {
    const key = hexToBytes('8abf1502f557f15026716030fb6384792583daf39608a3cd02ff2f47e9bc6e49')
    const pt = new Uint8Array(32)
    expect(encrypt(pt, key, 0)).toEqual(encrypt(pt, key, 0))
  })

  it('differs with different initCtr', () => {
    const key = hexToBytes('8abf1502f557f15026716030fb6384792583daf39608a3cd02ff2f47e9bc6e49')
    const pt = new Uint8Array(32)
    expect(encrypt(pt, key, 0)).not.toEqual(encrypt(pt, key, 1))
  })
})

describe('cipher - fixtures', () => {
  if (fixtures.length === 0) {
    it('has no fixtures yet', () => {
      expect(fixtures).toEqual([])
    })
  } else {
    for (const fixture of fixtures) {
      it(fixture.name, () => {
        const ct = encrypt(hexToBytes(fixture.plaintext), hexToBytes(fixture.key), fixture.initCtr)
        expect(bytesToHex(ct)).toBe(fixture.ciphertext)
      })
    }
  }
})

import { Bee } from '@ethersphere/bee-js'
import * as secp from '@noble/secp256k1'
import { describe, expect, it } from 'vitest'
import { BeeClientWrapper } from '../src/bee-client-wrapper.js'

const BEE_URL = process.env.BEE_URL || 'http://localhost:1633'
const STAMP = process.env.BEE_STAMP

describe.skipIf(!STAMP)('BeeClientWrapper integration', () => {
  it('supports create/get/patch parity and timestamped ACT reads', async () => {
    const bee = new Bee(BEE_URL)

    const creatorPriv = secp.utils.randomPrivateKey()
    const creatorPub = secp.getPublicKey(creatorPriv, false)
    const granteePriv = secp.utils.randomPrivateKey()
    const granteePub = secp.getPublicKey(granteePriv, false)

    const creator = new BeeClientWrapper({ bee, identityPrivKey: creatorPriv })
    const grantee = new BeeClientWrapper({ bee, identityPrivKey: granteePriv })

    const created = await creator.createGrantees(STAMP!, [creatorPub, granteePub])
    expect(created.status).toBe(201)
    expect(created.statusText).toBe('Created')
    expect(created.ref).toBeInstanceOf(Uint8Array)
    expect(created.historyref).toBeInstanceOf(Uint8Array)

    const listedBefore = await creator.getGrantees(created.ref)
    expect(listedBefore.status).toBe(200)
    expect(containsPubkey(listedBefore.grantees, creatorPub)).toBe(true)
    expect(containsPubkey(listedBefore.grantees, granteePub)).toBe(true)

    const oldPayload = new TextEncoder().encode(`before-revoke:${Date.now()}`)
    const oldUploaded = await creator.uploadData(STAMP!, oldPayload, {
      act: true,
      actHistoryAddress: created.historyref,
    })
    const tsBeforeRevoke = Math.floor(Date.now() / 1000)
    expect(oldUploaded.historyAddress).toEqual(created.historyref)

    // Ensure the next history patch lands in a distinct second.
    await new Promise(resolve => setTimeout(resolve, 1100))

    const patched = await creator.patchGrantees(STAMP!, created.ref, created.historyref, {
      revoke: [granteePub],
    })
    expect(patched.status).toBe(200)
    expect(patched.statusText).toBe('OK')

    const listedAfter = await creator.getGrantees(patched.ref)
    expect(containsPubkey(listedAfter.grantees, creatorPub)).toBe(true)
    expect(containsPubkey(listedAfter.grantees, granteePub)).toBe(false)

    const oldReadAtTimestamp = await grantee.downloadData(oldUploaded.reference.toUint8Array(), {
      actPublisher: creatorPub,
      actHistoryAddress: patched.historyref,
      actTimestamp: tsBeforeRevoke,
    })
    expect(oldReadAtTimestamp.toUint8Array()).toEqual(oldPayload)

    await expect(
      grantee.downloadData(oldUploaded.reference.toUint8Array(), {
        actPublisher: creatorPub,
        actHistoryAddress: patched.historyref,
      }),
    ).rejects.toThrow(/NOT_FOUND/)
  })
})

function containsPubkey(list: Uint8Array[], candidate: Uint8Array): boolean {
  return list.some(pk => pk.length === candidate.length && pk.every((b, i) => b === candidate[i]))
}

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

  it('rejects patch when reference does not match provided history', async () => {
    const bee = new Bee(BEE_URL)
    const creatorPriv = secp.utils.randomPrivateKey()
    const creatorPub = secp.getPublicKey(creatorPriv, false)
    const granteePub = secp.getPublicKey(secp.utils.randomPrivateKey(), false)
    const wrapper = new BeeClientWrapper({ bee, identityPrivKey: creatorPriv })

    const created = await wrapper.createGrantees(STAMP!, [creatorPub, granteePub])
    const wrongRef = new Uint8Array(32).fill(9)

    await expect(
      wrapper.patchGrantees(STAMP!, wrongRef, created.historyref, {
        revoke: [granteePub],
      }),
    ).rejects.toThrow(/reference does not match history state|reference\/history mismatch/)
  })

  it('requires explicit actHistoryAddress in strict upload mode', async () => {
    const bee = new Bee(BEE_URL)
    const priv = secp.utils.randomPrivateKey()
    const wrapper = new BeeClientWrapper({ bee, identityPrivKey: priv, actUploadMode: 'strict' })
    const payload = new TextEncoder().encode('strict-mode')

    await expect(wrapper.uploadData(STAMP!, payload, { act: true })).rejects.toThrow(/actHistoryAddress/)
  })

  it('supports compatibility upload mode without explicit history', async () => {
    const bee = new Bee(BEE_URL)
    const priv = secp.utils.randomPrivateKey()
    const wrapper = new BeeClientWrapper({ bee, identityPrivKey: priv, actUploadMode: 'compat' })
    const payload = new TextEncoder().encode('compat-mode')

    const uploaded = await wrapper.uploadData(STAMP!, payload, { act: true })
    expect(uploaded.historyAddress).not.toBeNull()
  })
})

describe('BeeClientWrapper option pass-through', () => {
  it('forwards requestOptions to underlying Bee calls', async () => {
    const calls: Array<{ method: string; requestOptions: unknown }> = []
    const bee = {
      async uploadData(
        _stamp: string | Uint8Array,
        _data: Uint8Array,
        _options?: Record<string, unknown>,
        requestOptions?: unknown,
      ) {
        calls.push({ method: 'uploadData', requestOptions })
        return { reference: { toUint8Array: () => new Uint8Array(32).fill(1) } }
      },
      async downloadData(_ref: Uint8Array, _options?: Record<string, unknown>, requestOptions?: unknown) {
        calls.push({ method: 'downloadData', requestOptions })
        return { toUint8Array: () => new Uint8Array([1, 2, 3]) }
      },
    }

    const wrapper = new BeeClientWrapper({
      bee: bee as unknown as Bee,
      identityPrivKey: secp.utils.randomPrivateKey(),
    })

    await wrapper.uploadData('a'.repeat(64), new Uint8Array([1]), { pin: true, requestOptions: { timeoutMs: 1 } })
    await wrapper.downloadData(new Uint8Array(32).fill(1), { requestOptions: { timeoutMs: 2 } })

    expect(calls).toEqual([
      { method: 'uploadData', requestOptions: { timeoutMs: 1 } },
      { method: 'downloadData', requestOptions: { timeoutMs: 2 } },
    ])
  })
})

function containsPubkey(list: Uint8Array[], candidate: Uint8Array): boolean {
  return list.some(pk => pk.length === candidate.length && pk.every((b, i) => b === candidate[i]))
}

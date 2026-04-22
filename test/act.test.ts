import * as secp from '@noble/secp256k1'
import { Bee } from '@ethersphere/bee-js'
import { describe, expect, it } from 'vitest'
import { ActClient } from '../src/act.js'

const BEE_URL = process.env.BEE_URL || 'http://localhost:1633'
const STAMP = process.env.BEE_STAMP

describe.skipIf(!STAMP)('ActClient integration', () => {
  it('create -> encryptRef -> decryptRef -> revoke -> denied', async () => {
    const bee = new Bee(BEE_URL)
    const act = new ActClient({ bee, stamp: STAMP! })

    const creatorPriv = secp.utils.randomSecretKey()
    const creatorPub = secp.getPublicKey(creatorPriv, false)
    const granteePriv = secp.utils.randomSecretKey()
    const granteePub = secp.getPublicKey(granteePriv, false)

    const { historyRef } = await act.create({
      publisher: creatorPriv,
      grantees: [creatorPub, granteePub],
    })

    const manifestRef = new Uint8Array(32).fill(0xaa)
    const encRef = await act.encryptRef(manifestRef, { publisher: creatorPriv, historyRef })
    const decRef = await act.decryptRef(encRef, { granteePriv, publisherPub: creatorPub, historyRef })
    expect(decRef).toEqual(manifestRef)

    const { historyRef: newHistoryRef } = await act.revokeGrantee(granteePub, {
      publisher: creatorPriv,
      historyRef,
    })

    await expect(
      act.decryptRef(encRef, { granteePriv, publisherPub: creatorPub, historyRef: newHistoryRef }),
    ).rejects.toThrow(/NOT_FOUND/)
  })
})

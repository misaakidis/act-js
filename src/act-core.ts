import { encrypt } from './crypto/cipher.js'
import { deriveSessionKeys } from './crypto/ecdh.js'
import { containsPubkey, removePubkey } from './grantee/grantee-list.js'
import { createEmptyManifest, manifestPut, type SimpleManifest } from './kvs/kvs.js'
import type { PrivateKeyBytes, PublicKeyBytes } from './types.js'

export interface GranteePatch {
  add?: PublicKeyBytes[]
  revoke?: PublicKeyBytes[]
}

export interface GranteePatchResult {
  nextGrantees: PublicKeyBytes[]
  revoking: boolean
}

export function ensurePublisherIncluded(
  publisherPub: PublicKeyBytes,
  grantees: PublicKeyBytes[],
): PublicKeyBytes[] {
  return containsPubkey(grantees, publisherPub) ? grantees : [publisherPub, ...grantees]
}

export function applyGranteePatch(current: PublicKeyBytes[], patch: GranteePatch): GranteePatchResult {
  const toAdd = patch.add ?? []
  const toRevoke = patch.revoke ?? []
  let next = current

  for (const pub of toAdd) {
    if (!containsPubkey(next, pub)) {
      next = [...next, pub]
    }
  }

  for (const pub of toRevoke) {
    next = removePubkey(next, pub)
  }

  return { nextGrantees: next, revoking: toRevoke.length > 0 }
}

export function buildAccessManifest(
  publisher: PrivateKeyBytes,
  grantees: PublicKeyBytes[],
  accessKey: Uint8Array,
): SimpleManifest {
  const kvs = createEmptyManifest()
  for (const granteePub of grantees) {
    const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(publisher, granteePub)
    manifestPut(kvs, lookupKey, encrypt(accessKey, accessKeyDecryptionKey, 0))
  }
  return kvs
}

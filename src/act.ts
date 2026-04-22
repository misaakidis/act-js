import type { BatchId, Bee } from '@ethersphere/bee-js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { decrypt, encrypt } from './crypto/cipher.js'
import { deriveKvsKeys, deriveSessionKeys, ecdhX, publicKeyFromPrivate } from './crypto/ecdh.js'
import { containsPubkey, deserializeGranteeList, removePubkey, serializeGranteeList } from './grantee/grantee-list.js'
import {
  addHistoryEntry,
  collectHistoryEntries,
  createEmptyHistory,
  downloadHistory,
  lookupHistory,
  uploadHistory,
} from './history/history.js'
import { createEmptyManifest, downloadKvs, manifestGet, manifestPut, uploadKvs } from './kvs/kvs.js'

function randomAccessKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

export interface ActClientOptions {
  bee: Bee
  stamp: BatchId | string
}

export interface CreateArgs {
  publisher: Uint8Array
  grantees: Uint8Array[]
}

export interface ActCreateResult {
  historyRef: Uint8Array
  accessKey: Uint8Array
}

export interface EncryptArgs {
  publisher: Uint8Array
  historyRef: Uint8Array
}

export interface DecryptArgs {
  granteePriv: Uint8Array
  publisherPub: Uint8Array
  historyRef: Uint8Array
}

export class ActClient {
  constructor(private opts: ActClientOptions) {}

  async create(args: CreateArgs): Promise<ActCreateResult> {
    const accessKey = randomAccessKey()
    const publisherPub = publicKeyFromPrivate(args.publisher)

    // Bee always includes publisher as a grantee implicitly; mirror that behaviour.
    const allGrantees = containsPubkey(args.grantees, publisherPub)
      ? args.grantees
      : [publisherPub, ...args.grantees]

    const kvs = createEmptyManifest()
    for (const granteePub of allGrantees) {
      const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(args.publisher, granteePub)
      manifestPut(kvs, lookupKey, encrypt(accessKey, accessKeyDecryptionKey, 0))
    }

    const kvsRef = await uploadKvs(this.opts.bee, this.opts.stamp, kvs)
    const encryptedGlRef = await this.saveGranteeList(args.publisher, allGrantees)

    const history = createEmptyHistory()
    await this.appendHistoryEntry(history, {
      kvsRef,
      metadata: { encryptedglref: bytesToHex(encryptedGlRef) },
    })

    const historyRef = await uploadHistory(this.opts.bee, this.opts.stamp, history)
    return { historyRef, accessKey }
  }

  async encryptRef(ref: Uint8Array, args: EncryptArgs): Promise<Uint8Array> {
    const accessKey = await this.getAccessKeyAsPublisher(args.publisher, args.historyRef)
    return encrypt(ref, accessKey, 0)
  }

  async reencryptRef(newRef: Uint8Array, args: DecryptArgs): Promise<Uint8Array> {
    const accessKey = await this.getAccessKeyAsGrantee(args.granteePriv, args.publisherPub, args.historyRef)
    return encrypt(newRef, accessKey, 0)
  }

  async decryptRef(encRef: Uint8Array, args: DecryptArgs): Promise<Uint8Array> {
    const accessKey = await this.getAccessKeyAsGrantee(args.granteePriv, args.publisherPub, args.historyRef)
    return decrypt(encRef, accessKey, 0)
  }

  async addGrantee(
    granteePub: Uint8Array,
    args: { publisher: Uint8Array; historyRef: Uint8Array },
  ): Promise<{ historyRef: Uint8Array }> {
    const accessKey = await this.getAccessKeyAsPublisher(args.publisher, args.historyRef)
    const currentGrantees = await this.listGrantees(args)
    if (containsPubkey(currentGrantees, granteePub)) {
      return { historyRef: args.historyRef }
    }

    const nextGrantees = [...currentGrantees, granteePub]
    const kvs = createEmptyManifest()
    for (const pk of nextGrantees) {
      const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(args.publisher, pk)
      manifestPut(kvs, lookupKey, encrypt(accessKey, accessKeyDecryptionKey, 0))
    }

    const kvsRef = await uploadKvs(this.opts.bee, this.opts.stamp, kvs)
    const encryptedGlRef = await this.saveGranteeList(args.publisher, nextGrantees)

    const history = await downloadHistory(this.opts.bee, args.historyRef)
    await this.appendHistoryEntry(history, {
      kvsRef,
      metadata: { encryptedglref: bytesToHex(encryptedGlRef) },
    })

    return { historyRef: await uploadHistory(this.opts.bee, this.opts.stamp, history) }
  }

  async revokeGrantee(
    granteePub: Uint8Array,
    args: { publisher: Uint8Array; historyRef: Uint8Array },
  ): Promise<{ historyRef: Uint8Array }> {
    const currentGrantees = await this.listGrantees(args)
    const remaining = removePubkey(currentGrantees, granteePub)
    if (remaining.length === currentGrantees.length) {
      return { historyRef: args.historyRef }
    }

    const newAccessKey = randomAccessKey()
    const kvs = createEmptyManifest()
    for (const pk of remaining) {
      const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(args.publisher, pk)
      manifestPut(kvs, lookupKey, encrypt(newAccessKey, accessKeyDecryptionKey, 0))
    }

    const kvsRef = await uploadKvs(this.opts.bee, this.opts.stamp, kvs)
    const encryptedGlRef = await this.saveGranteeList(args.publisher, remaining)

    const history = await downloadHistory(this.opts.bee, args.historyRef)
    await this.appendHistoryEntry(history, {
      kvsRef,
      metadata: { encryptedglref: bytesToHex(encryptedGlRef) },
    })

    return { historyRef: await uploadHistory(this.opts.bee, this.opts.stamp, history) }
  }

  async listGrantees(args: { publisher: Uint8Array; historyRef: Uint8Array }): Promise<Uint8Array[]> {
    const history = await downloadHistory(this.opts.bee, args.historyRef)
    const entry = lookupHistory(history, Math.floor(Date.now() / 1000))
    if (!entry) return []

    const encGlRefHex = entry.metadata.encryptedglref
    if (!encGlRefHex) return []

    const publisherPub = publicKeyFromPrivate(args.publisher)
    const [, publisherAKDec] = deriveKvsKeys(ecdhX(args.publisher, publisherPub))

    // The stored value is the encrypted 32-byte Swarm reference to the plaintext list.
    const granteeRef = decrypt(hexToBytes(encGlRefHex), publisherAKDec, 0)
    const plaintextBytes = await this.opts.bee.downloadData(granteeRef)
    return deserializeGranteeList(plaintextBytes.toUint8Array())
  }

  /**
   * Upload the plaintext grantee list to Swarm, then encrypt its 32-byte reference
   * with the publisher's self-ECDH key. This matches Bee's encryptRefForPublisher wire format.
   */
  private async saveGranteeList(publisher: Uint8Array, grantees: Uint8Array[]): Promise<Uint8Array> {
    const plaintext = serializeGranteeList(grantees)
    const uploaded = await this.opts.bee.uploadData(this.opts.stamp, plaintext)
    const granteeRef = uploaded.reference.toUint8Array()

    const publisherPub = publicKeyFromPrivate(publisher)
    const [, publisherAKDec] = deriveKvsKeys(ecdhX(publisher, publisherPub))
    return encrypt(granteeRef, publisherAKDec, 0)
  }

  private async getAccessKeyAsPublisher(publisher: Uint8Array, historyRef: Uint8Array): Promise<Uint8Array> {
    const publisherPub = publicKeyFromPrivate(publisher)
    return this.getAccessKeyAsGrantee(publisher, publisherPub, historyRef)
  }

  private async getAccessKeyAsGrantee(
    granteePriv: Uint8Array,
    publisherPub: Uint8Array,
    historyRef: Uint8Array,
  ): Promise<Uint8Array> {
    const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(granteePriv, publisherPub)
    const history = await downloadHistory(this.opts.bee, historyRef)
    const entry = lookupHistory(history, Math.floor(Date.now() / 1000))
    if (!entry) throw new Error('ACT: no history entries')

    const kvs = await downloadKvs(this.opts.bee, entry.kvsRef)
    const encAccessKey = manifestGet(kvs, lookupKey)
    if (!encAccessKey) {
      const err = new Error('NOT_FOUND: grantee not present in KVS') as Error & { code?: string }
      err.code = 'NOT_FOUND'
      throw err
    }

    return decrypt(encAccessKey, accessKeyDecryptionKey, 0)
  }

  /**
   * Add a history entry with the current second as timestamp.
   * If that second is already occupied (e.g. two rapid calls), wait 1 s and retry
   * rather than writing a future timestamp that would confuse history lookups.
   */
  private async appendHistoryEntry(
    history: Awaited<ReturnType<typeof downloadHistory>>,
    entry: { kvsRef: Uint8Array; metadata: Record<string, string> },
  ): Promise<void> {
    const entries = collectHistoryEntries(history)
    const usedTimestamps = new Set(entries.map(e => e.timestamp))

    for (let attempt = 0; attempt < 10; attempt++) {
      const ts = Math.floor(Date.now() / 1000)
      if (!usedTimestamps.has(ts)) {
        addHistoryEntry(history, { timestamp: ts, kvsRef: entry.kvsRef, metadata: entry.metadata })
        return
      }
      await new Promise(resolve => setTimeout(resolve, 1100))
    }

    throw new Error('ACT: could not find a free timestamp slot after 10 attempts')
  }
}

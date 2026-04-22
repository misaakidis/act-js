import type { BatchId } from '@ethersphere/bee-js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { applyGranteePatch, buildAccessManifest, ensurePublisherIncluded } from './act-core.js'
import { decrypt, encrypt } from './crypto/cipher.js'
import { deriveKvsKeys, deriveSessionKeys, ecdhX, publicKeyFromPrivate } from './crypto/ecdh.js'
import { deserializeGranteeList, serializeGranteeList } from './grantee/grantee-list.js'
import { SwarmHistoryStore } from './history/history.js'
import { downloadKvs, manifestGet, uploadKvs } from './kvs/kvs.js'
import type {
  BeeDataClient,
  BlobStore,
  HistoryResult,
  HistorySnapshot,
  HistoryStore,
  PrivateKeyBytes,
  PublicKeyBytes,
  SwarmRef,
} from './types.js'

function randomAccessKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

export interface ActClientOptions {
  bee: BeeDataClient
  stamp: BatchId | string
  historyStore?: HistoryStore
  blobStore?: BlobStore
}

export interface CreateArgs {
  publisher: PrivateKeyBytes
  grantees: PublicKeyBytes[]
}

export interface ActCreateResult extends HistoryResult {}

export interface EncryptArgs {
  publisher: PrivateKeyBytes
  historyRef: SwarmRef
}

export interface DecryptArgs {
  granteePriv: PrivateKeyBytes
  publisherPub: PublicKeyBytes
  historyRef: SwarmRef
}

export class ActClient {
  private readonly historyStore: HistoryStore
  private readonly blobStore: BlobStore

  constructor(private opts: ActClientOptions) {
    this.historyStore = opts.historyStore ?? new SwarmHistoryStore(opts.bee)
    this.blobStore = opts.blobStore ?? new SwarmBlobStore(opts.bee, opts.stamp)
  }

  async create(args: CreateArgs): Promise<ActCreateResult> {
    const accessKey = randomAccessKey()
    const publisherPub = publicKeyFromPrivate(args.publisher)

    const allGrantees = ensurePublisherIncluded(publisherPub, args.grantees)
    const kvs = buildAccessManifest(args.publisher, allGrantees, accessKey)

    const kvsRef = await uploadKvs(this.opts.bee, this.opts.stamp, kvs)
    const encryptedGlRef = await this.saveGranteeList(args.publisher, allGrantees)

    const history = await this.historyStore.createEmpty()
    await this.appendHistoryEntry(history, {
      kvsRef,
      metadata: { encryptedglref: bytesToHex(encryptedGlRef) },
    })

    const historyRef = await this.historyStore.save(history, this.opts.stamp)
    return { historyRef }
  }

  async encryptRef(ref: SwarmRef, args: EncryptArgs): Promise<SwarmRef> {
    const accessKey = await this.getAccessKeyAsPublisher(args.publisher, args.historyRef)
    return encrypt(ref, accessKey, 0)
  }

  async reencryptRef(newRef: SwarmRef, args: DecryptArgs): Promise<SwarmRef> {
    const accessKey = await this.getAccessKeyAsGrantee(args.granteePriv, args.publisherPub, args.historyRef)
    return encrypt(newRef, accessKey, 0)
  }

  async decryptRef(encRef: SwarmRef, args: DecryptArgs): Promise<SwarmRef> {
    const accessKey = await this.getAccessKeyAsGrantee(args.granteePriv, args.publisherPub, args.historyRef)
    return decrypt(encRef, accessKey, 0)
  }

  /**
   * Add and/or revoke grantees in one atomic history step.
   * Mirrors bee-js's `patchGrantees(stamp, ref, historyRef, { add, revoke })`.
   *
   * Adding a grantee that is already present is a no-op.
   * Revoking generates a fresh access key so the removed party cannot decrypt
   * content encrypted after revocation.
   */
  async patchGrantees(
    grantees: { add?: PublicKeyBytes[]; revoke?: PublicKeyBytes[] },
    args: { publisher: PrivateKeyBytes; historyRef: SwarmRef },
  ): Promise<HistoryResult> {
    const toAdd = grantees.add ?? []
    const toRevoke = grantees.revoke ?? []
    if (toAdd.length === 0 && toRevoke.length === 0) {
      return { historyRef: args.historyRef }
    }

    const currentGrantees = await this.getGrantees(args)
    const { nextGrantees: next, revoking } = applyGranteePatch(currentGrantees, { add: toAdd, revoke: toRevoke })

    // Only rotate the access key when revoking; adds can reuse the existing one.
    const accessKey = revoking
      ? randomAccessKey()
      : await this.getAccessKeyAsPublisher(args.publisher, args.historyRef)

    const kvs = buildAccessManifest(args.publisher, next, accessKey)

    const kvsRef = await uploadKvs(this.opts.bee, this.opts.stamp, kvs)
    const encryptedGlRef = await this.saveGranteeList(args.publisher, next)

    const history = await this.historyStore.load(args.historyRef)
    await this.appendHistoryEntry(history, {
      kvsRef,
      metadata: { encryptedglref: bytesToHex(encryptedGlRef) },
    })

    return { historyRef: await this.historyStore.save(history, this.opts.stamp) }
  }

  /**
   * Retrieve the current grantee list.
   * Mirrors bee-js's `getGrantees(ref)`.
   */
  async getGrantees(args: { publisher: PrivateKeyBytes; historyRef: SwarmRef }): Promise<PublicKeyBytes[]> {
    const history = await this.historyStore.load(args.historyRef)
    const entry = this.historyStore.lookupAt(history, Math.floor(Date.now() / 1000))
    if (!entry) return []

    const encGlRefHex = entry.metadata.encryptedglref
    if (!encGlRefHex) return []

    const publisherPub = publicKeyFromPrivate(args.publisher)
    const [, publisherAKDec] = deriveKvsKeys(ecdhX(args.publisher, publisherPub))

    // The stored value is the encrypted 32-byte Swarm reference to the plaintext list.
    const granteeRef = decrypt(hexToBytes(encGlRefHex), publisherAKDec, 0)
    const plaintextBytes = await this.blobStore.get(granteeRef)
    return deserializeGranteeList(plaintextBytes)
  }

  /**
   * Upload the plaintext grantee list to Swarm, then encrypt its 32-byte reference
   * with the publisher's self-ECDH key. This matches Bee's encryptRefForPublisher wire format.
   */
  private async saveGranteeList(
    publisher: PrivateKeyBytes,
    grantees: PublicKeyBytes[],
  ): Promise<SwarmRef> {
    const plaintext = serializeGranteeList(grantees)
    const granteeRef = await this.blobStore.put(plaintext)

    const publisherPub = publicKeyFromPrivate(publisher)
    const [, publisherAKDec] = deriveKvsKeys(ecdhX(publisher, publisherPub))
    return encrypt(granteeRef, publisherAKDec, 0)
  }

  private async getAccessKeyAsPublisher(
    publisher: PrivateKeyBytes,
    historyRef: SwarmRef,
  ): Promise<Uint8Array> {
    const publisherPub = publicKeyFromPrivate(publisher)
    return this.getAccessKeyAsGrantee(publisher, publisherPub, historyRef)
  }

  private async getAccessKeyAsGrantee(
    granteePriv: PrivateKeyBytes,
    publisherPub: PublicKeyBytes,
    historyRef: SwarmRef,
  ): Promise<Uint8Array> {
    const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(granteePriv, publisherPub)
    const history = await this.historyStore.load(historyRef)
    const entry = this.historyStore.lookupAt(history, Math.floor(Date.now() / 1000))
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
    history: HistorySnapshot,
    entry: { kvsRef: SwarmRef; metadata: Record<string, string> },
  ): Promise<void> {
    const usedTimestamps = new Set(history.entries.map(e => e.timestamp))

    for (let attempt = 0; attempt < 10; attempt++) {
      const ts = Math.floor(Date.now() / 1000)
      if (!usedTimestamps.has(ts)) {
        await this.historyStore.append(history, { timestamp: ts, kvsRef: entry.kvsRef, metadata: entry.metadata })
        return
      }
      await new Promise(resolve => setTimeout(resolve, 1100))
    }

    throw new Error('ACT: could not find a free timestamp slot after 10 attempts')
  }
}

class SwarmBlobStore implements BlobStore {
  constructor(
    private readonly bee: BeeDataClient,
    private readonly stamp: BatchId | string,
  ) {}

  async put(data: Uint8Array): Promise<SwarmRef> {
    const uploaded = await this.bee.uploadData(this.stamp, data)
    return uploaded.reference.toUint8Array()
  }

  async get(reference: SwarmRef): Promise<Uint8Array> {
    const downloaded = await this.bee.downloadData(reference)
    return downloaded.toUint8Array()
  }
}

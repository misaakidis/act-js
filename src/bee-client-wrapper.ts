import type { BatchId } from '@ethersphere/bee-js'
import * as secp from '@noble/secp256k1'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { ActClient } from './act.js'
import { decrypt } from './crypto/cipher.js'
import { deriveKvsKeys, deriveSessionKeys, ecdhX, publicKeyFromPrivate } from './crypto/ecdh.js'
import { deserializeGranteeList } from './grantee/grantee-list.js'
import { SwarmHistoryStore } from './history/history.js'
import { downloadKvs, manifestGet } from './kvs/kvs.js'
import type {
  BeeClientWrapperDownloadOptions,
  BeeClientWrapperGetGranteesResult,
  BeeClientWrapperGranteesResult,
  BeeClientWrapperPatchGranteesArgs,
  BeeClientWrapperUploadOptions,
  BeeDataClient,
  ByteArrayLike,
  HistoryStore,
  PrivateKeyBytes,
  PublicKeyBytes,
  PublicKeyInput,
  ReferenceInput,
  SwarmRef,
  UploadDataResultLike,
} from './types.js'

type BeeClientWithOptions = BeeDataClient & {
  uploadData(
    stamp: BatchId | Uint8Array | string,
    data: Uint8Array,
    options?: Record<string, unknown>,
  ): Promise<UploadDataResultLike>
  downloadData(reference: SwarmRef, options?: Record<string, unknown>): Promise<ByteArrayLike>
}

export interface BeeClientWrapperOptions {
  bee: BeeClientWithOptions
  identityPrivKey: PrivateKeyBytes
  historyStore?: HistoryStore
}

export class BeeClientWrapper {
  private readonly publisherPub: PublicKeyBytes
  private readonly historyStore: HistoryStore
  private currentHistoryRef: SwarmRef | null = null

  constructor(private readonly opts: BeeClientWrapperOptions) {
    this.publisherPub = publicKeyFromPrivate(opts.identityPrivKey)
    this.historyStore = opts.historyStore ?? new SwarmHistoryStore(opts.bee)
  }

  async createGrantees(
    postageBatchId: BatchId | Uint8Array | string,
    grantees: PublicKeyInput[],
    _requestOptions?: unknown,
  ): Promise<BeeClientWrapperGranteesResult> {
    const act = this.makeActClient(postageBatchId)
    const normalized = grantees.map(normalizePublicKey)
    const { historyRef } = await act.create({ publisher: this.opts.identityPrivKey, grantees: normalized })
    const ref = await this.resolveGranteeRefAt(historyRef, nowSec())
    this.currentHistoryRef = historyRef

    return {
      status: 201,
      statusText: 'Created',
      ref,
      historyref: historyRef,
    }
  }

  async getGrantees(reference: ReferenceInput, _requestOptions?: unknown): Promise<BeeClientWrapperGetGranteesResult> {
    const data = await this.opts.bee.downloadData(normalizeRef(reference))
    return {
      status: 200,
      statusText: 'OK',
      grantees: deserializeGranteeList(data.toUint8Array()),
    }
  }

  async patchGrantees(
    postageBatchId: BatchId | Uint8Array | string,
    _reference: ReferenceInput,
    history: ReferenceInput,
    grantees: BeeClientWrapperPatchGranteesArgs,
    _requestOptions?: unknown,
  ): Promise<BeeClientWrapperGranteesResult> {
    const historyRef = normalizeRef(history)
    const act = this.makeActClient(postageBatchId)
    const { historyRef: newHistoryRef } = await act.patchGrantees(
      {
        add: grantees.add?.map(normalizePublicKey),
        revoke: grantees.revoke?.map(normalizePublicKey),
      },
      { publisher: this.opts.identityPrivKey, historyRef },
    )

    const ref = await this.resolveGranteeRefAt(newHistoryRef, nowSec())
    this.currentHistoryRef = newHistoryRef
    return {
      status: 200,
      statusText: 'OK',
      ref,
      historyref: newHistoryRef,
    }
  }

  async uploadData(
    postageBatchId: BatchId | Uint8Array | string,
    data: Uint8Array,
    options?: BeeClientWrapperUploadOptions,
  ): Promise<UploadDataResultLike & { historyAddress: SwarmRef | null }> {
    const needsAct = Boolean(options?.act || options?.actHistoryAddress)
    if (!needsAct) {
      const uploaded = await this.opts.bee.uploadData(postageBatchId, data, stripActUploadOptions(options))
      return { ...uploaded, historyAddress: null }
    }

    let historyRef = options?.actHistoryAddress
      ? normalizeRef(options.actHistoryAddress)
      : this.currentHistoryRef

    if (!historyRef) {
      // Mirror Bee's "act: true" convenience when no history is provided.
      const act = this.makeActClient(postageBatchId)
      const created = await act.create({ publisher: this.opts.identityPrivKey, grantees: [this.publisherPub] })
      historyRef = created.historyRef
      this.currentHistoryRef = historyRef
    }

    const uploaded = await this.opts.bee.uploadData(postageBatchId, data, stripActUploadOptions(options))
    const act = this.makeActClient(postageBatchId)
    const encryptedRef = await act.encryptRef(uploaded.reference.toUint8Array(), {
      publisher: this.opts.identityPrivKey,
      historyRef,
    })

    return {
      ...uploaded,
      reference: toByteArrayLike(encryptedRef),
      historyAddress: historyRef,
    }
  }

  async downloadData(reference: ReferenceInput, options?: BeeClientWrapperDownloadOptions): Promise<ByteArrayLike> {
    const needsAct = Boolean(options?.actPublisher || options?.actHistoryAddress || options?.actTimestamp !== undefined)
    if (!needsAct) {
      return this.opts.bee.downloadData(normalizeRef(reference), stripActDownloadOptions(options))
    }

    const historyRef = options?.actHistoryAddress
      ? normalizeRef(options.actHistoryAddress)
      : this.currentHistoryRef
    if (!historyRef) {
      throw new Error('ACT: missing actHistoryAddress')
    }

    const publisherPub = options?.actPublisher
      ? normalizePublicKey(options.actPublisher)
      : this.publisherPub
    const at = parseActTimestamp(options?.actTimestamp)
    const plainRef = await this.decryptRefAtTimestamp(normalizeRef(reference), historyRef, publisherPub, at)
    return this.opts.bee.downloadData(plainRef, stripActDownloadOptions(options))
  }

  private makeActClient(stamp: BatchId | Uint8Array | string): ActClient {
    return new ActClient({ bee: this.opts.bee, stamp: normalizeStamp(stamp), historyStore: this.historyStore })
  }

  private async resolveGranteeRefAt(historyRef: SwarmRef, atUnixSec: number): Promise<SwarmRef> {
    const history = await this.historyStore.load(historyRef)
    const entry = this.historyStore.lookupAt(history, atUnixSec)
    if (!entry) throw new Error('ACT: no history entries')
    const encGlRefHex = entry.metadata.encryptedglref
    if (!encGlRefHex) throw new Error('ACT: missing encrypted grantee list reference')

    const [, publisherAKDec] = deriveKvsKeys(ecdhX(this.opts.identityPrivKey, this.publisherPub))
    return decrypt(hexToBytes(encGlRefHex), publisherAKDec, 0)
  }

  private async decryptRefAtTimestamp(
    encryptedRef: SwarmRef,
    historyRef: SwarmRef,
    publisherPub: PublicKeyBytes,
    atUnixSec: number,
  ): Promise<SwarmRef> {
    const history = await this.historyStore.load(historyRef)
    const entry = this.historyStore.lookupAt(history, atUnixSec)
    if (!entry) throw new Error('ACT: no history entries')

    const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(this.opts.identityPrivKey, publisherPub)
    const kvs = await downloadKvs(this.opts.bee, entry.kvsRef)
    const encAccessKey = manifestGet(kvs, lookupKey)
    if (!encAccessKey) {
      const err = new Error('NOT_FOUND: grantee not present in KVS') as Error & { code?: string }
      err.code = 'NOT_FOUND'
      throw err
    }

    const accessKey = decrypt(encAccessKey, accessKeyDecryptionKey, 0)
    return decrypt(encryptedRef, accessKey, 0)
  }
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000)
}

function parseActTimestamp(value: string | number | undefined): number {
  if (value === undefined) return nowSec()
  if (typeof value === 'number') return Math.floor(value)
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) {
    throw new Error(`ACT: invalid actTimestamp value '${value}'`)
  }
  return Math.floor(parsed)
}

function normalizeStamp(stamp: BatchId | Uint8Array | string): BatchId | string {
  if (typeof stamp === 'string') return stripHex(stamp)
  if (stamp instanceof Uint8Array) return bytesToHex(stamp)
  return stamp
}

function normalizeRef(input: ReferenceInput): SwarmRef {
  if (input instanceof Uint8Array) return input
  return hexToBytes(stripHex(input))
}

function normalizePublicKey(input: PublicKeyInput): PublicKeyBytes {
  const bytes = input instanceof Uint8Array ? input : hexToBytes(stripHex(input))

  if (bytes.length === 65 && bytes[0] === 0x04) return bytes
  if (bytes.length === 64) {
    const out = new Uint8Array(65)
    out[0] = 0x04
    out.set(bytes, 1)
    return out
  }
  if (bytes.length === 33) {
    return secp.Point.fromHex(bytes).toRawBytes(false)
  }

  throw new Error(`ACT: unsupported public key format (length=${bytes.length})`)
}

function stripHex(input: string): string {
  return input.startsWith('0x') ? input.slice(2) : input
}

function toByteArrayLike(bytes: Uint8Array): ByteArrayLike {
  return {
    toUint8Array: () => bytes,
  }
}

function stripActUploadOptions(options?: BeeClientWrapperUploadOptions): Record<string, unknown> | undefined {
  if (!options) return undefined
  const out = { ...options }
  delete out.act
  delete out.actHistoryAddress
  return out
}

function stripActDownloadOptions(options?: BeeClientWrapperDownloadOptions): Record<string, unknown> | undefined {
  if (!options) return undefined
  const out = { ...options }
  delete out.actPublisher
  delete out.actHistoryAddress
  delete out.actTimestamp
  return out
}

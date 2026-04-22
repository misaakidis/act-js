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
  BeeClientWrapperActUploadMode,
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
    requestOptions?: unknown,
  ): Promise<UploadDataResultLike>
  downloadData(reference: SwarmRef, options?: Record<string, unknown>, requestOptions?: unknown): Promise<ByteArrayLike>
}

export interface BeeClientWrapperOptions {
  bee: BeeClientWithOptions
  identityPrivKey: PrivateKeyBytes
  historyStore?: HistoryStore
  actUploadMode?: BeeClientWrapperActUploadMode
}

export class BeeClientWrapper {
  private readonly publisherPub: PublicKeyBytes
  private readonly historyStoreFactory: (requestOptions?: unknown) => HistoryStore
  private readonly actUploadMode: BeeClientWrapperActUploadMode
  private currentHistoryRef: SwarmRef | null = null
  private readonly refHistoryMap = new Map<string, string>()

  constructor(private readonly opts: BeeClientWrapperOptions) {
    this.publisherPub = publicKeyFromPrivate(opts.identityPrivKey)
    this.historyStoreFactory =
      opts.historyStore !== undefined
        ? () => opts.historyStore!
        : requestOptions => new SwarmHistoryStore(this.withRequestOptions(requestOptions))
    this.actUploadMode = opts.actUploadMode ?? 'strict'
  }

  async createGrantees(
    postageBatchId: BatchId | Uint8Array | string,
    grantees: PublicKeyInput[],
    requestOptions?: unknown,
  ): Promise<BeeClientWrapperGranteesResult> {
    const act = this.makeActClient(postageBatchId, requestOptions)
    const normalized = grantees.map(normalizePublicKey)
    const { historyRef } = await act.create({ publisher: this.opts.identityPrivKey, grantees: normalized })
    const ref = await this.resolveGranteeRefAt(historyRef, nowSec(), requestOptions)
    this.currentHistoryRef = historyRef
    this.cacheRefHistory(ref, historyRef)

    return {
      ...responseMeta(201, 'Created'),
      ref,
      historyref: historyRef,
    }
  }

  async getGrantees(reference: ReferenceInput, requestOptions?: unknown): Promise<BeeClientWrapperGetGranteesResult> {
    const data = await this.opts.bee.downloadData(normalizeRef(reference), undefined, requestOptions)
    return {
      ...responseMeta(200, 'OK'),
      grantees: deserializeGranteeList(data.toUint8Array()),
    }
  }

  async patchGrantees(
    postageBatchId: BatchId | Uint8Array | string,
    reference: ReferenceInput,
    history: ReferenceInput,
    grantees: BeeClientWrapperPatchGranteesArgs,
    requestOptions?: unknown,
  ): Promise<BeeClientWrapperGranteesResult> {
    const providedRef = normalizeRef(reference)
    const historyRef = normalizeRef(history)
    this.validateRefHistoryPair(providedRef, historyRef)
    const expectedRef = await this.resolveGranteeRefAt(historyRef, nowSec(), requestOptions)
    if (!bytesEqual(providedRef, expectedRef)) {
      throw new Error('ACT: reference does not match history state')
    }

    const act = this.makeActClient(postageBatchId, requestOptions)
    const { historyRef: newHistoryRef } = await act.patchGrantees(
      {
        add: grantees.add?.map(normalizePublicKey),
        revoke: grantees.revoke?.map(normalizePublicKey),
      },
      { publisher: this.opts.identityPrivKey, historyRef },
    )

    const ref = await this.resolveGranteeRefAt(newHistoryRef, nowSec(), requestOptions)
    this.currentHistoryRef = newHistoryRef
    this.cacheRefHistory(ref, newHistoryRef)
    return {
      ...responseMeta(200, 'OK'),
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
    const requestOptions = options?.requestOptions
    if (!needsAct) {
      const uploaded = await this.opts.bee.uploadData(postageBatchId, data, stripActUploadOptions(options), requestOptions)
      return { ...uploaded, historyAddress: null }
    }

    let historyRef = options?.actHistoryAddress
      ? normalizeRef(options.actHistoryAddress)
      : this.currentHistoryRef

    if (!historyRef && this.actUploadMode === 'strict') {
      throw new Error('ACT: actHistoryAddress is required when act=true in strict mode')
    }

    if (!historyRef && this.actUploadMode === 'compat') {
      // Compatibility mode mirrors a convenience flow by creating history on first ACT upload.
      const act = this.makeActClient(postageBatchId, requestOptions)
      const created = await act.create({ publisher: this.opts.identityPrivKey, grantees: [this.publisherPub] })
      historyRef = created.historyRef
      this.currentHistoryRef = historyRef
    }

    const uploaded = await this.opts.bee.uploadData(
      postageBatchId,
      data,
      stripActUploadOptions(options),
      requestOptions,
    )
    const act = this.makeActClient(postageBatchId, requestOptions)
    const encryptedRef = await act.encryptRef(uploaded.reference.toUint8Array(), {
      publisher: this.opts.identityPrivKey,
      historyRef: historyRef!,
    })

    return {
      ...uploaded,
      reference: toByteArrayLike(encryptedRef),
      historyAddress: historyRef!,
    }
  }

  async downloadData(reference: ReferenceInput, options?: BeeClientWrapperDownloadOptions): Promise<ByteArrayLike> {
    const needsAct = Boolean(options?.actPublisher || options?.actHistoryAddress || options?.actTimestamp !== undefined)
    const requestOptions = options?.requestOptions
    if (!needsAct) {
      return this.opts.bee.downloadData(normalizeRef(reference), stripActDownloadOptions(options), requestOptions)
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
    const plainRef = await this.decryptRefAtTimestamp(normalizeRef(reference), historyRef, publisherPub, at, requestOptions)
    return this.opts.bee.downloadData(plainRef, stripActDownloadOptions(options), requestOptions)
  }

  private makeActClient(stamp: BatchId | Uint8Array | string, requestOptions?: unknown): ActClient {
    return new ActClient({
      bee: this.withRequestOptions(requestOptions),
      stamp: normalizeStamp(stamp),
      historyStore: this.historyStoreFactory(requestOptions),
    })
  }

  private async resolveGranteeRefAt(historyRef: SwarmRef, atUnixSec: number, requestOptions?: unknown): Promise<SwarmRef> {
    const historyStore = this.historyStoreFactory(requestOptions)
    const history = await historyStore.load(historyRef)
    const entry = historyStore.lookupAt(history, atUnixSec)
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
    requestOptions?: unknown,
  ): Promise<SwarmRef> {
    const historyStore = this.historyStoreFactory(requestOptions)
    const history = await historyStore.load(historyRef)
    const entry = historyStore.lookupAt(history, atUnixSec)
    if (!entry) throw new Error('ACT: no history entries')

    const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(this.opts.identityPrivKey, publisherPub)
    const kvs = await downloadKvs(this.withRequestOptions(requestOptions), entry.kvsRef)
    const encAccessKey = manifestGet(kvs, lookupKey)
    if (!encAccessKey) {
      const err = new Error('NOT_FOUND: grantee not present in KVS') as Error & { code?: string }
      err.code = 'NOT_FOUND'
      throw err
    }

    const accessKey = decrypt(encAccessKey, accessKeyDecryptionKey, 0)
    return decrypt(encryptedRef, accessKey, 0)
  }

  private withRequestOptions(requestOptions?: unknown): BeeDataClient {
    if (requestOptions === undefined) {
      return this.opts.bee
    }

    return {
      uploadData: async (stamp, data) => this.opts.bee.uploadData(stamp, data, undefined, requestOptions),
      downloadData: async reference => this.opts.bee.downloadData(reference, undefined, requestOptions),
    }
  }

  private cacheRefHistory(ref: SwarmRef, historyRef: SwarmRef): void {
    this.refHistoryMap.set(bytesToHex(ref), bytesToHex(historyRef))
  }

  private validateRefHistoryPair(ref: SwarmRef, historyRef: SwarmRef): void {
    const expectedHistoryHex = this.refHistoryMap.get(bytesToHex(ref))
    if (!expectedHistoryHex) return
    if (expectedHistoryHex !== bytesToHex(historyRef)) {
      throw new Error('ACT: reference/history mismatch')
    }
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i])
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
  delete out.requestOptions
  return out
}

function stripActDownloadOptions(options?: BeeClientWrapperDownloadOptions): Record<string, unknown> | undefined {
  if (!options) return undefined
  const out = { ...options }
  delete out.actPublisher
  delete out.actHistoryAddress
  delete out.actTimestamp
  delete out.requestOptions
  return out
}

function responseMeta(status: number, statusText: string): { status: number; statusText: string } {
  return { status, statusText }
}

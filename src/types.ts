import type { BatchId } from '@ethersphere/bee-js'

/** 32-byte hex string (no 0x prefix, lowercase). */
export type HexString = string

/** Secp256k1 private key (32 bytes). */
export type PrivateKeyBytes = Uint8Array

/** Secp256k1 uncompressed public key (65 bytes, 0x04-prefixed). */
export type PublicKeyBytes = Uint8Array

/** Swarm reference (32 bytes, or 64 if Swarm-encrypted). */
export type SwarmRef = Uint8Array

/** Objects from bee-js that can be converted to raw bytes. */
export interface ByteArrayLike {
  toUint8Array(): Uint8Array
}

/** Minimal upload response shape needed by act-js. */
export interface UploadDataResultLike {
  reference: ByteArrayLike
}

/**
 * Minimal data client contract required by ActClient/KVS/history helpers.
 * A concrete `Bee` instance is structurally compatible with this interface.
 */
export interface BeeDataClient {
  uploadData(stamp: BatchId | string, data: Uint8Array): Promise<UploadDataResultLike>
  downloadData(reference: SwarmRef): Promise<ByteArrayLike>
}

/** A single ACT history entry at a given timestamp. */
export interface HistoryEntryLike {
  timestamp: number
  kvsRef: SwarmRef
  metadata: Record<string, string>
}

/**
 * Storage-agnostic history snapshot used by ActClient.
 * Implementations may carry extra backend-specific state internally.
 */
export interface HistorySnapshot {
  entries: HistoryEntryLike[]
}

/** History persistence/lookup backend used by ActClient. */
export interface HistoryStore {
  createEmpty(): Promise<HistorySnapshot>
  load(historyRef: SwarmRef): Promise<HistorySnapshot>
  lookupAt(snapshot: HistorySnapshot, atUnixSec: number): HistoryEntryLike | null
  append(snapshot: HistorySnapshot, entry: HistoryEntryLike): Promise<void>
  save(snapshot: HistorySnapshot, stamp: BatchId | string): Promise<SwarmRef>
}

/** Result of an ACT operation that may advance history. */
export interface HistoryResult {
  historyRef: SwarmRef
}

export interface ActError extends Error {
  code: 'NOT_FOUND' | 'INVALID_KEY' | 'DECRYPT_FAILED' | 'WIRE_MISMATCH'
}

/** Bee-style public key input accepted by wrapper methods. */
export type PublicKeyInput = PublicKeyBytes | string

/** Bee-style reference input accepted by wrapper methods. */
export type ReferenceInput = SwarmRef | string

export interface BeeClientWrapperGranteesResult {
  status: number
  statusText: string
  ref: SwarmRef
  historyref: SwarmRef
}

export interface BeeClientWrapperGetGranteesResult {
  status: number
  statusText: string
  grantees: PublicKeyBytes[]
}

export interface BeeClientWrapperPatchGranteesArgs {
  add?: PublicKeyInput[]
  revoke?: PublicKeyInput[]
}

export interface BeeClientWrapperUploadOptions {
  act?: boolean
  actHistoryAddress?: ReferenceInput
  [key: string]: unknown
}

export interface BeeClientWrapperDownloadOptions {
  actPublisher?: PublicKeyInput
  actHistoryAddress?: ReferenceInput
  actTimestamp?: string | number
  [key: string]: unknown
}

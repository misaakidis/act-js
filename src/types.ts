/** 32-byte hex string (no 0x prefix, lowercase). */
export type HexString = string

/** Secp256k1 private key (32 bytes). */
export type PrivateKeyBytes = Uint8Array

/** Secp256k1 uncompressed public key (65 bytes, 0x04-prefixed). */
export type PublicKeyBytes = Uint8Array

/** Swarm reference (32 bytes, or 64 if Swarm-encrypted). */
export type SwarmRef = Uint8Array

/** Result of an ACT operation that may advance history. */
export interface HistoryResult {
  historyRef: Uint8Array
}

export interface ActError extends Error {
  code: 'NOT_FOUND' | 'INVALID_KEY' | 'DECRYPT_FAILED' | 'WIRE_MISMATCH'
}

import { bytesToHex, hexToBytes } from '@noble/hashes/utils'

export interface ManifestEntry {
  reference: string
  metadata: Record<string, string>
}

export interface SimpleManifest {
  entries: Record<string, ManifestEntry>
}

export function createEmptyManifest(): SimpleManifest {
  return { entries: {} }
}

export function manifestPut(m: SimpleManifest, lookupKey: Uint8Array, value: Uint8Array): void {
  m.entries[bytesToHex(lookupKey)] = {
    reference: bytesToHex(value),
    metadata: {},
  }
}

export function manifestGet(m: SimpleManifest, lookupKey: Uint8Array): Uint8Array | null {
  const entry = m.entries[bytesToHex(lookupKey)]
  if (!entry) return null
  return hexToBytes(entry.reference)
}

export function manifestHas(m: SimpleManifest, lookupKey: Uint8Array): boolean {
  return bytesToHex(lookupKey) in m.entries
}

export function manifestDelete(m: SimpleManifest, lookupKey: Uint8Array): void {
  delete m.entries[bytesToHex(lookupKey)]
}

export function manifestToBytes(m: SimpleManifest): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(m))
}

export function manifestFromBytes(data: Uint8Array): SimpleManifest {
  const text = new TextDecoder().decode(data)
  const parsed = JSON.parse(text) as { entries?: unknown }
  if (typeof parsed !== 'object' || parsed === null || typeof parsed.entries !== 'object' || parsed.entries === null) {
    throw new Error('kvs: invalid SimpleManifest JSON shape')
  }
  return parsed as SimpleManifest
}

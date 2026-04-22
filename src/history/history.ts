import { MantarayNode, type BatchId, type Bee } from '@ethersphere/bee-js'

const MAX_INT64 = 9223372036854775807n

export interface HistoryEntry {
  timestamp: number
  kvsRef: Uint8Array
  metadata: Record<string, string>
}

export function timestampToPath(unixSec: number): string {
  return (MAX_INT64 - BigInt(unixSec)).toString()
}

export function pathToTimestamp(path: string): number {
  return Number(MAX_INT64 - BigInt(path))
}

export function createEmptyHistory(): MantarayNode {
  return new MantarayNode()
}

export function addHistoryEntry(root: MantarayNode, entry: HistoryEntry): void {
  const path = timestampToPath(entry.timestamp)
  if (root.find(path)) {
    throw new Error(`history: timestamp ${entry.timestamp} already present`)
  }
  root.addFork(path, entry.kvsRef, entry.metadata)
}

export function collectHistoryEntries(root: MantarayNode): HistoryEntry[] {
  const nodes = root.collect()
  const out: HistoryEntry[] = nodes.map(node => ({
    timestamp: pathToTimestamp(node.fullPathString),
    kvsRef: node.targetAddress,
    metadata: node.metadata ?? {},
  }))
  out.sort((a, b) => a.timestamp - b.timestamp)
  return out
}

export function lookupHistory(root: MantarayNode, atUnixSec: number): HistoryEntry | null {
  const entries = collectHistoryEntries(root)
  let best: HistoryEntry | null = null
  for (const entry of entries) {
    if (entry.timestamp <= atUnixSec && (!best || entry.timestamp > best.timestamp)) {
      best = entry
    }
  }
  return best
}

export async function uploadHistory(
  bee: Bee,
  stamp: BatchId | string,
  root: MantarayNode,
): Promise<Uint8Array> {
  const result = await root.saveRecursively(bee, stamp)
  return result.reference.toUint8Array()
}

/**
 * NOTE: This relies on bee-js Mantaray serialization being wire-compatible
 * with bee Go implementation. This is validated via integration tests.
 */
export async function downloadHistory(bee: Bee, historyRef: Uint8Array): Promise<MantarayNode> {
  const root = await MantarayNode.unmarshal(bee, historyRef)
  await root.loadRecursively(bee)
  return root
}

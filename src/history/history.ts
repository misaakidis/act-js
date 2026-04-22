import { MantarayNode, type BatchId, type Bee } from '@ethersphere/bee-js'
import type { BeeDataClient, HistorySnapshot, HistoryStore, SwarmRef } from '../types.js'

const MAX_INT64 = 9223372036854775807n

export interface HistoryEntry {
  timestamp: number
  kvsRef: SwarmRef
  metadata: Record<string, string>
}

interface SwarmHistorySnapshot extends HistorySnapshot {
  root: MantarayNode
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
  bee: BeeDataClient,
  stamp: BatchId | string,
  root: MantarayNode,
): Promise<SwarmRef> {
  const result = await root.saveRecursively(bee as unknown as Bee, stamp)
  return result.reference.toUint8Array()
}

/**
 * NOTE: This relies on bee-js Mantaray serialization being wire-compatible
 * with bee Go implementation. This is validated via integration tests.
 */
export async function downloadHistory(bee: BeeDataClient, historyRef: SwarmRef): Promise<MantarayNode> {
  const mantarayBee = bee as unknown as Bee
  const root = await MantarayNode.unmarshal(mantarayBee, historyRef)
  await root.loadRecursively(mantarayBee)
  return root
}

export class SwarmHistoryStore implements HistoryStore {
  constructor(private readonly bee: BeeDataClient) {}

  async createEmpty(): Promise<HistorySnapshot> {
    const root = createEmptyHistory()
    const snapshot: SwarmHistorySnapshot = { root, entries: [] }
    return snapshot
  }

  async load(historyRef: SwarmRef): Promise<HistorySnapshot> {
    const root = await downloadHistory(this.bee, historyRef)
    const snapshot: SwarmHistorySnapshot = { root, entries: collectHistoryEntries(root) }
    return snapshot
  }

  lookupAt(snapshot: HistorySnapshot, atUnixSec: number): HistoryEntry | null {
    return lookupHistory(this.asSwarm(snapshot).root, atUnixSec)
  }

  async append(snapshot: HistorySnapshot, entry: HistoryEntry): Promise<void> {
    const swarm = this.asSwarm(snapshot)
    addHistoryEntry(swarm.root, entry)
    swarm.entries = collectHistoryEntries(swarm.root)
  }

  async save(snapshot: HistorySnapshot, stamp: BatchId | string): Promise<SwarmRef> {
    return uploadHistory(this.bee, stamp, this.asSwarm(snapshot).root)
  }

  private asSwarm(snapshot: HistorySnapshot): SwarmHistorySnapshot {
    if (!('root' in snapshot) || !(snapshot.root instanceof MantarayNode)) {
      throw new Error('history: expected SwarmHistorySnapshot')
    }

    return snapshot as SwarmHistorySnapshot
  }
}

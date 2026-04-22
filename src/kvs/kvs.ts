import type { BatchId, Bee } from '@ethersphere/bee-js'
import {
  createEmptyManifest,
  manifestDelete,
  manifestFromBytes,
  manifestGet,
  manifestHas,
  manifestPut,
  manifestToBytes,
  type SimpleManifest,
} from './simple-manifest.js'

export async function uploadKvs(bee: Bee, stamp: BatchId | string, manifest: SimpleManifest): Promise<Uint8Array> {
  const bytes = manifestToBytes(manifest)
  const result = await bee.uploadData(stamp, bytes)
  return result.reference.toUint8Array()
}

export async function downloadKvs(bee: Bee, ref: Uint8Array): Promise<SimpleManifest> {
  const data = await bee.downloadData(ref)
  return manifestFromBytes(data.toUint8Array())
}

export { createEmptyManifest, manifestPut, manifestGet, manifestHas, manifestDelete }
export type { SimpleManifest }

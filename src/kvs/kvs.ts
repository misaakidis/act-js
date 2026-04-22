import type { BatchId } from '@ethersphere/bee-js'
import type { BeeDataClient, SwarmRef } from '../types.js'
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

export async function uploadKvs(
  bee: BeeDataClient,
  stamp: BatchId | string,
  manifest: SimpleManifest,
): Promise<SwarmRef> {
  const bytes = manifestToBytes(manifest)
  const result = await bee.uploadData(stamp, bytes)
  return result.reference.toUint8Array()
}

export async function downloadKvs(bee: BeeDataClient, ref: SwarmRef): Promise<SimpleManifest> {
  const data = await bee.downloadData(ref)
  return manifestFromBytes(data.toUint8Array())
}

export { createEmptyManifest, manifestPut, manifestGet, manifestHas, manifestDelete }
export type { SimpleManifest }

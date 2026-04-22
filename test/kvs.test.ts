import { hexToBytes } from '@noble/hashes/utils'
import { describe, expect, it } from 'vitest'
import {
  createEmptyManifest,
  manifestDelete,
  manifestFromBytes,
  manifestGet,
  manifestHas,
  manifestPut,
  manifestToBytes,
} from '../src/kvs/simple-manifest.js'

describe('SimpleManifest', () => {
  it('puts and gets by lookup key', () => {
    const m = createEmptyManifest()
    const key = hexToBytes('b6ee086390c280eeb9824c331a4427596f0c8510d5564bc1b6168d0059a46e2b')
    const val = hexToBytes('39a5ea87b141fe44aa609c3327ecd896c0e2122897f5f4bbacf74db1033c5559')
    manifestPut(m, key, val)
    expect(manifestHas(m, key)).toBe(true)
    expect(manifestGet(m, key)).toEqual(val)
  })

  it('serializes to JSON with expected shape', () => {
    const m = createEmptyManifest()
    const key = hexToBytes('b6ee086390c280eeb9824c331a4427596f0c8510d5564bc1b6168d0059a46e2b')
    const val = hexToBytes('39a5ea87b141fe44aa609c3327ecd896c0e2122897f5f4bbacf74db1033c5559')
    manifestPut(m, key, val)
    const decoded = JSON.parse(new TextDecoder().decode(manifestToBytes(m)))
    expect(decoded).toEqual({
      entries: {
        b6ee086390c280eeb9824c331a4427596f0c8510d5564bc1b6168d0059a46e2b: {
          reference: '39a5ea87b141fe44aa609c3327ecd896c0e2122897f5f4bbacf74db1033c5559',
          metadata: {},
        },
      },
    })
  })

  it('roundtrips through bytes', () => {
    const m = createEmptyManifest()
    const key = new Uint8Array(32).fill(0xab)
    const val = new Uint8Array(32).fill(0xcd)
    manifestPut(m, key, val)
    const parsed = manifestFromBytes(manifestToBytes(m))
    expect(manifestGet(parsed, key)).toEqual(val)
  })

  it('delete removes entry', () => {
    const m = createEmptyManifest()
    const key = new Uint8Array(32).fill(0x11)
    manifestPut(m, key, new Uint8Array(32).fill(0x22))
    manifestDelete(m, key)
    expect(manifestHas(m, key)).toBe(false)
  })
})

import { keccak_256 } from "@noble/hashes/sha3";

const BLOCK_SIZE = 32;

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Encrypt/decrypt with Bee's XOR stream cipher.
 * This is symmetric: decrypt(data) === encrypt(data) for same key/counter.
 */
export function transform(
  data: Uint8Array,
  key: Uint8Array,
  initCtr = 0,
): Uint8Array {
  if (key.length !== BLOCK_SIZE) {
    throw new Error(
      `cipher: key must be ${BLOCK_SIZE} bytes, got ${key.length}`,
    );
  }

  const output = new Uint8Array(data.length);
  const numBlocks = Math.ceil(data.length / BLOCK_SIZE);

  for (let i = 0; i < numBlocks; i++) {
    const ctr = (initCtr + i) >>> 0;
    const ctrBytes = new Uint8Array(4);
    ctrBytes[0] = ctr & 0xff;
    ctrBytes[1] = (ctr >>> 8) & 0xff;
    ctrBytes[2] = (ctr >>> 16) & 0xff;
    ctrBytes[3] = (ctr >>> 24) & 0xff;

    const h1 = keccak_256(concatBytes(key, ctrBytes));
    const blockKey = keccak_256(h1);

    const start = i * BLOCK_SIZE;
    const end = Math.min(start + BLOCK_SIZE, data.length);
    for (let j = start; j < end; j++) {
      output[j] = data[j] ^ blockKey[j - start];
    }
  }

  return output;
}

export const encrypt = transform;
export const decrypt = transform;

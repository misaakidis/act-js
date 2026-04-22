import * as secp from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Bee-compatible ECDH X-coordinate extraction.
 * Returns minimally encoded big-endian bytes (Go big.Int.Bytes behavior).
 */
export function ecdhX(myPriv: Uint8Array, theirPub: Uint8Array): Uint8Array {
  const shared = secp.getSharedSecret(myPriv, theirPub, false);
  const xFullWidth = shared.slice(1, 33);

  let start = 0;
  while (start < xFullWidth.length - 1 && xFullWidth[start] === 0) {
    start++;
  }

  return xFullWidth.slice(start);
}

export function deriveKvsKeys(sharedX: Uint8Array): [Uint8Array, Uint8Array] {
  const lookupKey = keccak_256(concatBytes(sharedX, new Uint8Array([0x00])));
  const accessKeyDecryptionKey = keccak_256(
    concatBytes(sharedX, new Uint8Array([0x01])),
  );
  return [lookupKey, accessKeyDecryptionKey];
}

export function deriveSessionKeys(
  myPriv: Uint8Array,
  theirPub: Uint8Array,
): { lookupKey: Uint8Array; accessKeyDecryptionKey: Uint8Array } {
  const sharedX = ecdhX(myPriv, theirPub);
  const [lookupKey, accessKeyDecryptionKey] = deriveKvsKeys(sharedX);
  return { lookupKey, accessKeyDecryptionKey };
}

export function publicKeyFromPrivate(priv: Uint8Array): Uint8Array {
  return secp.getPublicKey(priv, false);
}

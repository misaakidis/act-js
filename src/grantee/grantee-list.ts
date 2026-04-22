const PUBKEY_LEN = 65;

function byteEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function serializeGranteeList(pubkeys: Uint8Array[]): Uint8Array {
  for (const pk of pubkeys) {
    if (pk.length !== PUBKEY_LEN) {
      throw new Error(
        `grantee list: public key must be ${PUBKEY_LEN} bytes, got ${pk.length}`,
      );
    }
    if (pk[0] !== 0x04) {
      throw new Error(
        `grantee list: public key must have 0x04 prefix, got 0x${pk[0].toString(16)}`,
      );
    }
  }

  const out = new Uint8Array(pubkeys.length * PUBKEY_LEN);
  for (let i = 0; i < pubkeys.length; i++) {
    out.set(pubkeys[i], i * PUBKEY_LEN);
  }
  return out;
}

export function deserializeGranteeList(data: Uint8Array): Uint8Array[] {
  if (data.length % PUBKEY_LEN !== 0) {
    throw new Error(
      `grantee list: data length ${data.length} is not a multiple of ${PUBKEY_LEN}`,
    );
  }

  const out: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += PUBKEY_LEN) {
    const pk = data.slice(i, i + PUBKEY_LEN);
    if (pk[0] !== 0x04) {
      throw new Error(
        `grantee list: entry at offset ${i} has invalid prefix 0x${pk[0].toString(16)}`,
      );
    }
    out.push(pk);
  }
  return out;
}

export function containsPubkey(
  list: Uint8Array[],
  pubkey: Uint8Array,
): boolean {
  return list.some((pk) => byteEq(pk, pubkey));
}

export function removePubkey(
  list: Uint8Array[],
  pubkey: Uint8Array,
): Uint8Array[] {
  return list.filter((pk) => !byteEq(pk, pubkey));
}

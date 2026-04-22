import { ecdhX, publicKeyFromPrivate } from "./crypto/ecdh.js";
import type { PrivateKeyBytes, PublicKeyBytes } from "./types.js";

/**
 * Identity primitive used by ACT operations.
 *
 * Exposes only the two verbs ACT's wire format requires:
 *   - the signer's own public key
 *   - secp256k1 ECDH with a counterparty's public key, returning the raw
 *     minimally-encoded X coordinate (bee-compatible, not hashed)
 *
 * Deliberately does not expose raw private-key material so that custody-aware
 * backends (wallets, enclaves, remote signers) can implement the interface
 * without ever surfacing the secret. Pass `rawKeySigner(priv)` when the key
 * material is already in-process.
 */
export interface ActSigner {
  publicKey(): PublicKeyBytes;
  ecdhSharedX(otherPub: PublicKeyBytes): Uint8Array;
}

export function rawKeySigner(priv: PrivateKeyBytes): ActSigner {
  const pub = publicKeyFromPrivate(priv);
  return {
    publicKey: () => pub,
    ecdhSharedX: (otherPub) => ecdhX(priv, otherPub),
  };
}

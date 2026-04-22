import * as secp from "@noble/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";
import fixtures from "./fixtures/ecdh.json";
import {
  deriveSessionKeys,
  ecdhX,
  publicKeyFromPrivate,
} from "../src/crypto/ecdh.js";

describe("ecdh", () => {
  it("symmetric: alice x bobPub == bob x alicePub", () => {
    const alicePriv = secp.utils.randomPrivateKey();
    const bobPriv = secp.utils.randomPrivateKey();
    const alicePub = publicKeyFromPrivate(alicePriv);
    const bobPub = publicKeyFromPrivate(bobPriv);

    const a = ecdhX(alicePriv, bobPub);
    const b = ecdhX(bobPriv, alicePub);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it("derives both KVS keys", () => {
    const alicePriv = secp.utils.randomPrivateKey();
    const bobPub = publicKeyFromPrivate(secp.utils.randomPrivateKey());
    const { lookupKey, accessKeyDecryptionKey } = deriveSessionKeys(
      alicePriv,
      bobPub,
    );
    expect(lookupKey.length).toBe(32);
    expect(accessKeyDecryptionKey.length).toBe(32);
    expect(bytesToHex(lookupKey)).not.toBe(bytesToHex(accessKeyDecryptionKey));
  });
});

describe("ecdh - fixtures", () => {
  if (fixtures.length === 0) {
    it("has no fixtures yet", () => {
      expect(fixtures).toEqual([]);
    });
  } else {
    for (const fixture of fixtures) {
      it(fixture.name, () => {
        const alice = deriveSessionKeys(
          hexToBytes(fixture.alice_priv),
          hexToBytes(fixture.bob_pub),
        );
        expect(bytesToHex(alice.lookupKey)).toBe(fixture.lookup_key);
        expect(bytesToHex(alice.accessKeyDecryptionKey)).toBe(
          fixture.decrypt_key,
        );

        const bob = deriveSessionKeys(
          hexToBytes(fixture.bob_priv),
          hexToBytes(fixture.alice_pub),
        );
        expect(bytesToHex(bob.lookupKey)).toBe(fixture.lookup_key);
        expect(bytesToHex(bob.accessKeyDecryptionKey)).toBe(
          fixture.decrypt_key,
        );
      });
    }
  }
});

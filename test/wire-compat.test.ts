import { Bee } from "@ethersphere/bee-js";
import * as secp from "@noble/secp256k1";
import { hexToBytes } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";
import { ActClient } from "../src/act.js";
import { rawKeySigner } from "../src/signer.js";

const STAMP = process.env.BEE_STAMP;
const BEE_URL = process.env.BEE_URL || "http://localhost:1633";
const BEE_DEBUG_URL = process.env.BEE_DEBUG_URL;

describe.skipIf(!STAMP)("wire-compat", () => {
  it("bee node decrypts ACT-protected reference created by act-js", async () => {
    const bee = new Bee(BEE_URL);
    const act = new ActClient({ bee, stamp: STAMP! });

    const creatorPriv = secp.utils.randomPrivateKey();
    const creatorSigner = rawKeySigner(creatorPriv);
    const creatorPubCompressed = secp.getPublicKey(creatorPriv, true);

    const nodePub64 = await resolveNodePublicKey64(bee);
    const nodePub65 = toUncompressed65(nodePub64);

    const { historyRef } = await act.create({
      signer: creatorSigner,
      grantees: [creatorSigner.publicKey(), nodePub65],
    });

    const plaintext = new TextEncoder().encode(`wire-compat:${Date.now()}`);
    const uploaded = await bee.uploadData(STAMP!, plaintext);
    const encryptedRef = await act.encryptRef(
      uploaded.reference.toUint8Array(),
      {
        signer: creatorSigner,
        historyRef,
      },
    );

    const downloaded = await bee.downloadData(encryptedRef, {
      actPublisher: creatorPubCompressed,
      actHistoryAddress: historyRef,
    });

    expect(downloaded.toUint8Array()).toEqual(plaintext);
  });

  it("act-js decrypts ACT-protected reference created by bee node", async () => {
    const bee = new Bee(BEE_URL);

    // Grantee holds a secp256k1 key pair locally. Bee-go is the publisher
    // (its own node key) and manages the ACT server-side.
    const granteePriv = secp.utils.randomPrivateKey();
    const granteePubCompressed = secp.getPublicKey(granteePriv, true);

    // 1. Bee-go creates the ACT server-side, granting access to our grantee.
    const created = await bee.createGrantees(STAMP!, [granteePubCompressed]);

    // 2. Bee-go uploads data under that ACT.
    const plaintext = new TextEncoder().encode(
      `reverse-wire-compat:${Date.now()}`,
    );
    const uploaded = await bee.uploadData(STAMP!, plaintext, {
      act: true,
      actHistoryAddress: created.historyref,
    });
    const encryptedRef = uploaded.reference.toUint8Array();
    const historyRef = uploaded.historyAddress.getOrThrow().toUint8Array();

    // 3. act-js, using only the grantee's key and the node's public key,
    //    decrypts independently.
    const nodePub64 = await resolveNodePublicKey64(bee);
    const nodePub65 = toUncompressed65(nodePub64);

    const act = new ActClient({ bee });
    const plainRef = await act.decryptRef(encryptedRef, {
      signer: rawKeySigner(granteePriv),
      publisherPub: nodePub65,
      historyRef,
    });

    const fetched = await bee.downloadData(plainRef);
    expect(fetched.toUint8Array()).toEqual(plaintext);
  });
});

async function resolveNodePublicKey64(bee: Bee): Promise<Uint8Array> {
  const fromEnv = process.env.BEE_PUBLIC_KEY;
  if (fromEnv) {
    return normalizePublicKey64(hexToBytes(stripHex(fromEnv)));
  }

  const source = BEE_DEBUG_URL ? new Bee(BEE_DEBUG_URL) : bee;
  const addresses = await source.getNodeAddresses();
  return normalizePublicKey64(addresses.publicKey.toUint8Array());
}

function normalizePublicKey64(pub: Uint8Array): Uint8Array {
  if (pub.length === 64) return pub;
  if (pub.length === 65 && pub[0] === 0x04) return pub.slice(1);
  if (pub.length === 33) {
    const uncompressed = secp.Point.fromHex(pub).toRawBytes(false);
    return uncompressed.slice(1);
  }
  throw new Error(`unsupported Bee public key length: ${pub.length}`);
}

function toUncompressed65(pub64: Uint8Array): Uint8Array {
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(pub64, 1);
  return out;
}

function stripHex(input: string): string {
  return input.startsWith("0x") ? input.slice(2) : input;
}

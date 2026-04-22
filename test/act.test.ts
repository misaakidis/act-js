import * as secp from "@noble/secp256k1";
import { Bee } from "@ethersphere/bee-js";
import { describe, expect, it } from "vitest";
import { ActClient } from "../src/act.js";
import { rawKeySigner } from "../src/signer.js";

const BEE_URL = process.env.BEE_URL || "http://localhost:1633";
const STAMP = process.env.BEE_STAMP;

describe.skipIf(!STAMP)("ActClient integration", () => {
  it("create -> encryptRef -> decryptRef -> revoke -> denied", async () => {
    const bee = new Bee(BEE_URL);
    const act = new ActClient({ bee, stamp: STAMP! });

    const creatorSigner = rawKeySigner(secp.utils.randomPrivateKey());
    const granteeSigner = rawKeySigner(secp.utils.randomPrivateKey());
    const creatorPub = creatorSigner.publicKey();
    const granteePub = granteeSigner.publicKey();

    const { historyRef } = await act.create({
      signer: creatorSigner,
      grantees: [creatorPub, granteePub],
    });

    const manifestRef = new Uint8Array(32).fill(0xaa);
    const encRef = await act.encryptRef(manifestRef, {
      signer: creatorSigner,
      historyRef,
    });
    const decRef = await act.decryptRef(encRef, {
      signer: granteeSigner,
      publisherPub: creatorPub,
      historyRef,
    });
    expect(decRef).toEqual(manifestRef);

    const { historyRef: newHistoryRef } = await act.patchGrantees(
      { revoke: [granteePub] },
      { signer: creatorSigner, historyRef },
    );

    await expect(
      act.decryptRef(encRef, {
        signer: granteeSigner,
        publisherPub: creatorPub,
        historyRef: newHistoryRef,
      }),
    ).rejects.toThrow(/NOT_FOUND/);
  });
});

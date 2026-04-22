import { Bee } from "@ethersphere/bee-js";
import * as secp from "@noble/secp256k1";
import { describe, expect, it } from "vitest";
import { ActBeeWrapper } from "../src/act-bee-wrapper.js";
import { rawKeySigner } from "../src/signer.js";

const BEE_URL = process.env.BEE_URL || "http://localhost:1633";
const STAMP = process.env.BEE_STAMP;

describe.skipIf(!STAMP)("ActBeeWrapper integration", () => {
  it("supports create/get/patch parity and timestamped ACT reads", async () => {
    const bee = new Bee(BEE_URL);

    const creatorSigner = rawKeySigner(secp.utils.randomPrivateKey());
    const granteeSigner = rawKeySigner(secp.utils.randomPrivateKey());
    const creatorPub = creatorSigner.publicKey();
    const granteePub = granteeSigner.publicKey();

    const creator = new ActBeeWrapper({ bee, signer: creatorSigner });
    const grantee = new ActBeeWrapper({ bee, signer: granteeSigner });

    const created = await creator.createGrantees(STAMP!, [
      creatorPub,
      granteePub,
    ]);
    expect(created.ref).toBeInstanceOf(Uint8Array);
    expect(created.historyref).toBeInstanceOf(Uint8Array);

    const listedBefore = await creator.getGrantees(created.ref);
    expect(containsPubkey(listedBefore.grantees, creatorPub)).toBe(true);
    expect(containsPubkey(listedBefore.grantees, granteePub)).toBe(true);

    const oldPayload = new TextEncoder().encode(`before-revoke:${Date.now()}`);
    const oldUploaded = await creator.uploadData(STAMP!, oldPayload, {
      actHistoryAddress: created.historyref,
    });
    const tsBeforeRevoke = Math.floor(Date.now() / 1000);
    expect(oldUploaded.historyAddress).toEqual(created.historyref);

    // Ensure the revoke entry lands in a strictly later second than
    // tsBeforeRevoke so history lookup at tsBeforeRevoke can't resolve to it.
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const patched = await creator.patchGrantees(
      STAMP!,
      created.ref,
      created.historyref,
      { revoke: [granteePub] },
    );

    const listedAfter = await creator.getGrantees(patched.ref);
    expect(containsPubkey(listedAfter.grantees, creatorPub)).toBe(true);
    expect(containsPubkey(listedAfter.grantees, granteePub)).toBe(false);

    const oldReadAtTimestamp = await grantee.downloadData(
      oldUploaded.reference.toUint8Array(),
      {
        actPublisher: creatorPub,
        actHistoryAddress: patched.historyref,
        actTimestamp: tsBeforeRevoke,
      },
    );
    expect(oldReadAtTimestamp.toUint8Array()).toEqual(oldPayload);

    await expect(
      grantee.downloadData(oldUploaded.reference.toUint8Array(), {
        actPublisher: creatorPub,
        actHistoryAddress: patched.historyref,
      }),
    ).rejects.toThrow(/NOT_FOUND/);
  });
});

describe("ActBeeWrapper option pass-through", () => {
  it("forwards requestOptions to underlying Bee calls", async () => {
    const calls: Array<{ method: string; requestOptions: unknown }> = [];
    const bee = {
      async uploadData(
        _stamp: string | Uint8Array,
        _data: Uint8Array,
        _options?: Record<string, unknown>,
        requestOptions?: unknown,
      ) {
        calls.push({ method: "uploadData", requestOptions });
        return {
          reference: { toUint8Array: () => new Uint8Array(32).fill(1) },
        };
      },
      async downloadData(
        _ref: Uint8Array,
        _options?: Record<string, unknown>,
        requestOptions?: unknown,
      ) {
        calls.push({ method: "downloadData", requestOptions });
        // Empty grantee list — valid wire format, no crypto needed.
        return { toUint8Array: () => new Uint8Array(0) };
      },
    };

    const wrapper = new ActBeeWrapper({
      bee: bee as unknown as Bee,
      signer: rawKeySigner(secp.utils.randomPrivateKey()),
    });

    await wrapper.getGrantees(new Uint8Array(32).fill(1), { timeoutMs: 2 });

    expect(calls).toEqual([
      { method: "downloadData", requestOptions: { timeoutMs: 2 } },
    ]);
  });
});

function containsPubkey(list: Uint8Array[], candidate: Uint8Array): boolean {
  return list.some(
    (pk) =>
      pk.length === candidate.length && pk.every((b, i) => b === candidate[i]),
  );
}

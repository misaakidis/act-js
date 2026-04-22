import * as secp from "@noble/secp256k1";
import { describe, expect, it } from "vitest";
import {
  containsPubkey,
  deserializeGranteeList,
  removePubkey,
  serializeGranteeList,
} from "../src/grantee/grantee-list.js";

describe("grantee-list", () => {
  const pk = () => secp.getPublicKey(secp.utils.randomPrivateKey(), false);

  it("roundtrips a list", () => {
    const list = [pk(), pk(), pk()];
    const encoded = serializeGranteeList(list);
    expect(encoded.length).toBe(list.length * 65);
    const decoded = deserializeGranteeList(encoded);
    expect(decoded).toEqual(list);
  });

  it("rejects invalid pubkey length", () => {
    expect(() => serializeGranteeList([new Uint8Array(33)])).toThrow();
  });

  it("rejects non-0x04 prefix", () => {
    const bad = new Uint8Array(65);
    bad[0] = 0x02;
    expect(() => serializeGranteeList([bad])).toThrow();
  });

  it("rejects data not multiple of 65", () => {
    expect(() => deserializeGranteeList(new Uint8Array(100))).toThrow();
  });

  it("containsPubkey and removePubkey use byte equality", () => {
    const a = pk();
    const b = pk();
    const c = pk();
    const list = [a, b, c];
    expect(containsPubkey(list, b)).toBe(true);
    expect(removePubkey(list, b)).toEqual([a, c]);
  });
});

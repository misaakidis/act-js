import { describe, expect, it } from "vitest";
import {
  addHistoryEntry,
  collectHistoryEntries,
  createEmptyHistory,
  lookupHistory,
  pathToTimestamp,
  timestampToPath,
} from "../src/history/history.js";

describe("history", () => {
  it("inverts timestamps correctly", () => {
    expect(timestampToPath(1700000000)).toBe("9223372035154775807");
    expect(pathToTimestamp("9223372035154775807")).toBe(1700000000);
  });

  it("latest timestamp has lexicographically smallest key", () => {
    const earlier = timestampToPath(1000000000);
    const later = timestampToPath(2000000000);
    expect(later < earlier).toBe(true);
  });

  it("adds and looks up entries", () => {
    const root = createEmptyHistory();
    const ref1 = new Uint8Array(32).fill(0x11);
    const ref2 = new Uint8Array(32).fill(0x22);
    addHistoryEntry(root, { timestamp: 1000, kvsRef: ref1, metadata: {} });
    addHistoryEntry(root, { timestamp: 2000, kvsRef: ref2, metadata: {} });
    expect(lookupHistory(root, 1500)?.kvsRef).toEqual(ref1);
    expect(lookupHistory(root, 2500)?.kvsRef).toEqual(ref2);
    expect(lookupHistory(root, 500)).toBeNull();
  });

  it("preserves metadata", () => {
    const root = createEmptyHistory();
    addHistoryEntry(root, {
      timestamp: 1000,
      kvsRef: new Uint8Array(32).fill(1),
      metadata: { encryptedglref: "abc123" },
    });
    const entries = collectHistoryEntries(root);
    expect(entries[0].metadata).toEqual({ encryptedglref: "abc123" });
  });

  it("throws on duplicate timestamps", () => {
    const root = createEmptyHistory();
    addHistoryEntry(root, {
      timestamp: 1000,
      kvsRef: new Uint8Array(32),
      metadata: {},
    });
    expect(() =>
      addHistoryEntry(root, {
        timestamp: 1000,
        kvsRef: new Uint8Array(32).fill(1),
        metadata: {},
      }),
    ).toThrow();
  });
});

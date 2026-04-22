import type { BatchId } from "@ethersphere/bee-js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  applyGranteePatch,
  buildAccessManifest,
  ensurePublisherIncluded,
} from "./act-core.js";
import { decrypt, encrypt } from "./crypto/cipher.js";
import { deriveKvsKeys } from "./crypto/ecdh.js";
import {
  deserializeGranteeList,
  serializeGranteeList,
} from "./grantee/grantee-list.js";
import { SwarmHistoryStore } from "./history/history.js";
import { downloadKvs, manifestGet, uploadKvs } from "./kvs/kvs.js";
import type { ActSigner } from "./signer.js";
import type {
  BeeDataClient,
  HistoryResult,
  HistorySnapshot,
  HistoryStore,
  PublicKeyBytes,
  SwarmRef,
} from "./types.js";

function randomAccessKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export interface ActClientOptions {
  bee: BeeDataClient;
  /** Postage batch. Required for writes (create, patchGrantees).
   *  May be omitted for read-only clients that only call decryptRef. */
  stamp?: BatchId | string;
  historyStore?: HistoryStore;
}

export interface CreateArgs {
  signer: ActSigner;
  grantees: PublicKeyBytes[];
}

export interface GranteeResult extends HistoryResult {
  /** Swarm ref to the plaintext serialized grantee list (bee-js parity: `ref`). */
  granteeListRef: SwarmRef;
}

export interface ActCreateResult extends GranteeResult {}

export interface PublisherContextArgs {
  signer: ActSigner;
  historyRef: SwarmRef;
}

export interface GranteeContextArgs {
  signer: ActSigner;
  publisherPub: PublicKeyBytes;
  historyRef: SwarmRef;
  /** Unix seconds — select a past history entry (for reading content posted before revocation). */
  atUnixSec?: number;
}

export class ActClient {
  private readonly historyStore: HistoryStore;

  constructor(private opts: ActClientOptions) {
    this.historyStore = opts.historyStore ?? new SwarmHistoryStore(opts.bee);
  }

  async create(args: CreateArgs): Promise<ActCreateResult> {
    const stamp = this.requireStamp();
    const accessKey = randomAccessKey();
    const publisherPub = args.signer.publicKey();

    const allGrantees = ensurePublisherIncluded(publisherPub, args.grantees);
    const kvs = buildAccessManifest(args.signer, allGrantees, accessKey);

    const kvsRef = await uploadKvs(this.opts.bee, stamp, kvs);
    const { granteeListRef, encryptedRef } = await this.saveGranteeList(
      args.signer,
      stamp,
      allGrantees,
    );

    const history = await this.historyStore.createEmpty();
    await this.appendHistoryEntry(history, {
      kvsRef,
      metadata: { encryptedglref: bytesToHex(encryptedRef) },
    });

    const historyRef = await this.historyStore.save(history, stamp);
    return { historyRef, granteeListRef };
  }

  async encryptRef(
    ref: SwarmRef,
    args: PublisherContextArgs,
  ): Promise<SwarmRef> {
    const accessKey = await this.getAccessKey(
      args.signer,
      args.signer.publicKey(),
      args.historyRef,
    );
    return encrypt(ref, accessKey, 0);
  }

  async reencryptRef(
    newRef: SwarmRef,
    args: GranteeContextArgs,
  ): Promise<SwarmRef> {
    const accessKey = await this.getAccessKey(
      args.signer,
      args.publisherPub,
      args.historyRef,
      args.atUnixSec,
    );
    return encrypt(newRef, accessKey, 0);
  }

  async decryptRef(
    encRef: SwarmRef,
    args: GranteeContextArgs,
  ): Promise<SwarmRef> {
    const accessKey = await this.getAccessKey(
      args.signer,
      args.publisherPub,
      args.historyRef,
      args.atUnixSec,
    );
    return decrypt(encRef, accessKey, 0);
  }

  /**
   * Add and/or revoke grantees in one atomic history step.
   * Mirrors bee-js's `patchGrantees(stamp, ref, historyRef, { add, revoke })`.
   *
   * Adding a grantee that is already present is a no-op.
   * Revoking generates a fresh access key so the removed party cannot decrypt
   * content encrypted after revocation.
   */
  async patchGrantees(
    grantees: { add?: PublicKeyBytes[]; revoke?: PublicKeyBytes[] },
    args: PublisherContextArgs,
  ): Promise<GranteeResult> {
    const stamp = this.requireStamp();
    const toAdd = grantees.add ?? [];
    const toRevoke = grantees.revoke ?? [];
    if (toAdd.length === 0 && toRevoke.length === 0) {
      const current = await this.getGrantees(args);
      const { granteeListRef } = await this.saveGranteeList(
        args.signer,
        stamp,
        current,
      );
      return { historyRef: args.historyRef, granteeListRef };
    }

    const currentGrantees = await this.getGrantees(args);
    const { nextGrantees: next, revoking } = applyGranteePatch(
      currentGrantees,
      { add: toAdd, revoke: toRevoke },
    );

    // Only rotate the access key when revoking; adds can reuse the existing one.
    const accessKey = revoking
      ? randomAccessKey()
      : await this.getAccessKey(
          args.signer,
          args.signer.publicKey(),
          args.historyRef,
        );

    const kvs = buildAccessManifest(args.signer, next, accessKey);

    const kvsRef = await uploadKvs(this.opts.bee, stamp, kvs);
    const { granteeListRef, encryptedRef } = await this.saveGranteeList(
      args.signer,
      stamp,
      next,
    );

    const history = await this.historyStore.load(args.historyRef);
    await this.appendHistoryEntry(history, {
      kvsRef,
      metadata: { encryptedglref: bytesToHex(encryptedRef) },
    });

    return {
      historyRef: await this.historyStore.save(history, stamp),
      granteeListRef,
    };
  }

  /**
   * Retrieve the current grantee list.
   * Mirrors bee-js's `getGrantees(ref)`.
   */
  async getGrantees(args: PublisherContextArgs): Promise<PublicKeyBytes[]> {
    const history = await this.historyStore.load(args.historyRef);
    const entry = this.historyStore.lookupAt(
      history,
      Math.floor(Date.now() / 1000),
    );
    if (!entry) return [];

    const encGlRefHex = entry.metadata.encryptedglref;
    if (!encGlRefHex) return [];

    const [, publisherAKDec] = deriveKvsKeys(
      args.signer.ecdhSharedX(args.signer.publicKey()),
    );

    // The stored value is the encrypted 32-byte Swarm reference to the plaintext list.
    const granteeRef = decrypt(hexToBytes(encGlRefHex), publisherAKDec, 0);
    const plaintextBytes = await this.opts.bee.downloadData(granteeRef);
    return deserializeGranteeList(plaintextBytes.toUint8Array());
  }

  /**
   * Upload the plaintext grantee list to Swarm, then encrypt its 32-byte reference
   * with the publisher's self-ECDH key. This matches Bee's encryptRefForPublisher wire format.
   */
  private async saveGranteeList(
    signer: ActSigner,
    stamp: BatchId | string,
    grantees: PublicKeyBytes[],
  ): Promise<{ granteeListRef: SwarmRef; encryptedRef: SwarmRef }> {
    const plaintext = serializeGranteeList(grantees);
    const uploaded = await this.opts.bee.uploadData(stamp, plaintext);
    const granteeListRef = uploaded.reference.toUint8Array();

    const [, publisherAKDec] = deriveKvsKeys(
      signer.ecdhSharedX(signer.publicKey()),
    );
    return {
      granteeListRef,
      encryptedRef: encrypt(granteeListRef, publisherAKDec, 0),
    };
  }

  private requireStamp(): BatchId | string {
    if (this.opts.stamp === undefined) {
      throw new Error("ACT: stamp required for write operations");
    }
    return this.opts.stamp;
  }

  private async getAccessKey(
    signer: ActSigner,
    publisherPub: PublicKeyBytes,
    historyRef: SwarmRef,
    atUnixSec?: number,
  ): Promise<Uint8Array> {
    const [lookupKey, accessKeyDecryptionKey] = deriveKvsKeys(
      signer.ecdhSharedX(publisherPub),
    );
    const history = await this.historyStore.load(historyRef);
    const entry = this.historyStore.lookupAt(
      history,
      atUnixSec ?? Math.floor(Date.now() / 1000),
    );
    if (!entry) throw new Error("ACT: no history entries");

    const kvs = await downloadKvs(this.opts.bee, entry.kvsRef);
    const encAccessKey = manifestGet(kvs, lookupKey);
    if (!encAccessKey) {
      const err = new Error(
        "NOT_FOUND: grantee not present in KVS",
      ) as Error & { code?: string };
      err.code = "NOT_FOUND";
      throw err;
    }

    return decrypt(encAccessKey, accessKeyDecryptionKey, 0);
  }

  /**
   * Append a history entry stamped with the current second.
   *
   * Must not produce a future-dated timestamp: callers decrypt at
   * `Date.now()/1000`, and an entry dated ahead of wall-clock would be
   * invisible — allowing a just-revoked grantee to keep access until the
   * clock catches up. When a same-second collision occurs (two rapid
   * operations), sleep until the clock advances past the most recent entry
   * so the new entry gets a real timestamp strictly greater than all prior
   * entries and no later than `Date.now()/1000`.
   */
  private async appendHistoryEntry(
    history: HistorySnapshot,
    entry: { kvsRef: SwarmRef; metadata: Record<string, string> },
  ): Promise<void> {
    const maxExisting = history.entries.reduce(
      (m, e) => (e.timestamp > m ? e.timestamp : m),
      -Infinity,
    );
    let ts = Math.floor(Date.now() / 1000);
    while (ts <= maxExisting) {
      const waitMs = (maxExisting - ts + 1) * 1000 + 50;
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      ts = Math.floor(Date.now() / 1000);
    }
    await this.historyStore.append(history, {
      timestamp: ts,
      kvsRef: entry.kvsRef,
      metadata: entry.metadata,
    });
  }
}

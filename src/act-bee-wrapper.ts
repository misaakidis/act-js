import type { BatchId } from "@ethersphere/bee-js";
import * as secp from "@noble/secp256k1";
import { hexToBytes } from "@noble/hashes/utils";
import { ActClient } from "./act.js";
import type { ActSigner } from "./signer.js";
import type {
  ActBeeDownloadOptions,
  ActBeeGetGranteesResult,
  ActBeeGranteesResult,
  ActBeePatchGranteesArgs,
  ActBeeUploadOptions,
  ActBeeUploadResult,
  BeeDataClient,
  ByteArrayLike,
  HistoryStore,
  PublicKeyBytes,
  PublicKeyInput,
  ReferenceInput,
  SwarmRef,
  UploadDataResultLike,
} from "./types.js";
import { deserializeGranteeList } from "./grantee/grantee-list.js";

type BeeClientWithOptions = BeeDataClient & {
  uploadData(
    stamp: BatchId | Uint8Array | string,
    data: Uint8Array,
    options?: Record<string, unknown>,
    requestOptions?: unknown,
  ): Promise<UploadDataResultLike>;
  downloadData(
    reference: SwarmRef,
    options?: Record<string, unknown>,
    requestOptions?: unknown,
  ): Promise<ByteArrayLike>;
};

export interface ActBeeWrapperOptions {
  bee: BeeClientWithOptions;
  signer: ActSigner;
  historyStore?: HistoryStore;
}

/**
 * ACT-scoped wrapper around a Bee client.
 *
 * Every method on this class performs an ACT operation. Method names and
 * argument order mirror bee-js's ACT endpoints so migration is mechanical.
 * For plain (non-ACT) uploads or downloads, use the Bee client directly —
 * this wrapper exists only to replace bee-js's server-side ACT.
 *
 * Stateless: every call is independent. All crypto delegates to ActClient.
 */
export class ActBeeWrapper {
  constructor(private readonly opts: ActBeeWrapperOptions) {}

  async createGrantees(
    postageBatchId: BatchId | Uint8Array | string,
    grantees: PublicKeyInput[],
    requestOptions?: unknown,
  ): Promise<ActBeeGranteesResult> {
    const act = this.makeActClient(postageBatchId, requestOptions);
    const { historyRef, granteeListRef } = await act.create({
      signer: this.opts.signer,
      grantees: grantees.map(normalizePublicKey),
    });
    return { ref: granteeListRef, historyref: historyRef };
  }

  async getGrantees(
    reference: ReferenceInput,
    requestOptions?: unknown,
  ): Promise<ActBeeGetGranteesResult> {
    const data = await this.opts.bee.downloadData(
      normalizeRef(reference),
      undefined,
      requestOptions,
    );
    return { grantees: deserializeGranteeList(data.toUint8Array()) };
  }

  async patchGrantees(
    postageBatchId: BatchId | Uint8Array | string,
    _reference: ReferenceInput,
    history: ReferenceInput,
    grantees: ActBeePatchGranteesArgs,
    requestOptions?: unknown,
  ): Promise<ActBeeGranteesResult> {
    const historyRef = normalizeRef(history);
    const act = this.makeActClient(postageBatchId, requestOptions);
    const { historyRef: newHistoryRef, granteeListRef } =
      await act.patchGrantees(
        {
          add: grantees.add?.map(normalizePublicKey),
          revoke: grantees.revoke?.map(normalizePublicKey),
        },
        { signer: this.opts.signer, historyRef },
      );
    return { ref: granteeListRef, historyref: newHistoryRef };
  }

  /**
   * Upload data under an existing ACT history, returning an ACT-encrypted
   * reference. Create the history first with `createGrantees`.
   */
  async uploadData(
    postageBatchId: BatchId | Uint8Array | string,
    data: Uint8Array,
    options: ActBeeUploadOptions,
  ): Promise<ActBeeUploadResult> {
    const historyRef = normalizeRef(options.actHistoryAddress);
    const requestOptions = options.requestOptions;

    const uploaded = await this.opts.bee.uploadData(
      postageBatchId,
      data,
      stripActUploadOptions(options),
      requestOptions,
    );
    const act = this.makeActClient(postageBatchId, requestOptions);
    const encryptedRef = await act.encryptRef(
      uploaded.reference.toUint8Array(),
      { signer: this.opts.signer, historyRef },
    );

    return {
      ...uploaded,
      reference: toByteArrayLike(encryptedRef),
      historyAddress: historyRef,
    };
  }

  /**
   * Download and decrypt data protected by an ACT history. `actHistoryAddress`
   * is required; `actPublisher` defaults to the signer's own public key.
   */
  async downloadData(
    reference: ReferenceInput,
    options: ActBeeDownloadOptions,
  ): Promise<ByteArrayLike> {
    const historyRef = normalizeRef(options.actHistoryAddress);
    const requestOptions = options.requestOptions;
    const publisherPub = options.actPublisher
      ? normalizePublicKey(options.actPublisher)
      : this.opts.signer.publicKey();

    const act = this.makeActClient(undefined, requestOptions);
    const plainRef = await act.decryptRef(normalizeRef(reference), {
      signer: this.opts.signer,
      publisherPub,
      historyRef,
      atUnixSec: parseActTimestamp(options.actTimestamp),
    });
    return this.opts.bee.downloadData(
      plainRef,
      stripActDownloadOptions(options),
      requestOptions,
    );
  }

  private makeActClient(
    stamp: BatchId | Uint8Array | string | undefined,
    requestOptions?: unknown,
  ): ActClient {
    return new ActClient({
      bee: this.withRequestOptions(requestOptions),
      stamp: stamp === undefined ? undefined : normalizeStamp(stamp),
      historyStore: this.opts.historyStore,
    });
  }

  private withRequestOptions(requestOptions?: unknown): BeeDataClient {
    if (requestOptions === undefined) return this.opts.bee;
    return {
      uploadData: async (stamp, data) =>
        this.opts.bee.uploadData(stamp, data, undefined, requestOptions),
      downloadData: async (reference) =>
        this.opts.bee.downloadData(reference, undefined, requestOptions),
    };
  }
}

function parseActTimestamp(
  value: string | number | undefined,
): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "number") return Math.floor(value);
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`ACT: invalid actTimestamp value '${value}'`);
  }
  return Math.floor(parsed);
}

function normalizeStamp(
  stamp: BatchId | Uint8Array | string,
): BatchId | string {
  if (typeof stamp === "string") return stripHex(stamp);
  if (stamp instanceof Uint8Array) {
    return Array.from(stamp, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  return stamp;
}

function normalizeRef(input: ReferenceInput): SwarmRef {
  if (input instanceof Uint8Array) return input;
  return hexToBytes(stripHex(input));
}

function normalizePublicKey(input: PublicKeyInput): PublicKeyBytes {
  const bytes =
    input instanceof Uint8Array ? input : hexToBytes(stripHex(input));

  if (bytes.length === 65 && bytes[0] === 0x04) return bytes;
  if (bytes.length === 64) {
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(bytes, 1);
    return out;
  }
  if (bytes.length === 33) {
    return secp.Point.fromHex(bytes).toRawBytes(false);
  }

  throw new Error(
    `ACT: unsupported public key format (length=${bytes.length})`,
  );
}

function stripHex(input: string): string {
  return input.startsWith("0x") ? input.slice(2) : input;
}

function toByteArrayLike(bytes: Uint8Array): ByteArrayLike {
  return { toUint8Array: () => bytes };
}

function stripActUploadOptions(
  options: ActBeeUploadOptions,
): Record<string, unknown> {
  const { actHistoryAddress: _h, requestOptions: _r, ...rest } = options;
  return rest;
}

function stripActDownloadOptions(
  options: ActBeeDownloadOptions,
): Record<string, unknown> {
  const {
    actHistoryAddress: _h,
    actPublisher: _p,
    actTimestamp: _t,
    requestOptions: _r,
    ...rest
  } = options;
  return rest;
}

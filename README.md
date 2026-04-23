# act-js

TypeScript implementation of Swarm's Access Control Trie (ACT). Grant encrypted access to content on public storage, revoke it later — without handing your private key to a Bee node.

---

## What is ACT?

[Swarm](https://ethswarm.org) is content-addressed public storage: anyone who has a 32-byte reference can fetch the blob at that address. ACT lets you share content with specific recipients by encrypting the *reference* rather than the content itself. What you hand out looks like random bytes; only listed recipients (**grantees**) can turn it back into a fetchable reference using their private keys.

The protocol is small:

1. The publisher picks a random **access key**. Any reference encrypted with it is useless without the key.
2. For each grantee's public key, the publisher runs an ECDH with their own private key and derives a per-grantee encryption of the access key. These encrypted copies live in a shared manifest keyed by lookups derived from the same ECDH.
3. Sharing a reference = encrypting it with the access key and handing out the ciphertext.
4. A grantee derives the same ECDH from *their* private key, finds their encrypted access key in the manifest, decrypts it, then decrypts the reference.
5. Revoking a grantee = rotating the access key and rebuilding the manifest without that entry. Subsequent encryptions are unreadable to them.
6. Every manifest snapshot is recorded in a time-indexed **history**, which is how a grantee can still read content protected *before* they were revoked.

That's it. No third-party key service, no on-chain registry — just ECDH and a key-value manifest.

## Why this library?

bee-js exposes ACT as HTTP endpoints on a Bee node, which means the node holds your private key. That's workable for a single-operator server but a non-starter for browsers, wallets, mobile apps, or any deployment where end users own their keys.

`act-js` runs the same protocol in your process, against a pluggable **signer** that never needs to surface raw key bytes. It is **wire-compatible** with bee-go — references produced here are decryptable by any Bee node, and references produced by a Bee node are decryptable here. A round-trip integration test against a real Bee node ships in [`test/wire-compat.test.ts`](./test/wire-compat.test.ts).

## Use cases

- End-to-end encrypted file sharing with per-recipient grants.
- Collaborative documents where the reader set changes over time.
- Access-gated publishing — newsletters, course material — revocable per subscriber.
- Per-device encrypted backups where you can revoke a compromised device.
- Multi-writer resources where one party updates content without the publisher's key online.

---

## Install

```bash
npm install @nook/act-js @ethersphere/bee-js
```

## Quick start: Alice shares a document with Bob

Two separate processes, typically on separate machines. Neither private key ever leaves its owner.

### Alice publishes

```ts
import { Bee } from "@ethersphere/bee-js";
import { ActBeeWrapper, rawKeySigner } from "@nook/act-js";

const bee = new Bee("http://localhost:1633");
const alice = rawKeySigner(alicePrivKey);
const wrapper = new ActBeeWrapper({ bee, signer: alice });

// Create the ACT. Alice is auto-included; Bob is added explicitly.
// `ref` is sensitive — see the access model below.
const { ref, historyref } = await wrapper.createGrantees(stamp, [bobPubKey]);

// Upload under that ACT. `uploaded.reference` is ACT-encrypted.
const uploaded = await wrapper.uploadData(stamp, documentBytes, {
  actHistoryAddress: historyref,
});

// Give Bob: uploaded.reference, historyref, alice.publicKey().
// Keep `ref` on Alice's side.
```

### Bob reads

```ts
import { Bee } from "@ethersphere/bee-js";
import { ActBeeWrapper, rawKeySigner } from "@nook/act-js";

const bee = new Bee("http://localhost:1633");
const bob = rawKeySigner(bobPrivKey);
const wrapper = new ActBeeWrapper({ bee, signer: bob });

const document = await wrapper.downloadData(encryptedRef, {
  actHistoryAddress: historyref,
  actPublisher: alicePubKey,
});
```

### Alice revokes Bob

```ts
const { historyref: newHistoryref } = await wrapper.patchGrantees(
  stamp,
  ref,
  historyref,
  { revoke: [bobPubKey] },
);
```

Anything Alice uploads under `newHistoryref` is unreadable to Bob. What he already decrypted is in the clear on his machine.

### Bob reads pre-revoke content

```ts
await wrapper.downloadData(encryptedRef, {
  actHistoryAddress: newHistoryref,
  actPublisher: alicePubKey,
  actTimestamp: unixSecBeforeRevoke,
});
```

---

## The access model

**Forward-only revocation.** Revoking rotates the access key for *future* encryptions. Content a revoked party already decrypted is theirs; there is no cryptographic "unshare." If you need old content to become unreachable, revoke *and* re-publish a fresh copy, stopping distribution of the old reference.

**Past-timestamp reads are by design.** The history is a timeline of grantee → access-key snapshots. Pinning a lookup to a past timestamp selects the snapshot in force at that moment, so content stays reachable across membership changes. If you need "revoked means immediately unreadable," ACT alone is the wrong primitive.

**Trust boundaries:**

- **Publisher** — the authority. Adds, revokes, rotates.
- **Grantees** — trusted to protect their own keys. Once they decrypt, content is theirs.
- **Storage backend** — untrusted for key material. Sees only ciphertext references and opaque blobs. That's why this library runs the crypto in the caller's process.
- **Anyone who learns `ref`** — sees the full grantee list. Keep it publisher-private.

**What ACT does not hide:**

- That an upload happened — the storage layer is content-addressed and public.
- The grantee set, if `ref` leaks.
- Operation timing — history entries carry second-resolution UNIX timestamps.
- Correlation across uploads by the same publisher.

ACT gates decryption of *references*. If you also need the stored bytes themselves encrypted at rest, layer that on top — it's independent.

---

## API

### `ActBeeWrapper`

bee-js-shaped convenience. One method per bee-js ACT endpoint, same argument order, delegating all crypto to `ActClient`:

| Method                                                      | Purpose                                               |
| ----------------------------------------------------------- | ----------------------------------------------------- |
| `createGrantees(stamp, grantees)`                           | Start a new ACT. Publisher auto-included.             |
| `patchGrantees(stamp, ref, history, { add?, revoke? })`     | Add and/or revoke grantees. Rotates key on revoke.    |
| `getGrantees(ref)`                                          | Fetch the current grantee list (publisher).           |
| `uploadData(stamp, data, { actHistoryAddress, … })`         | Upload and ACT-encrypt the returned reference.        |
| `downloadData(ref, { actHistoryAddress, actPublisher?, actTimestamp?, … })` | Decrypt and fetch. |

Every method here performs an ACT operation. For plain uploads and downloads, call your Bee client directly.

### `ActClient` — the lower-level API

Use `ActClient` when you want a surface free of bee-js vocabulary:

```ts
const act = new ActClient({ bee, stamp });

await act.create({ signer, grantees });
await act.encryptRef(ref, { signer, historyRef });
await act.decryptRef(encRef, { signer, publisherPub, historyRef, atUnixSec? });
await act.reencryptRef(newRef, { signer, publisherPub, historyRef });
await act.patchGrantees({ add, revoke }, { signer, historyRef });
await act.getGrantees({ signer, historyRef });
```

- `signer` is per-call, not per-client. One `ActClient` can serve many identities.
- `stamp` is only required for writes (`create`, `patchGrantees`); omit for read-only clients.
- `reencryptRef` lets a grantee protect a new reference without the publisher's key — needed for multi-writer flows.

### `ActSigner` — identity

Every operation takes a `signer`. The interface exposes the two verbs ACT needs and nothing else:

```ts
interface ActSigner {
  publicKey(): PublicKeyBytes;                       // 65-byte uncompressed
  ecdhSharedX(otherPub: PublicKeyBytes): Uint8Array; // raw minimally-encoded X
}
```

- `rawKeySigner(priv)` for in-memory keys.
- For keys in a wallet, hardware enclave, or remote signer, implement those two methods against your backend. Raw private-key bytes never have to leave the wallet.

### Values glossary

| Name           | Meaning                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `stamp`        | Swarm postage batch ID. Pays for uploads. Same as in bee-js.                                                                                     |
| `ref`          | 32-byte Swarm address of the **plaintext** grantee list. Sensitive — anyone with `ref` fetches the list. Grantees can't derive it from `historyref`. |
| `historyref`   | 32-byte reference to the ACT history (timeline of access-manifest snapshots). Advances on every grant/revoke.                                    |
| `actPublisher` | The ACT creator's public key. Grantees supply this to decrypt. Defaults to the signer's own key.                                                 |
| `actTimestamp` | Unix seconds. Pins a download to a past history snapshot.                                                                                        |
| `signer`       | An `ActSigner`. Use `rawKeySigner(priv)` for in-memory keys.                                                                                     |

---

## Internals

- **`act-core.ts`** — pure, deterministic ACT computations: grantee-set transitions, access-key rotation rules, access-manifest construction. No I/O.
- **`HistoryStore`** — injectable I/O seam for ACT history. `SwarmHistoryStore` (Mantaray-encoded) is the default; swap it for tests or non-Swarm backends.
- KVS chunks and grantee-list blobs go through the Bee client directly — no ACT-specific envelope beyond what's described in the access model.
- Wire-format parity verified in both directions in [`test/wire-compat.test.ts`](./test/wire-compat.test.ts).

## Development

```bash
npm install
npm run check:types
npm test    # unit tests only

# Integration + wire-compat tests need a Bee node and a usable stamp:
BEE_URL=http://localhost:1633 BEE_STAMP=<batch-id> npm test
```

## Package layout

- `src/signer.ts` — `ActSigner`, `rawKeySigner`
- `src/act.ts` — `ActClient`
- `src/act-core.ts` — pure ACT computations
- `src/act-bee-wrapper.ts` — `ActBeeWrapper`
- `src/crypto/` — cipher, ECDH
- `src/grantee/` — grantee-list codec
- `src/kvs/` — SimpleManifest KVS
- `src/history/` — Mantaray history
- `src/types.ts` — shared types, I/O-boundary interfaces

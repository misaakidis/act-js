# act-js

Share encrypted content on [Swarm](https://ethswarm.org) with named recipients — and revoke that access later — without giving anyone your private key.

Swarm's [Access Control Trie (ACT)](https://docs.ethswarm.org/docs/develop/access-control) is normally run by a Bee node that holds the publisher's private key. `act-js` does the same work client-side: the Bee node becomes a plain storage backend and never sees key material. Wire-compatible with Bee — refs produced by `act-js` are decryptable by a Bee node, and vice versa.

## Install

```bash
npm install @nook/act-js @ethersphere/bee-js
```

## Example: Alice shares a document with Bob

The two sides run in separate processes. They exchange only public data.

### On Alice's machine (publisher)

```ts
import { Bee } from "@ethersphere/bee-js";
import { ActClient, rawKeySigner } from "@nook/act-js";

const bee = new Bee("http://localhost:1633");
const act = new ActClient({ bee, stamp });
const alice = rawKeySigner(alicePrivKey); // her key, never leaves this process

// Bob's public key is how Alice received his identity (out of band).
const { historyRef } = await act.create({
  signer: alice,
  grantees: [bobPubKey], // Alice is auto-included
});

const { reference } = await bee.uploadData(stamp, documentBytes);
const encRef = await act.encryptRef(reference.toUint8Array(), {
  signer: alice,
  historyRef,
});

// Send Bob: encRef, historyRef, alice.publicKey()
```

### On Bob's machine (grantee)

```ts
import { Bee } from "@ethersphere/bee-js";
import { ActClient, rawKeySigner } from "@nook/act-js";

const bee = new Bee("http://localhost:1633");
const act = new ActClient({ bee }); // no stamp needed — read-only
const bob = rawKeySigner(bobPrivKey); // his key, never leaves this process

const plainRef = await act.decryptRef(encRef, {
  signer: bob,
  publisherPub: alicePubKey,
  historyRef,
});
const document = await bee.downloadData(plainRef);
```

### Later: Alice revokes Bob

```ts
const { historyRef: newHistoryRef } = await act.patchGrantees(
  { revoke: [bobPubKey] },
  { signer: alice, historyRef },
);
```

ACT rotates its access key on revoke. Anything Alice protects under `newHistoryRef` is unreadable to Bob. Content he already decrypted with `historyRef` is still his — that's in the clear on his machine now.

## `ActClient` API

| Method                                                       | What it does                                                  | Stamp needed |
| ------------------------------------------------------------ | ------------------------------------------------------------- | ------------ |
| `create({ signer, grantees })`                               | Start a new ACT. Publisher is auto-included.                  | yes          |
| `patchGrantees({ add, revoke }, { signer, historyRef })`     | Atomically add and/or revoke grantees. Rotates key on revoke. | yes          |
| `getGrantees({ signer, historyRef })`                        | List current grantees (publisher only).                       | no           |
| `encryptRef(ref, { signer, historyRef })`                    | Protect a Swarm reference (publisher only).                   | no           |
| `decryptRef(encRef, { signer, publisherPub, historyRef })`   | Unprotect a reference (any grantee).                          | no           |
| `reencryptRef(newRef, { signer, publisherPub, historyRef })` | Protect a new reference without the publisher's key.          | no           |

`decryptRef` and `reencryptRef` accept an optional `atUnixSec` to read at a past history entry — that's how a revoked grantee reads something protected before they were revoked, or how an out-of-date grantee reads during a concurrent update.

## `ActSigner` — where private keys live

```ts
interface ActSigner {
  publicKey(): PublicKeyBytes; // 65-byte uncompressed
  ecdhSharedX(otherPub: PublicKeyBytes): Uint8Array;
}
```

Only the two operations ACT actually needs. No method returns raw private key bytes, so the same interface works whether your key lives in memory, in a browser wallet, or in a hardware enclave — each environment implements the two methods however it can.

`rawKeySigner(priv)` handles the in-memory case. For wallet-backed keys, write a small adapter.

## `ActBeeWrapper` — bee-js-shaped migration path

If you're replacing bee-js's server-side ACT endpoints, `ActBeeWrapper` has the same method names and argument order:

```ts
import { ActBeeWrapper, rawKeySigner } from "@nook/act-js";

const wrapper = new ActBeeWrapper({ bee, signer: rawKeySigner(priv) });

const { ref, historyref } = await wrapper.createGrantees(stamp, [bobPub]);
const uploaded = await wrapper.uploadData(stamp, data, {
  actHistoryAddress: historyref,
});
const decrypted = await wrapper.downloadData(
  uploaded.reference.toUint8Array(),
  {
    actHistoryAddress: historyref,
    actPublisher: publisherPub, // defaults to signer's own pubkey
    actTimestamp: pastUnixSec, // optional: read at a past history entry
  },
);
```

Every method on this class performs an ACT operation — for plain uploads or downloads, call your Bee client directly. Prefer `ActClient` for new code.

## Internals

- `act-core.ts` — pure ACT computations: grantee-set transitions, access-key rotation rules, access manifest construction. Takes an `ActSigner`.
- `HistoryStore` — the I/O seam for ACT history. `SwarmHistoryStore` is the default (Mantaray-backed); custom implementations can be injected for tests or non-Swarm backends.
- KVS and grantee-list blobs go through `bee` directly; they're plain Swarm chunk uploads with no special encoding.

## Development

```bash
npm install
npm run check:types
npm test            # unit tests

# Integration + wire-compat tests need a running Bee node and a usable stamp:
BEE_URL=http://localhost:1633 BEE_STAMP=<batch-id> npm test
```

## Package layout

- `src/signer.ts` — `ActSigner` interface, `rawKeySigner` factory
- `src/act.ts` — `ActClient`
- `src/act-core.ts` — pure ACT computations
- `src/act-bee-wrapper.ts` — `ActBeeWrapper`
- `src/crypto/` — cipher, ECDH
- `src/grantee/` — grantee-list codec
- `src/kvs/` — SimpleManifest
- `src/history/` — Mantaray history
- `src/types.ts` — shared types and I/O-boundary interfaces

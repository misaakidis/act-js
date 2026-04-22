# act-js

`act-js` is a TypeScript library that implements Swarm Access Control Trie (ACT) entirely on the client. Private key material stays in the browser or application; the Bee node is used only for content storage and never receives keys or plaintext access tokens.

## Why client-side ACT?

Standard bee-js ACT delegates all cryptographic operations to a trusted Bee node, which holds the publisher private key. `act-js` eliminates that trust requirement: your key never leaves your process.

| Mode | Private key location | Who performs ACT crypto |
|---|---|---|
| bee-js ACT | Bee node | Bee node |
| act-js `ActClient` | App / browser | Client (TypeScript) |
| act-js `BeeClientWrapper` | App / browser | Client, bee-js API surface |

## What it provides

### Core primitives
- Bee-compatible XOR cipher for reference encryption/decryption.
- secp256k1 ECDH key derivation for ACT lookup and decryption keys.
- Grantee list codec (serialize/deserialize concatenated public keys).
- SimpleManifest KVS helpers for key-value storage.
- Mantaray history helpers with inverted-timestamp path encoding.

### High-level clients
- **`ActClient`** — explicit ACT orchestration: create, encrypt/decrypt refs, add/revoke grantees, read grantee lists.
- **`BeeClientWrapper`** — drop-in bee-js ACT facade: same method names and return shapes as bee-js, backed by `ActClient` internals.

## BeeClientWrapper

`BeeClientWrapper` is designed to replace bee-js ACT call sites with minimal code changes.

```ts
const wrapper = new BeeClientWrapper({ bee, identityPrivKey: myPrivKey })

// Mirrors bee-js
const { ref, historyref } = await wrapper.createGrantees(stamp, [pubKey1, pubKey2])
const result = await wrapper.uploadData(stamp, data, { act: true, actHistoryAddress: historyref })
const data = await wrapper.downloadData(encRef, { actPublisher: pubKey, actHistoryAddress: historyref })
```

Parity notes:
- Accepts and forwards `requestOptions` to underlying Bee calls.
- Enforces `reference`/`history` consistency in `patchGrantees` to prevent silent state mismatches.
- Returns bee-style response shapes with `ref`, `historyref`, `status`, `statusText`.
- `uploadData({ act: true })` defaults to **strict mode**: `actHistoryAddress` is required. Pass `actUploadMode: 'compat'` to allow implicit history creation on first ACT upload.

## Architecture

`ActClient` separates concerns at two boundaries:

- **Core logic** (`src/act-core.ts`): deterministic, pure ACT computations (grantee-set transitions, access key rotation decisions, KVS manifest construction).
- **Persistence** (`HistoryStore`, `BlobStore`): interfaces for history and blob I/O, currently backed by Swarm/Bee only. Non-Swarm adapters are future work.

## Development

```bash
npm install
npm run check:types
npm run build
npm test
```

Integration tests require a running Bee node and the `BEE_STAMP` environment variable.

## Package layout

- `src/crypto`: cipher + ECDH primitives
- `src/grantee`: grantee-list codec
- `src/kvs`: ACT key-value storage helpers
- `src/history`: history encoding and lookup
- `src/act-core.ts`: pure ACT domain logic
- `src/act.ts`: high-level `ActClient` orchestration
- `src/bee-client-wrapper.ts`: bee-js-compatible `BeeClientWrapper`
- `test/`: unit and integration tests

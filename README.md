# act-js

`act-js` is a TypeScript implementation of Swarm Access Control Trie (ACT) that moves all crypto to the client.

Unlike bee-js ACT — where a Bee node holds the private key and performs ACT operations server-side — `act-js` keeps private key material in the browser or application. The Bee node is used purely for content storage (`uploadData`/`downloadData`) and never receives key material or plaintext access keys.

## What it provides

- Bee-compatible XOR cipher utilities for reference encryption/decryption.
- secp256k1 ECDH key derivation for ACT lookup/decryption keys.
- Grantee list serialization/deserialization helpers.
- KVS helpers based on SimpleManifest JSON structure.
- History helpers built on Mantaray manifests with inverted timestamps.
- `ActClient`: explicit, low-level ACT orchestration with full crypto control.
- `HistoryStore` abstraction for ACT history persistence (default backend: `SwarmHistoryStore`).
- `BeeClientWrapper`: bee-js ACT-compatible wrapper (`createGrantees`, `getGrantees`, `patchGrantees`, ACT-aware `uploadData`/`downloadData`) for migrating existing call sites to client-side key custody.

`BeeClientWrapper` parity notes:
- Accepts bee-style `requestOptions` via wrapper methods/options and forwards them to underlying Bee data calls.
- Enforces `reference`/`history` consistency in `patchGrantees` to avoid silent mismatches.
- Uses deterministic bee-style response metadata (`201 Created` for `createGrantees`, `200 OK` for `getGrantees`/`patchGrantees`).
- `uploadData({ act: true })` defaults to strict mode: `actHistoryAddress` is required unless wrapper is created with `actUploadMode: 'compat'`.

Architecture notes:
- `ActClient` now separates deterministic ACT core logic from persistence boundaries.
- Current shipped backends remain Swarm/Bee only (`SwarmHistoryStore` + Bee-backed blob/KVS paths).
- Non-Swarm persistence adapters are intentionally future work.

## Trust model

| Mode | Private key location | Who does ACT crypto |
|---|---|---|
| bee-js ACT | Bee node (server-side) | Bee node |
| act-js `ActClient` | App / browser | Client (TypeScript) |
| act-js `BeeClientWrapper` | App / browser | Client (TypeScript), bee-js API surface |

With `BeeClientWrapper`, app code keeps calling familiar bee-js ACT methods while the Bee node acts as a zero-trust content store: it cannot decrypt content because it never holds the key.

## Project status

This repository is under active development and currently targets correctness and wire-compat behavior first.


## Development

```bash
npm install
npm run check:types
npm run build
npm test
```

## Package layout

- `src/crypto`: cipher + ECDH primitives
- `src/grantee`: grantee-list codec
- `src/kvs`: ACT key-value storage helpers
- `src/history`: history encoding and lookup
- `src/act.ts`: explicit ACT orchestration (`ActClient`)
- `src/bee-client-wrapper.ts`: bee-js-compatible wrapper (`BeeClientWrapper`)
- `test/`: unit and integration tests

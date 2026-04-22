# act-js

`act-js` is a TypeScript implementation of Swarm Access Control Trie (ACT) primitives with a browser-friendly API.

## What it provides

- Bee-compatible XOR cipher utilities for reference encryption/decryption.
- secp256k1 ECDH key derivation for ACT lookup/decryption keys.
- Grantee list serialization/deserialization helpers.
- KVS helpers based on SimpleManifest JSON structure.
- History helpers built on Mantaray manifests with inverted timestamps.
- High-level `ActClient` for creating, updating, and querying ACT state.

## Project status

This repository is under active development and currently targets correctness and wire-compat behavior first.

## API notes

- `ActClient` now depends on a minimal data-client contract (`BeeDataClient`) rather than a concrete `Bee` class.
  - A regular `bee-js` `Bee` instance is structurally compatible and works as-is.
- `create()` returns `{ historyRef }` only.
  - The access key is kept internal and derived/used inside client operations such as `encryptRef()` and `decryptRef()`.
- Public method signatures use semantic byte aliases from `src/types.ts` (`PrivateKeyBytes`, `PublicKeyBytes`, `SwarmRef`) to make key/ref intent explicit.

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
- `src/act.ts`: high-level client orchestration
- `test/`: unit and integration tests

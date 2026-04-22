# Fixture Regeneration

Use the Go helpers in this directory against a local Bee repository checkout to regenerate wire fixtures.

Set `BEE_REPO` to your Bee checkout path, then run:

```bash
export BEE_REPO=/path/to/bee
```

## Cipher fixtures

```bash
(cd "$BEE_REPO" && go run ../act-js/test/gen/cipher_fixtures.go) > test/fixtures/cipher.json
```

## ECDH fixtures

```bash
(cd "$BEE_REPO" && go run ../act-js/test/gen/ecdh_fixtures.go) > test/fixtures/ecdh.json
```

# Fixture Regeneration

Use small Go helpers against the Bee repo to regenerate wire fixtures.

## Cipher fixtures

1. Create `test/gen/cipher_fixtures.go` in this repository.
2. Run:

```bash
cd ../bee
go run ../act-js/test/gen/cipher_fixtures.go > ../act-js/test/fixtures/cipher.json
```

## ECDH fixtures

1. Create `test/gen/ecdh_fixtures.go` in this repository.
2. Run:

```bash
cd ../bee
go run ../act-js/test/gen/ecdh_fixtures.go > ../act-js/test/fixtures/ecdh.json
```

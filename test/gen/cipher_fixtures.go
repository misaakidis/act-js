package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"os"

	"github.com/ethersphere/bee/v2/pkg/encryption"
	"golang.org/x/crypto/sha3"
)

type cipherFixture struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	InitCtr    int    `json:"initCtr"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

func mustHex(s string) []byte {
	out, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("decode hex %q: %v", s, err)
	}
	return out
}

func encrypt(key []byte, initCtr int, plaintext []byte) []byte {
	enc := encryption.New(encryption.Key(key), 0, uint32(initCtr), sha3.NewLegacyKeccak256)
	out, err := enc.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("encrypt failed: %v", err)
	}
	return out
}

func main() {
	key := mustHex("8abf1502f557f15026716030fb6384792583daf39608a3cd02ff2f47e9bc6e49")

	fixtures := []cipherFixture{
		{
			Name:       "act-ref-encryption-v0",
			Key:        hex.EncodeToString(key),
			InitCtr:    0,
			Plaintext:  "39a5ea87b141fe44aa609c3327ecd896c0e2122897f5f4bbacf74db1033c5559",
			Ciphertext: hex.EncodeToString(encrypt(key, 0, mustHex("39a5ea87b141fe44aa609c3327ecd896c0e2122897f5f4bbacf74db1033c5559"))),
		},
		{
			Name:       "all-zero-single-block",
			Key:        hex.EncodeToString(key),
			InitCtr:    0,
			Plaintext:  "0000000000000000000000000000000000000000000000000000000000000000",
			Ciphertext: hex.EncodeToString(encrypt(key, 0, mustHex("0000000000000000000000000000000000000000000000000000000000000000"))),
		},
		{
			Name:       "all-ff-single-block",
			Key:        hex.EncodeToString(key),
			InitCtr:    0,
			Plaintext:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			Ciphertext: hex.EncodeToString(encrypt(key, 0, mustHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))),
		},
		{
			Name:       "multi-block-64b",
			Key:        hex.EncodeToString(key),
			InitCtr:    0,
			Plaintext:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
			Ciphertext: hex.EncodeToString(encrypt(key, 0, mustHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"))),
		},
		{
			Name:       "single-block-initctr-7",
			Key:        hex.EncodeToString(key),
			InitCtr:    7,
			Plaintext:  "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
			Ciphertext: hex.EncodeToString(encrypt(key, 7, mustHex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"))),
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fixtures); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"

	"github.com/ethersphere/bee/v2/pkg/accesscontrol"
	"github.com/ethersphere/bee/v2/pkg/crypto"
)

type ecdhFixture struct {
	Name       string `json:"name"`
	AlicePriv  string `json:"alice_priv"`
	AlicePub   string `json:"alice_pub"`
	BobPriv    string `json:"bob_priv"`
	BobPub     string `json:"bob_pub"`
	LookupKey  string `json:"lookup_key"`
	DecryptKey string `json:"decrypt_key"`
}

func mustHex(s string) []byte {
	out, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("decode hex %q: %v", s, err)
	}
	return out
}

func uncompressed(pub *ecdsa.PublicKey) []byte {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	out := make([]byte, 65)
	out[0] = 0x04
	copy(out[1:33], x)
	copy(out[33:], y)
	return out
}

func fixture(name string, alicePrivHex string, bobPrivHex string) ecdhFixture {
	alicePriv := crypto.Secp256k1PrivateKeyFromBytes(mustHex(alicePrivHex))
	bobPriv := crypto.Secp256k1PrivateKeyFromBytes(mustHex(bobPrivHex))

	aliceSession := accesscontrol.NewDefaultSession(alicePriv)
	keys, err := aliceSession.Key(&bobPriv.PublicKey, [][]byte{{0x00}, {0x01}})
	if err != nil {
		log.Fatalf("derive session keys (%s): %v", name, err)
	}

	return ecdhFixture{
		Name:       name,
		AlicePriv:  hex.EncodeToString(alicePriv.D.FillBytes(make([]byte, 32))),
		AlicePub:   hex.EncodeToString(uncompressed(&alicePriv.PublicKey)),
		BobPriv:    hex.EncodeToString(bobPriv.D.FillBytes(make([]byte, 32))),
		BobPub:     hex.EncodeToString(uncompressed(&bobPriv.PublicKey)),
		LookupKey:  hex.EncodeToString(keys[0]),
		DecryptKey: hex.EncodeToString(keys[1]),
	}
}

func main() {
	fixtures := []ecdhFixture{
		fixture(
			"basic-pair-1",
			"1111111111111111111111111111111111111111111111111111111111111111",
			"2222222222222222222222222222222222222222222222222222222222222222",
		),
		fixture(
			"basic-pair-2",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		),
		fixture(
			"basic-pair-3",
			"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		),
		fixture(
			"small-value-pair",
			"0000000000000000000000000000000000000000000000000000000000000003",
			"0000000000000000000000000000000000000000000000000000000000000007",
		),
		fixture(
			"high-value-pair",
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364130",
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036412f",
		),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fixtures); err != nil {
		log.Fatal(err)
	}
}

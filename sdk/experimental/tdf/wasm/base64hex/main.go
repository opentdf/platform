// Canary: encoding/base64, encoding/hex
// These should pass under TinyGo — both pass all TinyGo tests.
package main

import (
	"encoding/base64"
	"encoding/hex"
)

func main() {
	// Base64 round-trip (used for policy encoding, key encoding)
	data := []byte("TDF policy payload test data")
	encoded := base64.StdEncoding.EncodeToString(data)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic("base64 decode failed")
	}
	if string(decoded) != string(data) {
		panic("base64 round-trip mismatch")
	}

	// Hex round-trip (used for assertion hash encoding)
	hexStr := hex.EncodeToString(data)
	hexDecoded, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("hex decode failed")
	}
	if string(hexDecoded) != string(data) {
		panic("hex round-trip mismatch")
	}
}

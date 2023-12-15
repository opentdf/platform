package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestCreateGcmEncryption(t *testing.T) {
	symmetricKey, err := SymmetricKey()
	if err != nil {
		t.Fatalf("Fail to create symmetric key: %v", err)
	}

	gmcEncryption, err := CreateGcmEncryption(symmetricKey, 16)
	cipherText, err := gmcEncryption.Encrypt([]byte("Hello world!!"))
	if err != nil {
		t.Fatalf("Fail to encrypt: %v", err)
	}

	fmt.Printf("%x\n", cipherText)

	testGcmEncryption("66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4",
		"29a8b044b5b6ce00e18bc6fc78ff50c6",
		"virtru",
		"29a8b044b5b6ce00e18bc6fc78ff50c6b3cf733137d865892e5af63dcbca08086ba1ac82aae2", t)

	testGcmEncryption("120fba31c537d99ade0a0a8c8e6df535f7de86fb6e1d5948317b4596982a5e1b",
		"ec9074bc6c6b81d6520f5a7425f8977a",
		"",
		"ec9074bc6c6b81d6520f5a7425f8977adabe8b28dd100eea2f58d71e3644b43d", t)

	testGcmEncryption("9895f395913a3cfd974ea53c0735030c7df4602d699c986afdc5fdd10071c0a5",
		"5142d90e8499f597802ca68cddb25ec1",
		`In cryptography, Galois/Counter Mode (GCM)[1] is a mode of operation
for symmetric-key cryptographic block ciphers which is
widely adopted for its performance`,
		`5142d90e8499f597802ca68cddb25ec101c1e44df776bfca60ed217e06421c7b945adaf328984
9406ca5b7046c886050fe72cc0ebc429f683f9cfe3a47613e2ca8a812ef9b75d361c32d042124d3dc5d84c757225
21df65ed7829327b5adda0ae020a778b909328a48311cc705d4c0a8b83f49430aa80febba73e27e99b3006d6e768
a092d5b9dc894e7a634235198b1a986a3624912dec108ef03055b319f59f25fc579eb08f01820ea19edc7f9896129
c572c36440ed80fd61fc71df37`, t)
}

func testGcmEncryption(symmetricKey, iv, plainText, out string, t *testing.T) {
	key, _ := hex.DecodeString(symmetricKey)
	nonce, _ := hex.DecodeString(iv)

	gmcEncryption, err := CreateGcmEncryption(key, 16)

	cipherText, err := gmcEncryption.EncryptWithIV(nonce, []byte(plainText))
	if err != nil {
		t.Fatalf("Fail to encrypt: %v", err)
	}

	actualCipherText, _ := hex.DecodeString(strings.ReplaceAll(out, "\n", ""))
	if string(actualCipherText) != string(cipherText) {
		t.Fatalf("encrypt test fail: actual:%s, expected:%s",
			string(actualCipherText), string(cipherText))
	}
}

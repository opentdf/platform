package ocrypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestCreateAesGcm_DecryptWithDefaults(t *testing.T) {
	gcmDecryptionTests := []struct {
		symmetricKey string
		iv           string
		cipherText   string
		plainText    string
	}{
		{
			"66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4",
			"d2c32fa42f97341e97a33b58",
			"a89d8e00e3bacacc2ed13bbc602a191d60584af3a933",
			"virtru",
		},
		{
			"120fba31c537d99ade0a0a8c8e6df535f7de86fb6e1d5948317b4596982a5e1b",
			"591a6f1e947dd887d72610c8",
			"83aaba876616c02bfaf5120c785ac92c",
			"",
		},
		{
			"9895f395913a3cfd974ea53c0735030c7df4602d699c986afdc5fdd10071c0a5",
			"71c291bc41aacde6e0b57e7d",
			`7b19b61dc053c3ffeaba57195356025a05600b071a4618912917681480f1eb62afb9ecc
ff7a90d6cba96275bd52bd8d6afa4fcbae6a400ce7033e7abd58e301ab9b4a9c3e7f4c0f55256d250faf8ce0c22bdd
9b79654842a6186df98831289eeee66fac014390a4363034d64e44fc9a2c0e0231d69c78f0a8049d8b458579041858
d4f6da9f39542d2287d20d19dd99db339c038e3b6e1720c97ff73adda5ca4fac7da70c7d53f97a5aa346e93af`,
			`In cryptography, Galois/Counter Mode (GCM)[1] is a mode of operation
for symmetric-key cryptographic block ciphers which is
widely adopted for its performance`,
		},
	}

	for _, test := range gcmDecryptionTests {
		key, _ := hex.DecodeString(test.symmetricKey)
		nonce, _ := hex.DecodeString(test.iv)

		aesGcm, err := NewAESGcm(key)
		if err != nil {
			t.Fatalf("Fail to create AesGcm: %v", err)
		}

		cipherBytes, _ := hex.DecodeString(strings.ReplaceAll(test.cipherText, "\n", ""))
		plainData, err := aesGcm.Decrypt(append(nonce, cipherBytes...))
		if err != nil {
			t.Fatalf("Fail to decrypt: %v", err)
		}

		if string(plainData) != test.plainText {
			t.Errorf("gcm decryption test don't match: expected %v, got %v", test.plainText, string(plainData))
		}
	}
}

func TestCreateAesGcm_EncryptWithDefaults(t *testing.T) {
	gcmEncryptionTests := []struct {
		symmetricKey string
		iv           string
		plainText    string
		cipherText   string
	}{
		{
			"66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4",
			"29a8b044b5b6ce00e18bc6fc78ff50c6",
			"virtru",
			"29a8b044b5b6ce00e18bc6fc78ff50c6b3cf733137d865892e5af63dcbca08086ba1ac82aae2",
		},
		{
			"120fba31c537d99ade0a0a8c8e6df535f7de86fb6e1d5948317b4596982a5e1b",
			"ec9074bc6c6b81d6520f5a7425f8977a",
			"",
			"ec9074bc6c6b81d6520f5a7425f8977adabe8b28dd100eea2f58d71e3644b43d",
		},
		{
			"9895f395913a3cfd974ea53c0735030c7df4602d699c986afdc5fdd10071c0a5",
			"5142d90e8499f597802ca68cddb25ec1",
			`In cryptography, Galois/Counter Mode (GCM)[1] is a mode of operation
for symmetric-key cryptographic block ciphers which is
widely adopted for its performance`,
			`5142d90e8499f597802ca68cddb25ec101c1e44df776bfca60ed217e06421c7b945adaf328984
9406ca5b7046c886050fe72cc0ebc429f683f9cfe3a47613e2ca8a812ef9b75d361c32d042124d3dc5d84c757225
21df65ed7829327b5adda0ae020a778b909328a48311cc705d4c0a8b83f49430aa80febba73e27e99b3006d6e768
a092d5b9dc894e7a634235198b1a986a3624912dec108ef03055b319f59f25fc579eb08f01820ea19edc7f9896129
c572c36440ed80fd61fc71df37`,
		},
	}

	for _, test := range gcmEncryptionTests {
		key, _ := hex.DecodeString(test.symmetricKey)
		nonce, _ := hex.DecodeString(test.iv)

		aesGcm, err := NewAESGcm(key)
		if err != nil {
			t.Fatalf("Fail to create AesGcm: %v", err)
		}

		cipherText, err := aesGcm.EncryptWithIV(nonce, []byte(test.plainText))
		if err != nil {
			t.Fatalf("Fail to encrypt with iv: %v", err)
		}

		actualCipherText, _ := hex.DecodeString(strings.ReplaceAll(test.cipherText, "\n", ""))
		if string(actualCipherText) != string(cipherText) {
			t.Fatalf("encrypt test fail: actual:%s, expected:%s",
				string(actualCipherText), string(cipherText))
		}
	}
}

func TestCreateAESGcm_WithDifferentAuthTags(t *testing.T) {
	plainText := "Virtru"
	key, _ := hex.DecodeString("66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4")
	aesGcm, err := NewAESGcm(key)
	if err != nil {
		t.Fatalf("Fail to create AesGcm: %v", err)
	}

	nonce, err := RandomBytes(GcmStandardNonceSize)
	if err != nil {
		t.Fatalf("Fail to grenerate nonce %v", err)
	}

	authTagsToTest := []int{12, 13, 14, 15, 16}
	for _, authTag := range authTagsToTest {
		cipherText, err := aesGcm.EncryptWithIVAndTagSize(nonce, []byte(plainText), authTag)
		if err != nil {
			t.Fatalf("Fail to encrypt with auth tag:%d err:%v", authTag, err)
		}

		decipherText, err := aesGcm.DecryptWithTagSize(cipherText, authTag)
		if err != nil {
			t.Fatalf("Fail to decrypt with auth tag:%d err:%v", authTag, err)
		}

		if plainText != string(decipherText) {
			t.Errorf("gcm decryption test don't match: expected %v, got %v", plainText, string(decipherText))
		}
	}
}

func BenchmarkAESGcm_ForTDF3(b *testing.B) {
	// Create 2mb buffer and fill with character 'X'
	twoMB := 2 * 1024 * 1024
	twoMbBuffer := make([]byte, twoMB)
	for index := 0; index < len(twoMbBuffer); index++ {
		twoMbBuffer[index] = 'X'
	}

	key, _ := hex.DecodeString("66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4")
	aesGcm, err := NewAESGcm(key)
	if err != nil {
		b.Fatalf("Fail to create AesGcm: %v", err)
	}

	cipherText, err := aesGcm.Encrypt(twoMbBuffer)
	if err != nil {
		b.Fatalf("Fail to encrypt:%v", err)
	}

	decipherText, err := aesGcm.Decrypt(cipherText)
	if err != nil {
		b.Fatalf("Fail to decrypt:%v", err)
	}

	if string(twoMbBuffer) != string(decipherText) {
		b.Errorf("gcm decryption test don't match")
	}
}

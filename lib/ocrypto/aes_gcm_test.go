package ocrypto

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
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
	key, _ := hex.DecodeString("66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4")
	aesGcm, err := NewAESGcm(key)
	if err != nil {
		t.Fatalf("Fail to create AesGcm: %v", err)
	}

	plainText := []byte("virtru")
	cipherText, err := aesGcm.Encrypt(plainText)
	if err != nil {
		t.Fatalf("Fail to encrypt: %v", err)
	}

	if len(cipherText) != len(plainText)+GcmStandardNonceSize+aes.BlockSize {
		t.Fatalf("unexpected ciphertext length: got %d", len(cipherText))
	}

	decipherText, err := aesGcm.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Fail to decrypt: %v", err)
	}

	if string(plainText) != string(decipherText) {
		t.Errorf("gcm decryption test don't match: expected %v, got %v", string(plainText), string(decipherText))
	}
}

func TestCreateAESGcm_EncryptInPlace(t *testing.T) {
	key, _ := hex.DecodeString("66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4")
	aesGcm, err := NewAESGcm(key)
	if err != nil {
		t.Fatalf("Fail to create AesGcm: %v", err)
	}

	plainText := []byte("Virtru")
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "exact capacity",
			data: append([]byte{}, plainText...),
		},
		{
			name: "spare capacity",
			data: func() []byte {
				buf := make([]byte, len(plainText), len(plainText)+GcmStandardNonceSize+aes.BlockSize)
				copy(buf, plainText)
				return buf
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cipherText, nonce, err := aesGcm.EncryptInPlace(test.data)
			if err != nil {
				t.Fatalf("Fail to encrypt in place: %v", err)
			}

			if len(nonce) != GcmStandardNonceSize {
				t.Fatalf("unexpected nonce length: got %d", len(nonce))
			}
			if len(cipherText) != len(plainText)+aes.BlockSize {
				t.Fatalf("unexpected ciphertext length: got %d", len(cipherText))
			}

			sealed := append(append([]byte{}, nonce...), cipherText...)
			decipherText, err := aesGcm.Decrypt(sealed)
			if err != nil {
				t.Fatalf("Fail to decrypt ciphertext: %v", err)
			}

			if string(plainText) != string(decipherText) {
				t.Errorf("gcm decryption test don't match: expected %v, got %v", string(plainText), string(decipherText))
			}
		})
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

func TestNewAESGcm_EmptyKey(t *testing.T) {
	_, err := NewAESGcm([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
	if !errors.Is(err, ErrInvalidKeyData) {
		t.Errorf("expected ErrInvalidKeyData, got %v", err)
	}
}

func TestNewAESGcm_InvalidKeySize(t *testing.T) {
	// AES only supports 16, 24, or 32 byte keys
	invalidKeys := [][]byte{
		{0x01},             // 1 byte
		{0x01, 0x02, 0x03}, // 3 bytes
		make([]byte, 15),   // 15 bytes
		make([]byte, 17),   // 17 bytes
		make([]byte, 31),   // 31 bytes
		make([]byte, 33),   // 33 bytes
	}

	for _, key := range invalidKeys {
		_, err := NewAESGcm(key)
		if err == nil {
			t.Errorf("expected error for %d-byte key, got nil", len(key))
		}
		if !errors.Is(err, ErrInvalidKeyData) {
			t.Errorf("expected ErrInvalidKeyData for %d-byte key, got %v", len(key), err)
		}
	}
}

func TestDecrypt_EmptyData(t *testing.T) {
	key, _ := hex.DecodeString("66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4")
	aesGcm, _ := NewAESGcm(key)

	_, err := aesGcm.Decrypt([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data, got nil")
	}
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestDecrypt_TooShortData(t *testing.T) {
	key, _ := hex.DecodeString("66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4")
	aesGcm, _ := NewAESGcm(key)

	// Data shorter than GcmStandardNonceSize (12 bytes)
	_, err := aesGcm.Decrypt([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for short data, got nil")
	}
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext, got %v", err)
	}
}

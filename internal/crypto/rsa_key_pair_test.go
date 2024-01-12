package crypto

import (
	"testing"
)

func TestRSAKeyPair(t *testing.T) {
	for _, size := range []int{2048, 3072, 4096} {
		rsaKeyPair, err := NewRSAKeyPair(size)
		if err != nil {
			t.Fatalf("NewRSAKeyPair(%d): %v", size, err)
		}

		_, err = rsaKeyPair.PublicKeyInPemFormat()
		if err != nil {
			t.Fatalf("rsa PublicKeyInPemFormat() error - %v", err)
		}

		_, err = rsaKeyPair.PrivateKeyInPemFormat()
		if err != nil {
			t.Fatalf("rsa PrivateKeyInPemFormat() error - %v", err)
		}

		keySize, err := rsaKeyPair.KeySize()
		if err != nil {
			t.Fatalf("rsa keysize error - %v", err)
		}

		if keySize != size {
			t.Fatalf("invalid key size expected:%d actual:%d",
				size, keySize)
		}
	}

	// Fail case
	emptyRSAKeyPair := RsaKeyPair{}

	_, err := emptyRSAKeyPair.PrivateKeyInPemFormat()
	if err == nil {
		t.Fatal("RsaKeyPair.PrivateKeyInPemFormat() fail to return error")
	}

	_, err = emptyRSAKeyPair.PublicKeyInPemFormat()
	if err == nil {
		t.Fatal("RsaKeyPair.PublicKeyInPemFormat() fail to return error")
	}

	_, err = emptyRSAKeyPair.KeySize()
	if err == nil {
		t.Fatal("RsaKeyPair.keySize() fail to return error")
	}
}

package ocrypto

import (
	"testing"
)

func TestECKeyPair(t *testing.T) {
	for _, modeGood := range []ECCMode{ECCModeSecp256r1, ECCModeSecp384r1, ECCModeSecp521r1} {
		ecKeyPair, err := NewECKeyPair(modeGood)
		if err != nil {
			t.Fatalf("NewECKeyPair(%d): %v", modeGood, err)
		}

		_, err = ecKeyPair.PublicKeyInPemFormat()
		if err != nil {
			t.Fatalf("ec PublicKeyInPemFormat() error - %v", err)
		}

		_, err = ecKeyPair.PrivateKeyInPemFormat()
		if err != nil {
			t.Fatalf("ec PrivateKeyInPemFormat() error - %v", err)
		}

		keySize, err := ecKeyPair.KeySize()
		if err != nil {
			t.Fatalf("ec keysize error - %v", err)
		}

		// Set expected size based on mode
		size := 0
		switch modeGood {
		case ECCModeSecp256r1:
			size = 256
			break
		case ECCModeSecp384r1:
			size = 384
			break
		case ECCModeSecp521r1:
			size = 521
			break
		default:
			size = 99999 // deliberately bad value
		}

		if keySize != size {
			t.Fatalf("invalid key size for mode %d, expected:%d actual:%d",
				modeGood, size, keySize)
		}
	}

	// Fail case
	emptyECKeyPair := ECKeyPair{}

	_, err := emptyECKeyPair.PrivateKeyInPemFormat()
	if err == nil {
		t.Fatal("EcKeyPair.PrivateKeyInPemFormat() fail to return error")
	}

	_, err = emptyECKeyPair.PublicKeyInPemFormat()
	if err == nil {
		t.Fatal("EcKeyPair.PublicKeyInPemFormat() fail to return error")
	}

	_, err = emptyECKeyPair.KeySize()
	if err == nil {
		t.Fatal("EcKeyPair.keySize() fail to return error")
	}

	for _, modeBad := range []ECCMode{ECCModeSecp256k1} {
		_, err := NewECKeyPair(modeBad)
		if err == nil {
			t.Fatalf("did not fail as expected: NewECKeyPair(%d): %v", modeBad, err)
		}
	}
}

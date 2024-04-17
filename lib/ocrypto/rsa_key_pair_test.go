package ocrypto

import (
	"crypto/sha256"
	"github.com/stretchr/testify/require"
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

func TestNanoTDFRewrapKeyGenerate(t *testing.T) {
	kasECKeyPair, err := NewECKeyPair(ECCModeSecp256r1)
	require.NoError(t, err, "fail on NewECKeyPair")

	kasPubKeyAsPem, err := kasECKeyPair.PublicKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec public key in pem format")

	kasPrivateKeyAsPem, err := kasECKeyPair.PrivateKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec private key in pem format")

	sdkECKeyPair, err := NewECKeyPair(ECCModeSecp256r1)
	require.NoError(t, err, "fail on NewECKeyPair")

	sdkPubKeyAsPem, err := sdkECKeyPair.PublicKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec public key in pem format")

	sdkPrivateKeyAsPem, err := sdkECKeyPair.PrivateKeyInPemFormat()
	require.NoError(t, err, "fail to generate ec private key in pem format")

	kasECDHKey, err := ComputeECDHKey(kasPrivateKeyAsPem, sdkPubKeyAsPem)
	require.NoError(t, err, "fail to calculate ecdh key")

	// slat
	digest := sha256.New()
	digest.Write([]byte("L1L"))

	kasSymmetricKey, err := CalculateHKDF(digest.Sum(nil), kasECDHKey, 32)
	require.NoError(t, err, "fail to calculate HKDF key")

	sdkECDHKey, err := ComputeECDHKey(sdkPrivateKeyAsPem, kasPubKeyAsPem)
	require.NoError(t, err, "fail to calculate ecdh key")

	sdkSymmetricKey, err := CalculateHKDF(digest.Sum(nil), sdkECDHKey, 32)
	require.NoError(t, err, "fail to calculate HKDF key")

	if string(kasSymmetricKey) != string(sdkSymmetricKey) {
		t.Fatalf("symmetric keys on both kas and sdk should be same kas:%s sdk:%s",
			string(kasSymmetricKey), string(sdkSymmetricKey))
	}
}

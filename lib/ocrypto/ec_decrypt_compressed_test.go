package ocrypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"
)

func TestECDecryptWithCompressedEphemeralKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		mode ECCMode
	}

	tests := []testCase{
		{name: "P256", mode: ECCModeSecp256r1},
		{name: "P384", mode: ECCModeSecp384r1},
		{name: "P521", mode: ECCModeSecp521r1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			receiverKeys, err := NewECKeyPair(test.mode)
			if err != nil {
				t.Fatalf("NewECKeyPair failed: %v", err)
			}

			pubPEM, err := receiverKeys.PublicKeyInPemFormat()
			if err != nil {
				t.Fatalf("PublicKeyInPemFormat failed: %v", err)
			}

			privPEM, err := receiverKeys.PrivateKeyInPemFormat()
			if err != nil {
				t.Fatalf("PrivateKeyInPemFormat failed: %v", err)
			}

			salt := []byte("test-salt")
			encryptor, err := FromPublicPEMWithSalt(pubPEM, salt, nil)
			if err != nil {
				t.Fatalf("FromPublicPEMWithSalt failed: %v", err)
			}

			plaintext := []byte("test payload for ec decrypt")
			ciphertext, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			ephemeralDER := encryptor.EphemeralKey()
			if len(ephemeralDER) == 0 {
				t.Fatal("EphemeralKey returned empty data")
			}

			compressed, err := compressEphemeralKeyFromDER(ephemeralDER)
			if err != nil {
				t.Fatalf("compressEphemeralKeyFromDER failed: %v", err)
			}

			decryptor, err := FromPrivatePEMWithSalt(privPEM, salt, nil)
			if err != nil {
				t.Fatalf("FromPrivatePEMWithSalt failed: %v", err)
			}

			ecDecryptor, ok := decryptor.(ECDecryptor)
			if !ok {
				t.Fatalf("unexpected decryptor type: %T", decryptor)
			}

			decrypted, err := ecDecryptor.DecryptWithEphemeralKey(ciphertext, compressed)
			if err != nil {
				t.Fatalf("DecryptWithEphemeralKey failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Fatalf("unexpected plaintext: got %q want %q", decrypted, plaintext)
			}
		})
	}
}

func compressEphemeralKeyFromDER(der []byte) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		ecdhPub, err := pub.ECDH()
		if err != nil {
			return nil, err
		}
		return compressUncompressedPoint(ecdhPub.Bytes())
	case *ecdh.PublicKey:
		return compressUncompressedPoint(pub.Bytes())
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func compressUncompressedPoint(uncompressed []byte) ([]byte, error) {
	if len(uncompressed) == 0 || uncompressed[0] != 4 {
		return nil, errors.New("unexpected uncompressed key format")
	}

	if (len(uncompressed)-1)%2 != 0 {
		return nil, errors.New("invalid uncompressed key length")
	}

	coordSize := (len(uncompressed) - 1) / 2
	x := uncompressed[1 : 1+coordSize]
	y := uncompressed[1+coordSize:]
	if len(y) != coordSize {
		return nil, errors.New("invalid coordinate sizes")
	}

	prefix := byte(2)
	if y[coordSize-1]&1 == 1 {
		prefix = 3
	}

	compressed := make([]byte, 1+coordSize)
	compressed[0] = prefix
	copy(compressed[1:], x)
	return compressed, nil
}

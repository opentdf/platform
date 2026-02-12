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

			ephemeralECDSA, err := parseECDSAPublicKey(ephemeralDER)
			if err != nil {
				t.Fatalf("parseECDSAPublicKey failed: %v", err)
			}

			compressed, err := CompressedECPublicKey(test.mode, *ephemeralECDSA)
			if err != nil {
				t.Fatalf("CompressedECPublicKey failed: %v", err)
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

func parseECDSAPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	case *ecdh.PublicKey:
		curve := convCurveForTest(pub.Curve())
		if curve == nil {
			return nil, errors.New("unsupported ecdh curve")
		}
		x, y := elliptic.Unmarshal(curve, pub.Bytes())
		if x == nil {
			return nil, errors.New("failed to unmarshal ecdh public key")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func convCurveForTest(c ecdh.Curve) elliptic.Curve {
	switch c {
	case ecdh.P256():
		return elliptic.P256()
	case ecdh.P384():
		return elliptic.P384()
	case ecdh.P521():
		return elliptic.P521()
	default:
		return nil
	}
}

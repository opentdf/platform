package ocrypto

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
)

// Sink variables to prevent compiler from optimizing away results.
var (
	sinkBytes []byte
	errSink   error
)

// testDEK is a 32-byte AES-256 key used as the payload for wrap/unwrap benchmarks.
var testDEK = []byte("0123456789abcdef0123456789abcdef")

func BenchmarkKeyGeneration(b *testing.B) {
	b.Run("RSA-2048", func(b *testing.B) {
		for b.Loop() {
			_, errSink = NewRSAKeyPair(2048)
		}
	})
	b.Run("EC-P256", func(b *testing.B) {
		for b.Loop() {
			_, errSink = NewECKeyPair(ECCModeSecp256r1)
		}
	})
	b.Run("EC-P384", func(b *testing.B) {
		for b.Loop() {
			_, errSink = NewECKeyPair(ECCModeSecp384r1)
		}
	})
	b.Run("XWing", func(b *testing.B) {
		for b.Loop() {
			_, errSink = NewXWingKeyPair()
		}
	})
	b.Run("P256_MLKEM768", func(b *testing.B) {
		for b.Loop() {
			_, errSink = NewP256MLKEM768KeyPair()
		}
	})
	b.Run("P384_MLKEM1024", func(b *testing.B) {
		for b.Loop() {
			_, errSink = NewP384MLKEM1024KeyPair()
		}
	})
}

// benchTDFSalt matches tdf.go:tdfSalt() — SHA-256("TDF").
func benchTDFSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	return digest.Sum(nil)
}

// BenchmarkWrapDEK mirrors the actual TDF key-wrapping paths in sdk/tdf.go.
// Hybrid paths go through FromPublicPEM -> Encrypt, matching how the SDK now
// dispatches via OID after the draft-14 / draft-10 conformance refactor.
func BenchmarkWrapDEK(b *testing.B) {
	salt := benchTDFSalt()

	rsaKP, err := NewRSAKeyPair(2048)
	if err != nil {
		b.Fatal(err)
	}
	rsaPubPEM, err := rsaKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	ecKP, err := NewECKeyPair(ECCModeSecp256r1)
	if err != nil {
		b.Fatal(err)
	}
	ecKASPubPEM, err := ecKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	ec384KP, err := NewECKeyPair(ECCModeSecp384r1)
	if err != nil {
		b.Fatal(err)
	}
	ec384KASPubPEM, err := ec384KP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	xwingKP, err := NewXWingKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	xwingPubPEM, err := xwingKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	p256KP, err := NewP256MLKEM768KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p256PubPEM, err := p256KP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	p384KP, err := NewP384MLKEM1024KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p384PubPEM, err := p384KP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("RSA-2048", func(b *testing.B) {
		for b.Loop() {
			enc, err := FromPublicPEM(rsaPubPEM)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = enc.Encrypt(testDEK)
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})

	b.Run("EC-P256", func(b *testing.B) {
		for b.Loop() {
			ephKP, err := NewECKeyPair(ECCModeSecp256r1)
			if err != nil {
				b.Fatal(err)
			}
			ephPrivPEM, err := ephKP.PrivateKeyInPemFormat()
			if err != nil {
				b.Fatal(err)
			}
			ecdhKey, err := ComputeECDHKey([]byte(ephPrivPEM), []byte(ecKASPubPEM))
			if err != nil {
				b.Fatal(err)
			}
			sessionKey, err := CalculateHKDF(salt, ecdhKey)
			if err != nil {
				b.Fatal(err)
			}
			gcm, err := NewAESGcm(sessionKey)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = gcm.Encrypt(testDEK)
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})

	b.Run("EC-P384", func(b *testing.B) {
		for b.Loop() {
			ephKP, err := NewECKeyPair(ECCModeSecp384r1)
			if err != nil {
				b.Fatal(err)
			}
			ephPrivPEM, err := ephKP.PrivateKeyInPemFormat()
			if err != nil {
				b.Fatal(err)
			}
			ecdhKey, err := ComputeECDHKey([]byte(ephPrivPEM), []byte(ec384KASPubPEM))
			if err != nil {
				b.Fatal(err)
			}
			sessionKey, err := CalculateHKDF(salt, ecdhKey)
			if err != nil {
				b.Fatal(err)
			}
			gcm, err := NewAESGcm(sessionKey)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = gcm.Encrypt(testDEK)
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})

	b.Run("XWing", func(b *testing.B) {
		for b.Loop() {
			enc, err := FromPublicPEM(xwingPubPEM)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = enc.Encrypt(testDEK)
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})

	b.Run("P256_MLKEM768", func(b *testing.B) {
		for b.Loop() {
			enc, err := FromPublicPEM(p256PubPEM)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = enc.Encrypt(testDEK)
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})

	b.Run("P384_MLKEM1024", func(b *testing.B) {
		for b.Loop() {
			enc, err := FromPublicPEM(p384PubPEM)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = enc.Encrypt(testDEK)
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})
}

// BenchmarkUnwrapDEK mirrors the actual KAS unwrap paths in
// service/internal/security/standard_crypto.go:Decrypt(). Hybrid paths now go
// through FromPrivatePEM -> Decrypt to match the OID-routed dispatcher.
func BenchmarkUnwrapDEK(b *testing.B) {
	salt := benchTDFSalt()

	// RSA-2048: KAS pre-loads the AsymDecryption at startup
	rsaKP, err := NewRSAKeyPair(2048)
	if err != nil {
		b.Fatal(err)
	}
	rsaPubPEM, err := rsaKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	rsaPrivPEM, err := rsaKP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	rsaEnc, err := FromPublicPEM(rsaPubPEM)
	if err != nil {
		b.Fatal(err)
	}
	rsaWrapped, err := rsaEnc.Encrypt(testDEK)
	if err != nil {
		b.Fatal(err)
	}
	rsaDec, err := FromPrivatePEM(rsaPrivPEM)
	if err != nil {
		b.Fatal(err)
	}

	// EC P-256
	ecKASKP, err := NewECKeyPair(ECCModeSecp256r1)
	if err != nil {
		b.Fatal(err)
	}
	ecKASPubPEM, err := ecKASKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ecKASPrivPEM, err := ecKASKP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ecEphKP, err := NewECKeyPair(ECCModeSecp256r1)
	if err != nil {
		b.Fatal(err)
	}
	ecEphPrivPEM, err := ecEphKP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ecEphPubPEM, err := ecEphKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ecdhKey, err := ComputeECDHKey([]byte(ecEphPrivPEM), []byte(ecKASPubPEM))
	if err != nil {
		b.Fatal(err)
	}
	ecSessionKey, err := CalculateHKDF(salt, ecdhKey)
	if err != nil {
		b.Fatal(err)
	}
	ecGCM, err := NewAESGcm(ecSessionKey)
	if err != nil {
		b.Fatal(err)
	}
	ecWrapped, err := ecGCM.Encrypt(testDEK)
	if err != nil {
		b.Fatal(err)
	}
	ecEphPubECDH, err := ECPubKeyFromPem([]byte(ecEphPubPEM))
	if err != nil {
		b.Fatal(err)
	}
	ecEphDER, err := x509.MarshalPKIXPublicKey(ecEphPubECDH)
	if err != nil {
		b.Fatal(err)
	}
	ecKASPrivKey, err := ECPrivateKeyFromPem([]byte(ecKASPrivPEM))
	if err != nil {
		b.Fatal(err)
	}

	// EC P-384
	ec384KASKP, err := NewECKeyPair(ECCModeSecp384r1)
	if err != nil {
		b.Fatal(err)
	}
	ec384KASPubPEM, err := ec384KASKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ec384KASPrivPEM, err := ec384KASKP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ec384EphKP, err := NewECKeyPair(ECCModeSecp384r1)
	if err != nil {
		b.Fatal(err)
	}
	ec384EphPrivPEM, err := ec384EphKP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ec384EphPubPEM, err := ec384EphKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	ec384DhKey, err := ComputeECDHKey([]byte(ec384EphPrivPEM), []byte(ec384KASPubPEM))
	if err != nil {
		b.Fatal(err)
	}
	ec384SessionKey, err := CalculateHKDF(salt, ec384DhKey)
	if err != nil {
		b.Fatal(err)
	}
	ec384GCM, err := NewAESGcm(ec384SessionKey)
	if err != nil {
		b.Fatal(err)
	}
	ec384Wrapped, err := ec384GCM.Encrypt(testDEK)
	if err != nil {
		b.Fatal(err)
	}
	ec384EphPubECDH, err := ECPubKeyFromPem([]byte(ec384EphPubPEM))
	if err != nil {
		b.Fatal(err)
	}
	ec384EphDER, err := x509.MarshalPKIXPublicKey(ec384EphPubECDH)
	if err != nil {
		b.Fatal(err)
	}
	ec384KASPrivKey, err := ECPrivateKeyFromPem([]byte(ec384KASPrivPEM))
	if err != nil {
		b.Fatal(err)
	}

	// X-Wing
	xwingKP, err := NewXWingKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	xwingPrivPEM, err := xwingKP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	xwingWrapped, err := wrapDEKWithKEM(xwingKEM{}, xwingKP.publicKey, testDEK, salt, nil)
	if err != nil {
		b.Fatal(err)
	}

	// P256+MLKEM768
	p256KP, err := NewP256MLKEM768KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p256PrivPEM, err := p256KP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	p256Wrapped, err := wrapDEKWithKEM(hybridNISTKEM{params: &p256mlkem768Params}, p256KP.publicKey, testDEK, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	// P384+MLKEM1024
	p384KP, err := NewP384MLKEM1024KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p384PrivPEM, err := p384KP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	p384Wrapped, err := wrapDEKWithKEM(hybridNISTKEM{params: &p384mlkem1024Params}, p384KP.publicKey, testDEK, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("RSA-2048", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, errSink = rsaDec.Decrypt(rsaWrapped)
		}
	})

	b.Run("EC-P256", func(b *testing.B) {
		for b.Loop() {
			dec, err := NewSaltedECDecryptor(ecKASPrivKey, salt, nil)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = dec.DecryptWithEphemeralKey(ecWrapped, ecEphDER)
		}
	})

	b.Run("EC-P384", func(b *testing.B) {
		for b.Loop() {
			dec, err := NewSaltedECDecryptor(ec384KASPrivKey, salt, nil)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = dec.DecryptWithEphemeralKey(ec384Wrapped, ec384EphDER)
		}
	})

	b.Run("XWing", func(b *testing.B) {
		for b.Loop() {
			dec, err := FromPrivatePEM(xwingPrivPEM)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = dec.Decrypt(xwingWrapped)
		}
	})

	b.Run("P256_MLKEM768", func(b *testing.B) {
		for b.Loop() {
			dec, err := FromPrivatePEM(p256PrivPEM)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = dec.Decrypt(p256Wrapped)
		}
	})

	b.Run("P384_MLKEM1024", func(b *testing.B) {
		for b.Loop() {
			dec, err := FromPrivatePEM(p384PrivPEM)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = dec.Decrypt(p384Wrapped)
		}
	})
}

func TestWrappedKeySizeComparison(t *testing.T) {
	type sizeResult struct {
		scheme     string
		wrappedLen int
		pubKeyLen  int
		notes      string
	}

	var results []sizeResult

	// RSA-2048
	rsaKP, err := NewRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPubPEM, err := rsaKP.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	rsaEnc, err := FromPublicPEM(rsaPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	rsaWrapped, err := rsaEnc.Encrypt(testDEK)
	if err != nil {
		t.Fatal(err)
	}
	results = append(results, sizeResult{
		scheme:     "RSA-2048",
		wrappedLen: len(rsaWrapped),
		pubKeyLen:  len(rsaPubPEM),
		notes:      "No ephemeral key",
	})

	// EC P-256
	ecKP, err := NewECKeyPair(ECCModeSecp256r1)
	if err != nil {
		t.Fatal(err)
	}
	ecPubPEM, err := ecKP.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	ecEnc, err := FromPublicPEM(ecPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	ecWrapped, err := ecEnc.Encrypt(testDEK)
	if err != nil {
		t.Fatal(err)
	}
	ecEphemeral := ecEnc.EphemeralKey()
	results = append(results, sizeResult{
		scheme:     "EC P-256",
		wrappedLen: len(ecWrapped),
		pubKeyLen:  len(ecPubPEM),
		notes:      fmt.Sprintf("+ ephemeral key (%d bytes)", len(ecEphemeral)),
	})

	// EC P-384
	ec384KP, err := NewECKeyPair(ECCModeSecp384r1)
	if err != nil {
		t.Fatal(err)
	}
	ec384PubPEM, err := ec384KP.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	ec384Enc, err := FromPublicPEM(ec384PubPEM)
	if err != nil {
		t.Fatal(err)
	}
	ec384Wrapped, err := ec384Enc.Encrypt(testDEK)
	if err != nil {
		t.Fatal(err)
	}
	ec384Ephemeral := ec384Enc.EphemeralKey()
	results = append(results, sizeResult{
		scheme:     "EC P-384",
		wrappedLen: len(ec384Wrapped),
		pubKeyLen:  len(ec384PubPEM),
		notes:      fmt.Sprintf("+ ephemeral key (%d bytes)", len(ec384Ephemeral)),
	})

	// X-Wing
	xwingKP, err := NewXWingKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xwingPubPEM, err := xwingKP.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	xwingWrapped, err := wrapDEKWithKEM(xwingKEM{}, xwingKP.publicKey, testDEK, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	results = append(results, sizeResult{
		scheme:     "X-Wing",
		wrappedLen: len(xwingWrapped),
		pubKeyLen:  len(xwingPubPEM),
		notes:      "All in ASN.1 blob",
	})

	// P256+MLKEM768
	p256KP, err := NewP256MLKEM768KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	p256PubPEM, err := p256KP.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	p256Wrapped, err := wrapDEKWithKEM(hybridNISTKEM{params: &p256mlkem768Params}, p256KP.publicKey, testDEK, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	results = append(results, sizeResult{
		scheme:     "P256+MLKEM768",
		wrappedLen: len(p256Wrapped),
		pubKeyLen:  len(p256PubPEM),
		notes:      "All in ASN.1 blob",
	})

	// P384+MLKEM1024
	p384KP, err := NewP384MLKEM1024KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	p384PubPEM, err := p384KP.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	p384Wrapped, err := wrapDEKWithKEM(hybridNISTKEM{params: &p384mlkem1024Params}, p384KP.publicKey, testDEK, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	results = append(results, sizeResult{
		scheme:     "P384+MLKEM1024",
		wrappedLen: len(p384Wrapped),
		pubKeyLen:  len(p384PubPEM),
		notes:      "All in ASN.1 blob",
	})

	// Print table
	t.Logf("\n%-20s %20s %20s   %s", "Scheme", "Wrapped Key (bytes)", "Public Key (bytes)", "Notes")
	t.Logf("%-20s %20s %20s   %s", "------", "-------------------", "------------------", "-----")
	for _, r := range results {
		t.Logf("%-20s %20d %20d   %s", r.scheme, r.wrappedLen, r.pubKeyLen, r.notes)
	}
}

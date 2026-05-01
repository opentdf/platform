package ocrypto

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
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

// BenchmarkWrapDEK mirrors the actual TDF key-wrapping paths in sdk/tdf.go:
//   - RSA:    FromPublicPEM -> Encrypt                (generateWrapKeyWithRSA)
//   - EC:     NewECKeyPair -> ComputeECDHKey -> HKDF -> AES-GCM  (generateWrapKeyWithEC)
//   - Hybrid: PubKeyFromPem -> Encapsulate -> HKDF -> AES-GCM -> ASN.1 (generateWrapKeyWithHybrid)
func BenchmarkWrapDEK(b *testing.B) {
	salt := benchTDFSalt()

	// RSA-2048: setup KAS public key
	rsaKP, err := NewRSAKeyPair(2048)
	if err != nil {
		b.Fatal(err)
	}
	rsaPubPEM, err := rsaKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	// EC P-256: setup KAS public key PEM
	ecKP, err := NewECKeyPair(ECCModeSecp256r1)
	if err != nil {
		b.Fatal(err)
	}
	ecKASPubPEM, err := ecKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	// EC P-384: setup KAS public key PEM
	ec384KP, err := NewECKeyPair(ECCModeSecp384r1)
	if err != nil {
		b.Fatal(err)
	}
	ec384KASPubPEM, err := ec384KP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	// X-Wing: setup KAS public key PEM
	xwingKP, err := NewXWingKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	xwingPubPEM, err := xwingKP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	// P256+MLKEM768: setup KAS public key PEM
	p256KP, err := NewP256MLKEM768KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p256PubPEM, err := p256KP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	// P384+MLKEM1024: setup KAS public key PEM
	p384KP, err := NewP384MLKEM1024KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p384PubPEM, err := p384KP.PublicKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}

	// RSA: tdf.go calls FromPublicPEM -> Encrypt
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

	// EC: tdf.go generates ephemeral EC keypair, computes ECDH, derives via HKDF, AES-GCM wraps
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

	// X-Wing: tdf.go parses PEM, calls Encapsulate, HKDF, AES-GCM, then ASN.1 marshal
	b.Run("XWing", func(b *testing.B) {
		for b.Loop() {
			pubKey, err := XWingPubKeyFromPem([]byte(xwingPubPEM))
			if err != nil {
				b.Fatal(err)
			}
			ss, ct, err := XWingEncapsulate(pubKey)
			if err != nil {
				b.Fatal(err)
			}
			wrapKey, err := CalculateHKDF(salt, ss)
			if err != nil {
				b.Fatal(err)
			}
			gcm, err := NewAESGcm(wrapKey)
			if err != nil {
				b.Fatal(err)
			}
			encDEK, err := gcm.Encrypt(testDEK)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = asn1.Marshal(HybridNISTWrappedKey{
				HybridCiphertext: ct,
				EncryptedDEK:     encDEK,
			})
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})

	// P256+MLKEM768: same flow as X-Wing with different Encapsulate/PEM parse
	b.Run("P256_MLKEM768", func(b *testing.B) {
		for b.Loop() {
			pubKey, err := P256MLKEM768PubKeyFromPem([]byte(p256PubPEM))
			if err != nil {
				b.Fatal(err)
			}
			ss, ct, err := P256MLKEM768Encapsulate(pubKey)
			if err != nil {
				b.Fatal(err)
			}
			wrapKey, err := CalculateHKDF(salt, ss)
			if err != nil {
				b.Fatal(err)
			}
			gcm, err := NewAESGcm(wrapKey)
			if err != nil {
				b.Fatal(err)
			}
			encDEK, err := gcm.Encrypt(testDEK)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = asn1.Marshal(HybridNISTWrappedKey{
				HybridCiphertext: ct,
				EncryptedDEK:     encDEK,
			})
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})

	// P384+MLKEM1024: same flow with P384 variant
	b.Run("P384_MLKEM1024", func(b *testing.B) {
		for b.Loop() {
			pubKey, err := P384MLKEM1024PubKeyFromPem([]byte(p384PubPEM))
			if err != nil {
				b.Fatal(err)
			}
			ss, ct, err := P384MLKEM1024Encapsulate(pubKey)
			if err != nil {
				b.Fatal(err)
			}
			wrapKey, err := CalculateHKDF(salt, ss)
			if err != nil {
				b.Fatal(err)
			}
			gcm, err := NewAESGcm(wrapKey)
			if err != nil {
				b.Fatal(err)
			}
			encDEK, err := gcm.Encrypt(testDEK)
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = asn1.Marshal(HybridNISTWrappedKey{
				HybridCiphertext: ct,
				EncryptedDEK:     encDEK,
			})
		}
		b.ReportMetric(float64(len(sinkBytes)), "wrapped-bytes")
	})
}

// BenchmarkUnwrapDEK mirrors the actual KAS unwrap paths in
// service/internal/security/standard_crypto.go:Decrypt():
//   - RSA:    pre-loaded AsymDecryption.Decrypt (key already parsed)
//   - EC:     ECPrivateKeyFromPem (cached) -> NewSaltedECDecryptor(TDFSalt) -> DecryptWithEphemeralKey
//   - Hybrid: PrivateKeyFromPem -> UnwrapDEK  (PEM parsed each time in current KAS code)
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
	rsaEnc, err := NewAsymEncryption(rsaPubPEM)
	if err != nil {
		b.Fatal(err)
	}
	rsaWrapped, err := rsaEnc.Encrypt(testDEK)
	if err != nil {
		b.Fatal(err)
	}
	rsaDec, err := NewAsymDecryption(rsaPrivPEM)
	if err != nil {
		b.Fatal(err)
	}

	// EC P-256: KAS caches the parsed private key, creates decryptor per request
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
	// Wrap using the TDF path: ephemeral keygen + ECDH + HKDF + AES-GCM
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
	// KAS receives the ephemeral public key as DER (parsed from PEM in the manifest).
	// DecryptWithEphemeralKey first tries x509.ParsePKIXPublicKey (DER), then compressed.
	ecEphPubECDH, err := ECPubKeyFromPem([]byte(ecEphPubPEM))
	if err != nil {
		b.Fatal(err)
	}
	ecEphDER, err := x509.MarshalPKIXPublicKey(ecEphPubECDH)
	if err != nil {
		b.Fatal(err)
	}
	// KAS parses private key once (cached in StandardECCrypto)
	ecKASPrivKey, err := ECPrivateKeyFromPem([]byte(ecKASPrivPEM))
	if err != nil {
		b.Fatal(err)
	}

	// EC P-384: same flow as P-256, just on a different curve
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

	// X-Wing: KAS parses PEM each call, then calls UnwrapDEK
	xwingKP, err := NewXWingKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	xwingPrivPEM, err := xwingKP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	xwingWrapped, err := XWingWrapDEK(xwingKP.publicKey, testDEK)
	if err != nil {
		b.Fatal(err)
	}

	// P256+MLKEM768: KAS parses PEM each call, then calls UnwrapDEK
	p256KP, err := NewP256MLKEM768KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p256PrivPEM, err := p256KP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	p256Wrapped, err := P256MLKEM768WrapDEK(p256KP.publicKey, testDEK)
	if err != nil {
		b.Fatal(err)
	}

	// P384+MLKEM1024: KAS parses PEM each call, then calls UnwrapDEK
	p384KP, err := NewP384MLKEM1024KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p384PrivPEM, err := p384KP.PrivateKeyInPemFormat()
	if err != nil {
		b.Fatal(err)
	}
	p384Wrapped, err := P384MLKEM1024WrapDEK(p384KP.publicKey, testDEK)
	if err != nil {
		b.Fatal(err)
	}

	// RSA: KAS has pre-loaded AsymDecryption, just calls Decrypt
	b.Run("RSA-2048", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, errSink = rsaDec.Decrypt(rsaWrapped)
		}
	})

	// EC: KAS creates NewSaltedECDecryptor(cachedSK, TDFSalt, nil) -> DecryptWithEphemeralKey
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

	// X-Wing: KAS parses PEM then calls UnwrapDEK
	b.Run("XWing", func(b *testing.B) {
		for b.Loop() {
			privKey, err := XWingPrivateKeyFromPem([]byte(xwingPrivPEM))
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = XWingUnwrapDEK(privKey, xwingWrapped)
		}
	})

	// P256+MLKEM768: KAS parses PEM then calls UnwrapDEK
	b.Run("P256_MLKEM768", func(b *testing.B) {
		for b.Loop() {
			privKey, err := P256MLKEM768PrivateKeyFromPem([]byte(p256PrivPEM))
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = P256MLKEM768UnwrapDEK(privKey, p256Wrapped)
		}
	})

	// P384+MLKEM1024: KAS parses PEM then calls UnwrapDEK
	b.Run("P384_MLKEM1024", func(b *testing.B) {
		for b.Loop() {
			privKey, err := P384MLKEM1024PrivateKeyFromPem([]byte(p384PrivPEM))
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes, errSink = P384MLKEM1024UnwrapDEK(privKey, p384Wrapped)
		}
	})
}

func BenchmarkHybridSubOps(b *testing.B) {
	// Setup X-Wing
	xwingKP, err := NewXWingKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	xwingSS, xwingCt, err := XWingEncapsulate(xwingKP.publicKey)
	if err != nil {
		b.Fatal(err)
	}

	// Setup P256+MLKEM768
	p256KP, err := NewP256MLKEM768KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p256SS, p256Ct, err := P256MLKEM768Encapsulate(p256KP.publicKey)
	if err != nil {
		b.Fatal(err)
	}

	// Setup P384+MLKEM1024
	p384KP, err := NewP384MLKEM1024KeyPair()
	if err != nil {
		b.Fatal(err)
	}
	p384SS, p384Ct, err := P384MLKEM1024Encapsulate(p384KP.publicKey)
	if err != nil {
		b.Fatal(err)
	}

	salt := defaultTDFSalt()

	// Pre-derive a wrap key for AES-GCM benchmarks
	wrapKey, err := deriveXWingWrapKey(xwingSS, salt, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("XWing/Encapsulate", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, sinkBytes, errSink = XWingEncapsulate(xwingKP.publicKey)
		}
	})
	b.Run("XWing/HKDF", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, errSink = deriveXWingWrapKey(xwingSS, salt, nil)
		}
	})
	b.Run("XWing/AES-GCM-Encrypt", func(b *testing.B) {
		gcm, err := NewAESGcm(wrapKey)
		if err != nil {
			b.Fatal(err)
		}
		for b.Loop() {
			sinkBytes, errSink = gcm.Encrypt(testDEK)
		}
	})
	b.Run("XWing/ASN1-Marshal", func(b *testing.B) {
		wrapped := XWingWrappedKey{XWingCiphertext: xwingCt, EncryptedDEK: testDEK}
		for b.Loop() {
			sinkBytes, errSink = asn1.Marshal(wrapped)
		}
	})

	// P256+MLKEM768 sub-ops
	p256WrapKey, err := deriveHybridNISTWrapKey(p256SS, salt, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("P256_MLKEM768/Encapsulate", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, sinkBytes, errSink = P256MLKEM768Encapsulate(p256KP.publicKey)
		}
	})
	b.Run("P256_MLKEM768/HKDF", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, errSink = deriveHybridNISTWrapKey(p256SS, salt, nil)
		}
	})
	b.Run("P256_MLKEM768/AES-GCM-Encrypt", func(b *testing.B) {
		gcm, err := NewAESGcm(p256WrapKey)
		if err != nil {
			b.Fatal(err)
		}
		for b.Loop() {
			sinkBytes, errSink = gcm.Encrypt(testDEK)
		}
	})
	b.Run("P256_MLKEM768/ASN1-Marshal", func(b *testing.B) {
		wrapped := HybridNISTWrappedKey{HybridCiphertext: p256Ct, EncryptedDEK: testDEK}
		for b.Loop() {
			sinkBytes, errSink = asn1.Marshal(wrapped)
		}
	})

	// P384+MLKEM1024 sub-ops
	p384WrapKey, err := deriveHybridNISTWrapKey(p384SS, salt, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("P384_MLKEM1024/Encapsulate", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, sinkBytes, errSink = P384MLKEM1024Encapsulate(p384KP.publicKey)
		}
	})
	b.Run("P384_MLKEM1024/HKDF", func(b *testing.B) {
		for b.Loop() {
			sinkBytes, errSink = deriveHybridNISTWrapKey(p384SS, salt, nil)
		}
	})
	b.Run("P384_MLKEM1024/AES-GCM-Encrypt", func(b *testing.B) {
		gcm, err := NewAESGcm(p384WrapKey)
		if err != nil {
			b.Fatal(err)
		}
		for b.Loop() {
			sinkBytes, errSink = gcm.Encrypt(testDEK)
		}
	})
	b.Run("P384_MLKEM1024/ASN1-Marshal", func(b *testing.B) {
		wrapped := HybridNISTWrappedKey{HybridCiphertext: p384Ct, EncryptedDEK: testDEK}
		for b.Loop() {
			sinkBytes, errSink = asn1.Marshal(wrapped)
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
	rsaEnc, err := NewAsymEncryption(rsaPubPEM)
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
	xwingWrapped, err := XWingWrapDEK(xwingKP.publicKey, testDEK)
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
	p256Wrapped, err := P256MLKEM768WrapDEK(p256KP.publicKey, testDEK)
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
	p384Wrapped, err := P384MLKEM1024WrapDEK(p384KP.publicKey, testDEK)
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

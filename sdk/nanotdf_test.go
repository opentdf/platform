package sdk

import (
	"bytes"
	"encoding/gob"
	"io"
	"os"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// nanotdfEqual compares two nanoTdf structures for equality.
func nanoTDFEqual(a, b *NanoTDFHeader) bool {
	// Compare kasURL field
	if a.kasURL.protocol != b.kasURL.protocol || a.kasURL.getLength() != b.kasURL.getLength() || a.kasURL.body != b.kasURL.body {
		return false
	}

	// Compare binding field
	if a.bindCfg.useEcdsaBinding != b.bindCfg.useEcdsaBinding || a.bindCfg.padding != b.bindCfg.padding || a.bindCfg.eccMode != b.bindCfg.eccMode {
		return false
	}

	// Compare sigCfg field
	if a.sigCfg.hasSignature != b.sigCfg.hasSignature || a.sigCfg.signatureMode != b.sigCfg.signatureMode || a.sigCfg.cipher != b.sigCfg.cipher {
		return false
	}

	// Compare policy field
	// if a.PolicyBinding  != b.PolicyBinding) {
	// 	return false
	// }

	// Compare EphemeralPublicKey field
	if !bytes.Equal(a.EphemeralKey, b.EphemeralKey) {
		return false
	}

	// If all comparisons passed, the structures are equal
	return true
}

//// policyBodyEqual compares two PolicyBody instances for equality.
// func policyBodyEqual(a, b PolicyBody) bool { //nolint:unused future usage
//	// Compare based on the concrete type of PolicyBody
//	switch a.mode {
//	case policyTypeRemotePolicy:
//		return remotePolicyEqual(a.rp, b.rp)
//	case policyTypeEmbeddedPolicyPlainText:
//	case policyTypeEmbeddedPolicyEncrypted:
//	case policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess:
//		return embeddedPolicyEqual(a.ep, b.ep)
//	}
//	return false
// }

//// remotePolicyEqual compares two remotePolicy instances for equality.
// func remotePolicyEqual(a, b remotePolicy) bool { // nolint:unused future usage
//	// Compare url field
//	if a.url.protocol != b.url.protocol || a.url.getLength() != b.url.getLength() || a.url.body != b.url.body {
//		return false
//	}
//	return true
// }
//
//// embeddedPolicyEqual compares two embeddedPolicy instances for equality.
// func embeddedPolicyEqual(a, b embeddedPolicy) bool { // nolint:unused future usage
//	// Compare lengthBody and body fields
//	return a.lengthBody == b.lengthBody && bytes.Equal(a.body, b.body)
// }
//
//// eccSignatureEqual compares two eccSignature instances for equality.
// func eccSignatureEqual(a, b *eccSignature) bool { // nolint:unused future usage
//	// Compare value field
//	return bytes.Equal(a.value, b.value)
// }

func init() {
	// Register the remotePolicy type with gob
	gob.Register(&remotePolicy{})
}

func NotTestReadNanoTDFHeader(t *testing.T) {
	// Prepare a sample nanoTdf structure
	goodHeader := NanoTDFHeader{
		kasURL: ResourceLocator{
			protocol: urlProtocolHTTPS,
			body:     "kas.virtru.com",
		},
		bindCfg: bindingConfig{
			useEcdsaBinding: true,
			padding:         0,
			eccMode:         ocrypto.ECCModeSecp256r1,
		},
		sigCfg: signatureConfig{
			hasSignature:  true,
			signatureMode: ocrypto.ECCModeSecp256r1,
			cipher:        cipherModeAes256gcm64Bit,
		},
		//PolicyBinding: policyInfo{
		//	body: PolicyBody{
		//		mode: policyTypeRemotePolicy,
		//		rp: remotePolicy{
		//			url: ResourceLocator{
		//				protocol: urlProtocolHTTPS,
		//				body:     "kas.virtru.com/policy",
		//			},
		//		},
		//	},
		//	binding: &eccSignature{
		//		value: []byte{181, 228, 19, 166, 2, 17, 229, 241},
		//	},
		// },
		EphemeralKey: []byte{123, 34, 52, 160, 205, 63, 54, 255, 123, 186, 109,
			143, 232, 223, 35, 246, 44, 157, 9, 53, 111, 133,
			130, 248, 169, 207, 21, 18, 108, 138, 157, 164, 108},
	}

	const (
		kExpectedHeaderSize = 128
	)

	// Serialize the sample nanoTdf structure into a byte slice using gob
	file, err := os.Open("nanotdfspec.ntdf")
	if err != nil {
		t.Fatalf("Cannot open nanoTdf file: %v", err)
	}
	defer file.Close()

	resultHeader, headerSize, err := NewNanoTDFHeaderFromReader(io.ReadSeeker(file))
	if err != nil {
		t.Fatalf("Error while reading nanoTdf header: %v", err)
	}

	if headerSize != kExpectedHeaderSize {
		t.Fatalf("expecting length %d, got %d", kExpectedHeaderSize, headerSize)
	}

	// Compare the result with the original nanoTdf structure
	if !nanoTDFEqual(&resultHeader, &goodHeader) {
		t.Error("Result does not match the expected nanoTdf structure.")
	}
}

const (
//	sdkPrivateKey = `-----BEGIN PRIVATE KEY-----
// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1HjFYV8D16BQszNW
// 6Hx/JxTE53oqk5/bWaIj4qV5tOyhRANCAAQW1Hsq0tzxN6ObuXqV+JoJN0f78Em/
// PpJXUV02Y6Ex3WlxK/Oaebj8ATsbfaPaxrhyCWB3nc3w/W6+lySlLPn5
// -----END PRIVATE KEY-----`

//	sdkPublicKey = `-----BEGIN PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFtR7KtLc8Tejm7l6lfiaCTdH+/BJ
// vz6SV1FdNmOhMd1pcSvzmnm4/AE7G32j2sa4cglgd53N8P1uvpckpSz5+Q==
// -----END PUBLIC KEY-----`

//	kasPrivateKey = `-----BEGIN PRIVATE KEY-----
// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu2Hmm80uUzQB1OfB
// PyMhWIyJhPA61v+j0arvcLjTwtqhRANCAASHCLUHY4szFiVV++C9+AFMkEL2gG+O
// byN4Hi7Ywl8GMPOAPcQdIeUkoTd9vub9PcuSj23I8/pLVzs23qhefoUf
// -----END PRIVATE KEY-----`

//	kasPublicKey = `-----BEGIN PUBLIC KEY-----
//
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhwi1B2OLMxYlVfvgvfgBTJBC9oBv
// jm8jeB4u2MJfBjDzgD3EHSHlJKE3fb7m/T3Lko9tyPP6S1c7Nt6oXn6FHw==
// -----END PUBLIC KEY-----`
)

// disabled for now, no remote policy support yet
func NotTestNanoTDFEncryptFile(t *testing.T) {
	const (
		kExpectedOutSize = 128
	)

	var s SDK
	infile, err := os.Open("nanotest1.txt")
	if err != nil {
		t.Fatal(err)
	}

	// try to delete the output file in case it exists already - ignore error if it doesn't exist
	_ = os.Remove("nanotest1.ntdf")

	outfile, err := os.Create("nanotest1.ntdf")
	if err != nil {
		t.Fatal(err)
	}

	// TODO - populate config properly
	var kasURL = "https://kas.virtru.com/kas"
	var config NanoTDFConfig
	err = config.kasURL.setURL(kasURL)
	if err != nil {
		t.Fatal(err)
	}

	outSize, err := s.CreateNanoTDF(io.Writer(outfile), io.ReadSeeker(infile), config)
	if err != nil {
		t.Fatal(err)
	}
	if outSize != kExpectedOutSize {
		t.Fatalf("expecting length %d, got %d", kExpectedOutSize, outSize)
	}
}

// disabled for now
func NotTestCreateNanoTDF(t *testing.T) {
	var s SDK

	grpc.WithTransportCredentials(insecure.NewCredentials())

	infile, err := os.Open("nanotest1.txt")
	if err != nil {
		t.Fatal(err)
	}

	// try to delete the output file in case it exists already - ignore error if it doesn't exist
	_ = os.Remove("nanotest1.ntdf")

	outfile, err := os.Create("nanotest1.ntdf")
	if err != nil {
		t.Fatal(err)
	}

	// TODO - populate config properly
	var kasURL = "https://kas.virtru.com/kas"
	var config NanoTDFConfig
	err = config.kasURL.setURL(kasURL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.CreateNanoTDF(io.Writer(outfile), io.ReadSeeker(infile), config)
	if err != nil {
		t.Fatal(err)
	}
}

package sdk

import (
	"bytes"
	"encoding/gob"
	"os"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
)

// nanotdfEqual compares two nanoTdf structures for equality.
func nanoTDFEqual(a, b *NanoTDFHeader) bool {
	// Compare magicNumber field
	if a.magicNumber != b.magicNumber {
		return false
	}

	// Compare kasURL field
	if a.kasURL.protocol != b.kasURL.protocol || a.kasURL.lengthBody != b.kasURL.lengthBody || a.kasURL.body != b.kasURL.body {
		return false
	}

	// Compare binding field
	if a.binding.useEcdsaBinding != b.binding.useEcdsaBinding || a.binding.padding != b.binding.padding || a.binding.bindingBody != b.binding.bindingBody {
		return false
	}

	// Compare sigCfg field
	if a.sigCfg.hasSignature != b.sigCfg.hasSignature || a.sigCfg.signatureMode != b.sigCfg.signatureMode || a.sigCfg.cipher != b.sigCfg.cipher {
		return false
	}

	// Compare policy field
	if a.policy.mode != b.policy.mode || !policyBodyEqual(a.policy.body, b.policy.body) || !eccSignatureEqual(a.policy.binding, b.policy.binding) {
		return false
	}

	// Compare EphemeralPublicKey field
	if !bytes.Equal(a.EphemeralPublicKey.Key, b.EphemeralPublicKey.Key) {
		return false
	}

	// If all comparisons passed, the structures are equal
	return true
}

// policyBodyEqual compares two PolicyBody instances for equality.
func policyBodyEqual(a, b PolicyBody) bool {
	// Compare based on the concrete type of PolicyBody
	switch a := a.(type) {
	case remotePolicy:
		b, ok := b.(remotePolicy)
		if !ok {
			return false
		}
		return remotePolicyEqual(a, b)
	case embeddedPolicy:
		b, ok := b.(embeddedPolicy)
		if !ok {
			return false
		}
		return embeddedPolicyEqual(a, b)
	default:
		// Handle other types as needed
		return false
	}
}

// remotePolicyEqual compares two remotePolicy instances for equality.
func remotePolicyEqual(a, b remotePolicy) bool {
	// Compare url field
	if a.url.protocol != b.url.protocol || a.url.lengthBody != b.url.lengthBody || a.url.body != b.url.body {
		return false
	}
	return true
}

// embeddedPolicyEqual compares two embeddedPolicy instances for equality.
func embeddedPolicyEqual(a, b embeddedPolicy) bool {
	// Compare lengthBody and body fields
	return a.lengthBody == b.lengthBody && a.body == b.body
}

// eccSignatureEqual compares two eccSignature instances for equality.
func eccSignatureEqual(a, b *eccSignature) bool {
	// Compare value field
	return bytes.Equal(a.value, b.value)
}

func init() {
	// Register the remotePolicy type with gob
	gob.Register(&remotePolicy{})
}

func TestReadNanoTDFHeader(t *testing.T) {
	// Prepare a sample nanoTdf structure
	nanoTDF := NanoTDFHeader{
		magicNumber: [3]byte{'L', '1', 'L'},
		kasURL: &resourceLocator{
			protocol:   urlProtocolHTTPS,
			lengthBody: 14,
			body:       "kas.virtru.com",
		},
		binding: &bindingCfg{
			useEcdsaBinding: true,
			padding:         0,
			bindingBody:     ocrypto.ECCModeSecp256r1,
		},
		sigCfg: &signatureConfig{
			hasSignature:  true,
			signatureMode: ocrypto.ECCModeSecp256r1,
			cipher:        cipherModeAes256gcm64Bit,
		},
		policy: &policyInfo{
			mode: uint8(policyTypeRemotePolicy),
			body: remotePolicy{
				url: &resourceLocator{
					protocol:   urlProtocolHTTPS,
					lengthBody: 21,
					body:       "kas.virtru.com/policy",
				},
			},
			binding: &eccSignature{
				value: []byte{181, 228, 19, 166, 2, 17, 229, 241},
			},
		},
		EphemeralPublicKey: &eccKey{
			Key: []byte{123, 34, 52, 160, 205, 63, 54, 255, 123, 186, 109,
				143, 232, 223, 35, 246, 44, 157, 9, 53, 111, 133,
				130, 248, 169, 207, 21, 18, 108, 138, 157, 164, 108},
		},
	}

	// Serialize the sample nanoTdf structure into a byte slice using gob
	file, err := os.Open("nanotdfspec.ntdf")
	if err != nil {
		t.Fatalf("Cannot open nanoTdf file: %v", err)
	}
	defer file.Close()

	result, err := ReadNanoTDFHeader(file)
	if err != nil {
		t.Fatalf("Error while reading nanoTdf header: %v", err)
	}

	// Compare the result with the original nanoTdf structure
	if !nanoTDFEqual(result, &nanoTDF) {
		t.Error("Result does not match the expected nanoTdf structure.")
	}
}

const (
	sdkPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1HjFYV8D16BQszNW
6Hx/JxTE53oqk5/bWaIj4qV5tOyhRANCAAQW1Hsq0tzxN6ObuXqV+JoJN0f78Em/
PpJXUV02Y6Ex3WlxK/Oaebj8ATsbfaPaxrhyCWB3nc3w/W6+lySlLPn5
-----END PRIVATE KEY-----`

	//	sdkPublicKey = `-----BEGIN PUBLIC KEY-----
	// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFtR7KtLc8Tejm7l6lfiaCTdH+/BJ
	// vz6SV1FdNmOhMd1pcSvzmnm4/AE7G32j2sa4cglgd53N8P1uvpckpSz5+Q==
	// -----END PUBLIC KEY-----`

	//	kasPrivateKey = `-----BEGIN PRIVATE KEY-----
	// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu2Hmm80uUzQB1OfB
	// PyMhWIyJhPA61v+j0arvcLjTwtqhRANCAASHCLUHY4szFiVV++C9+AFMkEL2gG+O
	// byN4Hi7Ywl8GMPOAPcQdIeUkoTd9vub9PcuSj23I8/pLVzs23qhefoUf
	// -----END PRIVATE KEY-----`

	kasPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhwi1B2OLMxYlVfvgvfgBTJBC9oBv
jm8jeB4u2MJfBjDzgD3EHSHlJKE3fb7m/T3Lko9tyPP6S1c7Nt6oXn6FHw==
-----END PUBLIC KEY-----`
)

func TestNanoTDFEncryptFile(t *testing.T) {
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
	config.mBufferSize = 8192 * 1024
	config.mKasURL.body = kasURL // TODO - check for excessive length here
	config.mKasURL.lengthBody = uint8(len(kasURL))
	config.mKasURL.protocol = urlProtocolHTTPS // TODO FIXME - should be derived from URL
	config.mPrivateKey = sdkPrivateKey
	config.mKasPublicKey = kasPublicKey
	config.mEccMode = ocrypto.ECCModeSecp256r1

	err = NanoTDFEncryptFile(infile, outfile, config)
	if err != nil {
		t.Fatal(err)
	}
}

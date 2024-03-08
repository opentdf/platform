package nanotdf

import (
	"bytes"
	"encoding/gob"
	"os"
	"testing"
)

// nanotdfEqual compares two nanoTdf structures for equality.
func nanoTDFEqual(a, b *nanoTdf) bool {
	// Compare magicNumber field
	if a.magicNumber != b.magicNumber {
		return false
	}

	// Compare kasUrl field
	if a.kasUrl.protocol != b.kasUrl.protocol || a.kasUrl.lengthBody != b.kasUrl.lengthBody || a.kasUrl.body != b.kasUrl.body {
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
	nanoTDF := nanoTdf{
		magicNumber: [3]byte{'L', '1', 'L'},
		kasUrl: &resourceLocator{
			protocol:   urlProtocolHttps,
			lengthBody: 14,
			body:       "kas.virtru.com",
		},
		binding: &bindingCfg{
			useEcdsaBinding: true,
			padding:         0,
			bindingBody:     eccModeSecp256r1,
		},
		sigCfg: &signatureConfig{
			hasSignature:  true,
			signatureMode: eccModeSecp256r1,
			cipher:        cipherModeAes256gcm64Bit,
		},
		policy: &policyInfo{
			mode: uint8(policyTypeRemotePolicy),
			body: remotePolicy{
				url: &resourceLocator{
					protocol:   urlProtocolHttps,
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

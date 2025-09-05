package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// AssertionBindingStyle defines how assertions are bound to TDFs
type AssertionBindingStyle int

const (
	// BindingStyleLegacy uses generic assertionHash and assertionSig claims
	// This is the original SDK approach - flexible but less secure
	BindingStyleLegacy AssertionBindingStyle = iota

	// BindingStyleSecure uses tdfPolicyHash and keyAccessDigest claims
	// This is the otdfctl approach - cryptographically binds assertion to specific TDF components
	BindingStyleSecure

	// BindingStyleAuto detects the style based on available claims (for validation)
	BindingStyleAuto
)

// AssertionBinding contains the computed hashes for binding an assertion to a TDF
type AssertionBinding struct {
	// For secure binding (recommended)
	TDFPolicyHash   string `json:"tdfPolicyHash,omitempty"`
	KeyAccessDigest string `json:"keyAccessDigest,omitempty"`

	// For legacy binding (backward compatibility)
	AssertionHash string `json:"assertionHash,omitempty"`
	AssertionSig  string `json:"assertionSig,omitempty"`
}

// ComputeTDFPolicyHash computes the SHA-256 hash of the TDF policy object
func ComputeTDFPolicyHash(policyJSON []byte) (string, error) {
	// The policy should be the canonicalized JSON from the manifest
	hash := sha256.Sum256(policyJSON)
	return hex.EncodeToString(hash[:]), nil
}

// ComputeKeyAccessDigest computes the SHA-256 hash of the key access object
func ComputeKeyAccessDigest(keyAccessJSON []byte) (string, error) {
	// The key access object contains the wrapped key and KAS information
	hash := sha256.Sum256(keyAccessJSON)
	return hex.EncodeToString(hash[:]), nil
}

// ComputeSecureBinding computes the secure assertion binding for a TDF manifest
func ComputeSecureBinding(manifest interface{}) (*AssertionBinding, error) {
	// Extract policy and key access from manifest
	manifestMap, ok := manifest.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid manifest format")
	}

	encInfo, ok := manifestMap["encryptionInformation"].(map[string]interface{})
	if !ok {
		return nil, errors.New("encryptionInformation not found in manifest")
	}

	// Compute policy hash
	policy, ok := encInfo["policy"]
	if !ok {
		return nil, errors.New("policy not found in manifest")
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	policyHash, err := ComputeTDFPolicyHash(policyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to compute policy hash: %w", err)
	}

	// Compute key access digest
	keyAccess, ok := encInfo["keyAccess"]
	if !ok {
		return nil, errors.New("keyAccess not found in manifest")
	}

	keyAccessJSON, err := json.Marshal(keyAccess)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keyAccess: %w", err)
	}

	keyAccessDigest, err := ComputeKeyAccessDigest(keyAccessJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to compute key access digest: %w", err)
	}

	return &AssertionBinding{
		TDFPolicyHash:   policyHash,
		KeyAccessDigest: keyAccessDigest,
	}, nil
}

// JWT claim keys for secure binding style
const (
	// Secure binding claims (recommended)
	kTDFPolicyHash   = "tdfPolicyHash"
	kKeyAccessDigest = "keyAccessDigest"

	// Legacy binding claims are defined in tdf.go:
	// kAssertionHash = "assertionHash"
	// kAssertionSignature = "assertionSig"
)

// GetBindingClaims returns the appropriate JWT claims based on the binding style
func GetBindingClaims(style AssertionBindingStyle, binding *AssertionBinding) map[string]interface{} {
	claims := make(map[string]interface{})

	switch style {
	case BindingStyleSecure:
		if binding.TDFPolicyHash != "" {
			claims[kTDFPolicyHash] = binding.TDFPolicyHash
		}
		if binding.KeyAccessDigest != "" {
			claims[kKeyAccessDigest] = binding.KeyAccessDigest
		}
	case BindingStyleLegacy:
		if binding.AssertionHash != "" {
			claims[kAssertionHash] = binding.AssertionHash
		}
		if binding.AssertionSig != "" {
			claims[kAssertionSignature] = binding.AssertionSig
		}
	case BindingStyleAuto:
		// For auto style, include both secure and legacy claims if available
		if binding.TDFPolicyHash != "" {
			claims[kTDFPolicyHash] = binding.TDFPolicyHash
		}
		if binding.KeyAccessDigest != "" {
			claims[kKeyAccessDigest] = binding.KeyAccessDigest
		}
		if binding.AssertionHash != "" {
			claims[kAssertionHash] = binding.AssertionHash
		}
		if binding.AssertionSig != "" {
			claims[kAssertionSignature] = binding.AssertionSig
		}
	}

	return claims
}

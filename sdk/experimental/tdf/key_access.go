// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/experimental/tdf/keysplit"
)

var tdfSaltBytes []byte

// tdfSalt generates the standard TDF salt for key derivation
func init() {
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	tdfSaltBytes = digest.Sum(nil)
}

func tdfSalt() []byte {
	return tdfSaltBytes
}

// BuildKeyAccessObjects creates KeyAccess objects from splits for TDF manifest inclusion
func buildKeyAccessObjects(result *keysplit.SplitResult, policyBytes []byte, metadata string) ([]KeyAccess, error) {
	if result == nil || len(result.Splits) == 0 {
		return nil, errors.New("no splits provided")
	}

	var keyAccessList []KeyAccess

	// Create base64-encoded policy for binding
	base64Policy := string(ocrypto.Base64Encode(policyBytes))

	for _, split := range result.Splits {
		for _, kasURL := range split.KASURLs {
			// Get public key info for this KAS
			pubKeyInfo, exists := result.KASPublicKeys[kasURL]
			if !exists {
				slog.Warn("no public key found for KAS, skipping",
					slog.String("kas_url", kasURL),
					slog.String("split_id", split.ID))
				continue
			}

			// Create policy binding
			policyBinding := createPolicyBinding(split.Data, base64Policy)

			// Encrypt metadata if provided
			var encryptedMetadata string
			if metadata != "" {
				var err error
				encryptedMetadata, err = encryptMetadata(split.Data, metadata)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt metadata for KAS %s: %w", kasURL, err)
				}
			}

			// Encrypt the split key with KAS public key
			wrappedKey, keyType, ephemeralPubKey, err := wrapKeyWithPublicKey(split.Data, pubKeyInfo)
			if err != nil {
				return nil, fmt.Errorf("failed to wrap key for KAS %s: %w", kasURL, err)
			}

			// Build the KeyAccess object
			keyAccess := KeyAccess{
				KeyType:           keyType,
				KasURL:            kasURL,
				KID:               pubKeyInfo.KID,
				Protocol:          "kas",
				SplitID:           split.ID,
				WrappedKey:        wrappedKey,
				PolicyBinding:     policyBinding,
				EncryptedMetadata: encryptedMetadata,
			}

			// Add ephemeral public key for EC keys
			if ephemeralPubKey != "" {
				keyAccess.EphemeralPublicKey = ephemeralPubKey
			}

			keyAccessList = append(keyAccessList, keyAccess)

			slog.Debug("created key access object",
				slog.String("kas_url", kasURL),
				slog.String("split_id", split.ID),
				slog.String("key_type", keyType),
				slog.String("kid", pubKeyInfo.KID))
		}
	}

	if len(keyAccessList) == 0 {
		return nil, errors.New("no valid key access objects generated")
	}

	slog.Debug("built key access objects",
		slog.Int("num_key_access", len(keyAccessList)),
		slog.Int("num_splits", len(result.Splits)))

	return keyAccessList, nil
}

// createPolicyBinding creates an HMAC binding between the key and policy
func createPolicyBinding(symKey []byte, base64PolicyObject string) any {
	// Create HMAC hash of the policy using the symmetric key
	hmacHash := ocrypto.CalculateSHA256Hmac(symKey, []byte(base64PolicyObject))

	// Convert to hex string
	hashHex := hex.EncodeToString(hmacHash)

	// Create policy binding structure
	binding := PolicyBinding{
		Alg:  kPolicyBindingAlg,
		Hash: string(ocrypto.Base64Encode([]byte(hashHex))),
	}

	// Return as any to match KeyAccess.PolicyBinding field
	return binding
}

// encryptMetadata encrypts TDF metadata using the split key
func encryptMetadata(symKey []byte, metadata string) (string, error) {
	// Create AES-GCM cipher
	gcm, err := ocrypto.NewAESGcm(symKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES-GCM: %w", err)
	}

	// Encrypt the metadata
	encryptedBytes, err := gcm.Encrypt([]byte(metadata))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Extract IV (first 12 bytes for GCM)
	iv := encryptedBytes[:ocrypto.GcmStandardNonceSize]

	// Create encrypted metadata structure
	encMeta := EncryptedMetadata{
		Cipher: string(ocrypto.Base64Encode(encryptedBytes)),
		Iv:     string(ocrypto.Base64Encode(iv)),
	}

	// Serialize to JSON and base64 encode
	metadataJSON, err := json.Marshal(encMeta)
	if err != nil {
		return "", fmt.Errorf("failed to marshal encrypted metadata: %w", err)
	}

	return string(ocrypto.Base64Encode(metadataJSON)), nil
}

// wrapKeyWithPublicKey encrypts a symmetric key with a KAS public key
func wrapKeyWithPublicKey(symKey []byte, pubKeyInfo keysplit.KASPublicKey) (string, string, string, error) {
	if pubKeyInfo.PEM == "" {
		return "", "", "", fmt.Errorf("public key PEM is empty for KAS %s", pubKeyInfo.URL)
	}

	kasPublicKey, err := ocrypto.FromPublicPEM(pubKeyInfo.PEM)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse KAS public key: %w", err)
	}

	switch kasPublicKey.Type() {
	case ocrypto.EC:
		epk, ok := kasPublicKey.(ocrypto.ECEncryptor)
		if !ok {
			return "", "", "", fmt.Errorf("unexpected encryptor type %T", kasPublicKey)
		}
		return wrapKeyWithEC(epk.KeyType(), epk, symKey)
	case ocrypto.RSA:
		wrapped, err := wrapKeyWithRSA(kasPublicKey, symKey)
		return wrapped, "wrapped", "", err
	default:
		return "", "", "", fmt.Errorf("unsupported KAS public key type: %v", kasPublicKey.KeyType())
	}
}

// wrapKeyWithEC encrypts a key using EC public key with ECIES
func wrapKeyWithEC(keyType ocrypto.KeyType, kasPublicKey ocrypto.ECEncryptor, symKey []byte) (string, string, string, error) {
	if !ocrypto.IsECKeyType(kasPublicKey.KeyType()) {
		return "", "", "", fmt.Errorf("unexpected KAS public key type: %v", kasPublicKey.KeyType())
	}

	wrapped, err := kasPublicKey.Encrypt(symKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to wrap with %v: %w", keyType, err)
	}

	epk, err := kasPublicKey.EphemeralPublicKeyInPemFormat()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to export ephemeral public key: %w", err)
	}

	return string(ocrypto.Base64Encode(wrapped)), "ec-wrapped", epk, nil
}

// wrapKeyWithRSA encrypts a key using RSA public key with OAEP padding
func wrapKeyWithRSA(encryptor ocrypto.PublicKeyEncryptor, symKey []byte) (string, error) {
	// Encrypt with OAEP padding
	encryptedKey, err := encryptor.Encrypt(symKey)
	if err != nil {
		return "", fmt.Errorf("failed to RSA encrypt key: %w", err)
	}

	return string(ocrypto.Base64Encode(encryptedKey)), nil
}

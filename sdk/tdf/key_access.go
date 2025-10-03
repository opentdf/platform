package tdf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/tdf/keysplit"
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

	// Determine key type based on algorithm
	ktype := ocrypto.KeyType(pubKeyInfo.Algorithm)

	if ocrypto.IsECKeyType(ktype) {
		// Handle EC key wrapping
		return wrapKeyWithEC(ktype, pubKeyInfo.PEM, symKey)
	}
	// Handle RSA key wrapping
	wrapped, err := wrapKeyWithRSA(pubKeyInfo.PEM, symKey)
	return wrapped, "wrapped", "", err
}

// wrapKeyWithEC encrypts a key using EC public key with ECIES
func wrapKeyWithEC(keyType ocrypto.KeyType, kasPublicKeyPEM string, symKey []byte) (string, string, string, error) {
	// Convert key type to ECC mode
	mode, err := ocrypto.ECKeyTypeToMode(keyType)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to convert key type to ECC mode: %w", err)
	}

	// Generate ephemeral key pair
	ecKeyPair, err := ocrypto.NewECKeyPair(mode)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create EC key pair: %w", err)
	}

	// Get ephemeral public key in PEM format
	ephemeralPubKey, err := ecKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get ephemeral public key: %w", err)
	}

	// Get ephemeral private key
	ephemeralPrivKey, err := ecKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get ephemeral private key: %w", err)
	}

	// Compute ECDH shared secret
	ecdhKey, err := ocrypto.ComputeECDHKey([]byte(ephemeralPrivKey), []byte(kasPublicKeyPEM))
	if err != nil {
		return "", "", "", fmt.Errorf("failed to compute ECDH key: %w", err)
	}

	// Derive wrapping key using HKDF
	salt := tdfSalt()
	wrapKey, err := ocrypto.CalculateHKDF(salt, ecdhKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to derive wrap key: %w", err)
	}

	// Ensure we have the right length for wrapping (trim or pad as needed)
	if len(wrapKey) > len(symKey) {
		wrapKey = wrapKey[:len(symKey)]
	} else if len(wrapKey) < len(symKey) {
		return "", "", "", fmt.Errorf("wrap key too short: got %d, expected at least %d",
			len(wrapKey), len(symKey))
	}

	wrapped := make([]byte, len(symKey))
	for i := range symKey {
		wrapped[i] = symKey[i] ^ wrapKey[i]
	}

	return string(ocrypto.Base64Encode(wrapped)), "eccWrapped", ephemeralPubKey, nil
}

// wrapKeyWithRSA encrypts a key using RSA public key with OAEP padding
func wrapKeyWithRSA(kasPublicKeyPEM string, symKey []byte) (string, error) {
	// Create RSA encryptor from PEM
	encryptor, err := ocrypto.FromPublicPEM(kasPublicKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to create RSA encryptor: %w", err)
	}

	// Encrypt with OAEP padding
	encryptedKey, err := encryptor.Encrypt(symKey)
	if err != nil {
		return "", fmt.Errorf("failed to RSA encrypt key: %w", err)
	}

	return string(ocrypto.Base64Encode(encryptedKey)), nil
}

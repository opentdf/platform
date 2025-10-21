package ocrypto

import (
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidPEMBlock indicates the input could not be decoded as a PEM block
	ErrInvalidPEMBlock = errors.New("invalid pem: failed to decode block or wrong type")
	// ErrInvalidPublicKey indicates the PEM contents could not be parsed as a public key
	ErrInvalidPublicKey = errors.New("invalid pem: failed to parse public key")
	// ErrUnsupportedPublicKeyType indicates a non-RSA/EC public key was provided
	ErrUnsupportedPublicKeyType = errors.New("unsupported public key type")
	// ErrInvalidRSAKeySize indicates an RSA key size that is not supported
	ErrInvalidRSAKeySize = errors.New("invalid rsa key size")
	// ErrInvalidECCurve indicates an EC curve that is not supported
	ErrInvalidECCurve = errors.New("invalid ec key curve")
)

// PublicKeyInfo captures parsed metadata about a PEM public key.
type KeySource string

const (
	// KeySourcePublicKey indicates the PEM block type was PUBLIC KEY
	KeySourcePublicKey KeySource = "public-key"
	// KeySourceCertificate indicates the PEM block type was CERTIFICATE
	KeySourceCertificate KeySource = "certificate"
)

type PublicKeyInfo struct {
	Type    KeyType
	RSABits int
	ECCurve ECCMode
	// Source indicates where the key was parsed from.
	Source KeySource
}

// ValidatePublicKeyPEM validates a PKIX PEM public key, or a certificate
// containing a public key. It returns basic information about the key when
// valid, otherwise an error describing the validation failure.
//
// Behavior:
// - Scans all PEM blocks provided.
// - For supported blocks (PUBLIC KEY or CERTIFICATE):
//   - If parsing/classification fails, return an error immediately.
//   - If valid, remember the first valid key found.
//
// - Returns the first valid key if any; otherwise ErrInvalidPEMBlock.
//
// Supported algorithms: RSA 2048/4096 and EC P-256/P-384/P-521.
func ValidatePublicKeyPEM(pemBytes []byte) (*PublicKeyInfo, error) {
	var firstValid *PublicKeyInfo

	data := pemBytes
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		switch block.Type {
		case "PUBLIC KEY", "CERTIFICATE":
			pemStr := string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}))
			enc, err := FromPublicPEM(pemStr)
			if err != nil {
				if strings.Contains(err.Error(), "unsupported type of public key") {
					return nil, ErrUnsupportedPublicKeyType
				}
				if strings.Contains(err.Error(), "unsupported curve") {
					return nil, ErrInvalidECCurve
				}
				return nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
			}
			// Determine source
			src := KeySourcePublicKey
			if block.Type == "CERTIFICATE" {
				src = KeySourceCertificate
			}

			// Classify based on concrete encryptor type (build once, assign once)
			var info *PublicKeyInfo
			switch e := enc.(type) {
			case *AsymEncryption:
				// RSA path; compute bit length and enforce allowed sizes
				bits := e.PublicKey.N.BitLen()
				switch bits {
				case RSA2048Size:
					info = &PublicKeyInfo{Type: RSA2048Key, RSABits: RSA2048Size, Source: src}
				case RSA4096Size:
					info = &PublicKeyInfo{Type: RSA4096Key, RSABits: RSA4096Size, Source: src}
				default:
					return nil, fmt.Errorf("%w: %d", ErrInvalidRSAKeySize, bits)
				}
			case ECEncryptor:
				// EC path; rely on KeyType mapping via helper
				kt := e.KeyType()
				if curve, err := ECKeyTypeToMode(kt); err == nil {
					info = &PublicKeyInfo{Type: kt, ECCurve: curve, Source: src}
				} else {
					return nil, ErrInvalidECCurve
				}
			default:
				return nil, ErrUnsupportedPublicKeyType
			}
			if firstValid == nil {
				firstValid = info
			}
		default:
			// ignore unrelated block types
		}

		data = rest
	}

	if firstValid != nil {
		return firstValid, nil
	}
	return nil, ErrInvalidPEMBlock
}

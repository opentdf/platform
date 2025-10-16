package ocrypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
type PublicKeyInfo struct {
	Type    KeyType
	RSABits int
	ECCurve ECCMode
	// Source indicates where the key was parsed from: "public-key" or "certificate".
	// Empty means unspecified.
	Source string
}

const (
	// SourcePublicKey indicates the PEM block type was PUBLIC KEY
	SourcePublicKey = "public-key"
	// SourceCertificate indicates the PEM block type was CERTIFICATE
	SourceCertificate = "certificate"
)

// ValidatePublicKeyPEM validates a PKIX PEM public key, or a certificate
// containing a public key. It returns basic information about the key when
// valid, otherwise an error describing the validation failure.
//
// Behavior:
// - Scans all PEM blocks provided.
// - For supported blocks (PUBLIC KEY or CERTIFICATE):
//   - If parsing/classification fails, return an error immediately.
//   - If valid, remember the first valid key found.
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
        case "PUBLIC KEY":
            pub, err := x509.ParsePKIXPublicKey(block.Bytes)
            if err != nil {
                return nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
            }
            info, err := classifyPublicKey(pub, SourcePublicKey)
            if err != nil {
                return nil, err
            }
            if firstValid == nil {
                firstValid = info
            }
        case "CERTIFICATE":
            cert, err := x509.ParseCertificate(block.Bytes)
            if err != nil {
                return nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
            }
            info, err := classifyPublicKey(cert.PublicKey, SourceCertificate)
            if err != nil {
                return nil, err
            }
            if firstValid == nil {
                firstValid = info
            }
        default:
            // ignore unrelated block types
        }

        data = rest
        if len(data) == 0 {
            break
        }
    }

    if firstValid != nil {
        return firstValid, nil
    }
    return nil, ErrInvalidPEMBlock
}

func classifyPublicKey(pub any, source string) (*PublicKeyInfo, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		switch bits {
		case RSA2048Size:
			return &PublicKeyInfo{Type: RSA2048Key, RSABits: bits, Source: source}, nil
		case RSA4096Size:
			return &PublicKeyInfo{Type: RSA4096Key, RSABits: bits, Source: source}, nil
		default:
			return nil, fmt.Errorf("%w: %d", ErrInvalidRSAKeySize, bits)
		}

    case *ecdsa.PublicKey:
        // Use the named curve rather than bit length to avoid ambiguity with
        // similarly sized but unsupported curves (e.g., secp256k1).
        switch k.Params().Name {
        case "P-256":
            return &PublicKeyInfo{Type: EC256Key, ECCurve: ECCModeSecp256r1, Source: source}, nil
        case "P-384":
            return &PublicKeyInfo{Type: EC384Key, ECCurve: ECCModeSecp384r1, Source: source}, nil
        case "P-521":
            return &PublicKeyInfo{Type: EC521Key, ECCurve: ECCModeSecp521r1, Source: source}, nil
        default:
            return nil, ErrInvalidECCurve
        }

	default:
		return nil, ErrUnsupportedPublicKeyType
	}
}

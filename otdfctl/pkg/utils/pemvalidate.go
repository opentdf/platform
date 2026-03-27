package utils

import (
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

// ValidatePublicKeyPEM validates a PEM-encoded public key block and ensures it
// matches the expected algorithm. The input should be raw PEM bytes (not base64).
func ValidatePublicKeyPEM(pemBytes []byte, expected policy.Algorithm) error {
	if len(pemBytes) == 0 {
		return errors.New("empty pem input")
	}

	enc, err := ocrypto.FromPublicPEM(string(pemBytes))
	if err != nil {
		return fmt.Errorf("invalid public key pem: %w", err)
	}

	switch expected {
	case policy.Algorithm_ALGORITHM_RSA_2048:
		if enc.KeyType() != ocrypto.RSA2048Key {
			return errors.New("algorithm mismatch: expected RSA 2048")
		}
	case policy.Algorithm_ALGORITHM_RSA_4096:
		if enc.KeyType() != ocrypto.RSA4096Key {
			return errors.New("algorithm mismatch: expected RSA 4096")
		}
	case policy.Algorithm_ALGORITHM_EC_P256:
		if enc.KeyType() != ocrypto.EC256Key {
			return errors.New("algorithm mismatch: expected EC P-256")
		}
	case policy.Algorithm_ALGORITHM_EC_P384:
		if enc.KeyType() != ocrypto.EC384Key {
			return errors.New("algorithm mismatch: expected EC P-384")
		}
	case policy.Algorithm_ALGORITHM_EC_P521:
		if enc.KeyType() != ocrypto.EC521Key {
			return errors.New("algorithm mismatch: expected EC P-521")
		}
	case policy.Algorithm_ALGORITHM_UNSPECIFIED:
		fallthrough
	default:
		return errors.New("unsupported or unspecified algorithm")
	}

	return nil
}

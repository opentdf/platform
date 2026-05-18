package ocrypto

import (
	"crypto/mlkem"
	"encoding/pem"
	"fmt"
)

const (
	// MLKem768CiphertextSize is the byte length of an ML-KEM-768 ciphertext.
	MLKem768CiphertextSize = 1088
	// MLKem768PublicKeySize is the byte length of an ML-KEM-768 encapsulation key.
	MLKem768PublicKeySize = 1184

	mlkem768PEMType = "ML-KEM-768 PUBLIC KEY"
)

// MLKEMPublicKeyFromPEM parses an ML-KEM-768 encapsulation key from a PEM block
// with type "ML-KEM-768 PUBLIC KEY".
func MLKEMPublicKeyFromPEM(pemData []byte) (*mlkem.EncapsulationKey768, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block for ML-KEM-768 public key")
	}
	if block.Type != mlkem768PEMType {
		return nil, fmt.Errorf("unexpected PEM type %q, expected %q", block.Type, mlkem768PEMType)
	}
	key, err := mlkem.NewEncapsulationKey768(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ML-KEM-768 encapsulation key: %w", err)
	}
	return key, nil
}

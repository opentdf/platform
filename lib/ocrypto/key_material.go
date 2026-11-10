package ocrypto

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// IsPEMOrDERPrivateKey reports whether data appears to be an unencrypted private key
// in PEM or DER format. It does not attempt decryption or key unwrapping.
func IsPEMOrDERPrivateKey(data []byte) bool {
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return true
		}
	}

	if _, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(data); err == nil {
		return true
	}

	return false
}

package ocrypto

// Algorithm identifiers for BaseTDF v4.4.0 Key Access Objects.
// These are the string values used in the "alg" field of KAOs.
const (
	AlgRSAOAEP    = "RSA-OAEP"
	AlgRSAOAEP256 = "RSA-OAEP-256"
	AlgECDHHKDF   = "ECDH-HKDF"
	AlgMLKEM768   = "ML-KEM-768"
	AlgMLKEM1024  = "ML-KEM-1024"
	AlgHybridECDH = "X-ECDH-ML-KEM-768"
)

// AlgForKeyType returns the BaseTDF algorithm identifier for the given KeyType.
// This maps internal key types to the explicit algorithm strings used in v4.4.0 KAOs.
func AlgForKeyType(kt KeyType) string {
	switch kt {
	case RSA2048Key, RSA4096Key:
		return AlgRSAOAEP
	case EC256Key, EC384Key, EC521Key:
		return AlgECDHHKDF
	default:
		return string(kt)
	}
}

// KeyTypeForAlg returns the KeyType for a given BaseTDF algorithm identifier.
// Returns the algorithm string as a KeyType if no specific mapping exists.
func KeyTypeForAlg(alg string) KeyType {
	switch alg {
	case AlgRSAOAEP, AlgRSAOAEP256:
		return RSA2048Key
	case AlgECDHHKDF:
		return EC256Key
	default:
		return KeyType(alg)
	}
}

// AlgForLegacyType maps the v4.3.0 "type" field values to algorithm identifiers.
func AlgForLegacyType(legacyType string) string {
	switch legacyType {
	case "wrapped":
		return AlgRSAOAEP
	case "ec-wrapped":
		return AlgECDHHKDF
	default:
		return ""
	}
}

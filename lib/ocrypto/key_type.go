package ocrypto

import "fmt"

type KeyType string

const (
	RSA2048Key   KeyType = "rsa:2048"
	RSA4096Key   KeyType = "rsa:4096"
	EC256Key     KeyType = "ec:secp256r1"
	EC384Key     KeyType = "ec:secp384r1"
	EC521Key     KeyType = "ec:secp521r1"
	MLKEM768Key  KeyType = "mlkem:768"
	MLKEM1024Key KeyType = "mlkem:1024"
)

const (
	RSA2048Size = 2048
	RSA4096Size = 4096
)

// ParseKeyType validates a string as a known KeyType, returning an error for
// unrecognized values.
func ParseKeyType(alg string) (KeyType, error) {
	switch KeyType(alg) {
	case RSA2048Key, RSA4096Key,
		EC256Key, EC384Key, EC521Key,
		MLKEM768Key, MLKEM1024Key,
		HybridXWingKey, HybridSecp256r1MLKEM768Key, HybridSecp384r1MLKEM1024Key:
		return KeyType(alg), nil
	default:
		return "", fmt.Errorf("unrecognized key type: %s", alg)
	}
}

func IsECKeyType(kt KeyType) bool {
	switch kt { //nolint:exhaustive // only handle ec types
	case EC256Key, EC384Key, EC521Key:
		return true
	default:
		return false
	}
}

func IsRSAKeyType(kt KeyType) bool {
	switch kt { //nolint:exhaustive // only handle rsa types
	case RSA2048Key, RSA4096Key:
		return true
	default:
		return false
	}
}

func IsMLKEMKeyType(kt KeyType) bool {
	switch kt { //nolint:exhaustive // only handle mlkem types
	case MLKEM768Key, MLKEM1024Key:
		return true
	default:
		return false
	}
}

func ECKeyTypeToMode(kt KeyType) (ECCMode, error) {
	switch kt { //nolint:exhaustive // only handle ec types
	case EC256Key:
		return ECCModeSecp256r1, nil
	case EC384Key:
		return ECCModeSecp384r1, nil
	case EC521Key:
		return ECCModeSecp521r1, nil
	default:
		return 0, fmt.Errorf("unsupported type: %v", kt)
	}
}

func RSAKeyTypeToBits(kt KeyType) (int, error) {
	switch kt { //nolint:exhaustive // only handle rsa types
	case RSA2048Key:
		return RSA2048Size, nil
	case RSA4096Key:
		return RSA4096Size, nil
	default:
		return 0, fmt.Errorf("unsupported type: %v", kt)
	}
}

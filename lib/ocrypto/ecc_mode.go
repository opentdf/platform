package ocrypto

import (
	"crypto/elliptic"
	"errors"
	"fmt"
)

type ECCMode uint8

const (
	ECCModeSecp256r1 ECCMode = 0
	ECCModeSecp384r1 ECCMode = 1
	ECCModeSecp521r1 ECCMode = 2
	ECCModeSecp256k1 ECCMode = 3
)

const (
	ECCurveP256Size = 256
	ECCurveP384Size = 384
	ECCurveP521Size = 521
)

// GetECCurveFromECCMode return elliptic curve from ecc mode
func GetECCurveFromECCMode(mode ECCMode) (elliptic.Curve, error) {
	var c elliptic.Curve

	switch mode {
	case ECCModeSecp256r1:
		c = elliptic.P256()
	case ECCModeSecp384r1:
		c = elliptic.P384()
	case ECCModeSecp521r1:
		c = elliptic.P521()
	case ECCModeSecp256k1:
		// TODO FIXME - unsupported?
		return nil, errors.New("unsupported ECC mode")
	default:
		return nil, fmt.Errorf("unsupported ECC mode %d", mode)
	}

	return c, nil
}

func (mode ECCMode) String() string {
	switch mode {
	case ECCModeSecp256r1:
		return "ec:secp256r1"
	case ECCModeSecp384r1:
		return "ec:secp384r1"
	case ECCModeSecp521r1:
		return "ec:secp521r1"
	case ECCModeSecp256k1:
		return "ec:secp256k1"
	}
	return "unspecified"
}

// ECSizeToMode converts a curve size to an ECCMode
func ECSizeToMode(size int) (ECCMode, error) {
	switch size {
	case ECCurveP256Size:
		return ECCModeSecp256r1, nil
	case ECCurveP384Size:
		return ECCModeSecp384r1, nil
	case ECCurveP521Size:
		return ECCModeSecp521r1, nil
	default:
		return 0, fmt.Errorf("unsupported EC curve size: %d", size)
	}
}

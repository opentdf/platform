//go:build opentdf.hsm

package access

import (
	"context"
	"testing"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	configHSM = security.Config{
		Type: "hsm",
		HSMConfig: security.HSMConfig{
			ModulePath: "",
			PIN:        "12345",
			SlotID:     0,
			SlotLabel:  "dev-token",
			Keys: map[string]security.KeyInfo{
				"rsa": {
					Name:  "rsa",
					Label: "development-rsa-kas",
				},
				"ec": {
					Name:  "ec",
					Label: "development-ec-kas",
				},
			},
		},
	}
)

func TestHSMCertificateHandlerEmpty(t *testing.T) {
	configHSM.HSMConfig.Keys = map[string]security.KeyInfo{
		"rsa": {},
		"ec":  {},
	}
	c := mustNewCryptoProvider(t, configHSM)
	defer c.Close()
	kasURI := urlHost(t)

	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Fmt: "pkcs8"})
	require.Error(t, err, "not found")
	assert.Nil(t, result)
}

func TestCertificateHandlerWithEc256(t *testing.T) {
	configHSM.HSMConfig.Keys = map[string]security.KeyInfo{
		"rsa": {
			Name:  "rsa",
			Label: "development-rsa-kas",
		},
		"ec": {
			Name:  "ec",
			Label: "development-ec-kas",
		},
	}
	c := mustNewCryptoProvider(t, configHSM)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.LegacyPublicKey(context.Background(), &kaspb.LegacyPublicKeyRequest{Algorithm: "ec:secp256r1"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.GetValue(), "BEGIN PUBLIC KEY")
}

func TestHSMPublicKeyHandlerWithEc256(t *testing.T) {
	configHSM.HSMConfig.Keys = map[string]security.KeyInfo{
		"rsa": {
			Name:  "rsa",
			Label: "development-rsa-kas",
		},
		"ec": {
			Name:  "ec",
			Label: "development-ec-kas",
		},
	}
	c := mustNewCryptoProvider(t, configHSM)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "ec:secp256r1"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.GetPublicKey(), "BEGIN PUBLIC KEY")
}

func TestHSMPublicKeyHandlerV2(t *testing.T) {
	configHSM.HSMConfig.Keys = map[string]security.KeyInfo{
		"rsa": {
			Name:  "rsa",
			Label: "development-rsa-kas",
		},
		"ec": {
			Name:  "ec",
			Label: "development-ec-kas",
		},
	}
	c := mustNewCryptoProvider(t, configHSM)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "rsa"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.GetPublicKey(), "BEGIN PUBLIC KEY")
}

func TestHSMPublicKeyHandlerV2Failure(t *testing.T) {
	configHSM.HSMConfig.Keys = map[string]security.KeyInfo{
		"rsa": {},
		"ec":  {},
	}
	c := mustNewCryptoProvider(t, configHSM)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	_, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "rsa"})
	assert.Error(t, err)
}

func TestHSMPublicKeyHandlerV2WithEc256(t *testing.T) {
	configHSM.HSMConfig.Keys = map[string]security.KeyInfo{
		"rsa": {
			Name:  "rsa",
			Label: "development-rsa-kas",
		},
		"ec": {
			Name:  "ec",
			Label: "development-ec-kas",
		},
	}
	c := mustNewCryptoProvider(t, configHSM)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "ec:secp256r1",
		V: "2"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.GetPublicKey(), "BEGIN PUBLIC KEY")
}

func TestHSMPublicKeyHandlerV2WithJwk(t *testing.T) {
	configHSM.HSMConfig.Keys = map[string]security.KeyInfo{
		"rsa": {
			Name:  "rsa",
			Label: "development-rsa-kas",
		},
		"ec": {
			Name:  "ec",
			Label: "development-ec-kas",
		},
	}
	c := mustNewCryptoProvider(t, configHSM)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{
		Algorithm: "rsa",
		V:         "2",
		Fmt:       "jwk",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.GetPublicKey(), "\"kty\"")
}

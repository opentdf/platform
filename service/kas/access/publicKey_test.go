package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"testing"

	"connectrpc.com/connect"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportRsaPublicKeyAsPemStrSuccess(t *testing.T) {
	mockKey := &rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	output, err := exportRsaPublicKeyAsPemStr(mockKey)

	require.NoError(t, err)
	assert.NotEmpty(t, output)
	assert.IsType(t, "string", output)
}

func TestExportRsaPublicKeyAsPemStrFailure(t *testing.T) {
	output, err := exportRsaPublicKeyAsPemStr(&rsa.PublicKey{})
	assert.Empty(t, output)
	assert.Error(t, err)
}

func TestExportEcPublicKeyAsPemStrSuccess(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	output, err := exportEcPublicKeyAsPemStr(&privateKey.PublicKey)
	require.NoError(t, err)

	assert.NotEmpty(t, output)
	assert.IsType(t, "string", output)
}

func TestExportEcPublicKeyAsPemStrFailure(t *testing.T) {
	output, err := exportEcPublicKeyAsPemStr(&ecdsa.PublicKey{})
	assert.Empty(t, output)
	assert.Error(t, err)
}

func TestExportCertificateAsPemStrSuccess(t *testing.T) {
	certBytes, err := os.ReadFile("./testdata/cert.der")
	require.NoError(t, err, "Failed to read certificate file in test")

	mockCert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err, "Failed to parse certificate in test")

	pemStr, err := exportCertificateAsPemStr(mockCert)
	require.NoError(t, err)

	// Decode the pemStr back into a block
	pemBlock, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, pemBlock)

	// Ensure that the PEM block has the expected type "CERTIFICATE"
	assert.Equal(t, "CERTIFICATE", pemBlock.Type)

	// Compare the decoded certificate bytes with the original mock certificate bytes
	assert.Equal(t, certBytes, pemBlock.Bytes)
}

func TestError(t *testing.T) {
	output := Error.Error(ErrCertificateEncode)
	assert.Equal(t, "certificate encode error", output)
}

const hostname = "localhost"

func TestStandardCertificateHandlerEmpty(t *testing.T) {
	configStandard := security.Config{
		Type: "standard",
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)

	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
		Logger:         logger.CreateTestLogger(),
	}

	result, err := kas.PublicKey(context.Background(), &connect.Request[kaspb.PublicKeyRequest]{Msg: &kaspb.PublicKeyRequest{Fmt: "pkcs8"}})
	require.Error(t, err, "not found")
	assert.Nil(t, result)
}

func mustNewCryptoProvider(t *testing.T, configStandard security.Config) security.CryptoProvider {
	c, err := security.NewCryptoProvider(configStandard)
	require.NoError(t, err)
	require.NotNil(t, c)
	return c
}

func urlHost(t *testing.T) *url.URL {
	url, err := url.Parse("https://" + hostname + ":5000")
	require.NoError(t, err)
	return url
}

func TestStandardPublicKeyHandlerV2(t *testing.T) {
	configStandard := security.Config{
		Type: "standard",
		StandardConfig: security.StandardConfig{
			RSAKeys: map[string]security.StandardKeyInfo{
				"rsa": {
					PrivateKeyPath: "./testdata/access-provider-000-private.pem",
					PublicKeyPath:  "./testdata/access-provider-000-certificate.pem",
				},
			},
		},
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
		KASConfig: KASConfig{
			Keyring: []CurrentKeyFor{
				{
					Algorithm: security.AlgorithmRSA2048,
					KID:       "rsa",
				},
			},
		},
	}

	result, err := kas.PublicKey(context.Background(), &connect.Request[kaspb.PublicKeyRequest]{Msg: &kaspb.PublicKeyRequest{}})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Msg.GetPublicKey(), "BEGIN PUBLIC KEY")
}

func TestStandardPublicKeyHandlerV2Failure(t *testing.T) {
	configStandard := security.Config{
		Type: "standard",
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
		Logger:         logger.CreateTestLogger(),
	}

	k, err := kas.PublicKey(context.Background(), &connect.Request[kaspb.PublicKeyRequest]{Msg: &kaspb.PublicKeyRequest{}})
	assert.Nil(t, k)
	require.Error(t, err)
}

func TestStandardPublicKeyHandlerV2NotFound(t *testing.T) {
	configStandard := security.Config{
		Type: "standard",
		StandardConfig: security.StandardConfig{
			RSAKeys: map[string]security.StandardKeyInfo{
				"rsa": {
					PrivateKeyPath: "./testdata/access-provider-000-private.pem",
					PublicKeyPath:  "./testdata/access-provider-000-certificate.pem",
				},
			},
		},
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
		Logger:         logger.CreateTestLogger(),
	}

	k, err := kas.PublicKey(context.Background(), &connect.Request[kaspb.PublicKeyRequest]{
		Msg: &kaspb.PublicKeyRequest{
			Algorithm: "algorithm:unknown",
		},
	})
	assert.Nil(t, k)
	require.Error(t, err)

	status := connect.CodeOf(err)
	assert.Equal(t, connect.CodeNotFound, status)
}

func TestStandardPublicKeyHandlerV2WithJwk(t *testing.T) {
	configStandard := security.Config{
		Type: "standard",
		StandardConfig: security.StandardConfig{
			RSAKeys: map[string]security.StandardKeyInfo{
				"rsa": {
					PrivateKeyPath: "./testdata/access-provider-000-private.pem",
					PublicKeyPath:  "./testdata/access-provider-000-certificate.pem",
				},
			},
		},
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
		KASConfig: KASConfig{
			Keyring: []CurrentKeyFor{
				{
					Algorithm: security.AlgorithmRSA2048,
					KID:       "rsa",
				},
			},
		},
	}

	result, err := kas.PublicKey(context.Background(), &connect.Request[kaspb.PublicKeyRequest]{
		Msg: &kaspb.PublicKeyRequest{
			Algorithm: "rsa:2048",
			V:         "2",
			Fmt:       "jwk",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Msg.GetPublicKey(), "\"kty\"")
}

func TestStandardCertificateHandlerWithEc256(t *testing.T) {
	t.Skip("EC Not yet implemented")
	configStandard := security.Config{
		Type: "standard",
		StandardConfig: security.StandardConfig{
			ECKeys: map[string]security.StandardKeyInfo{
				"ec": {
					PrivateKeyPath: "./testdata/access-provider-ec-private.pem",
					PublicKeyPath:  "./testdata/access-provider-ec-certificate.pem",
				},
			},
		},
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.LegacyPublicKey(context.Background(), &connect.Request[kaspb.LegacyPublicKeyRequest]{
		Msg: &kaspb.LegacyPublicKeyRequest{
			Algorithm: "ec:secp256r1",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Msg.GetValue(), "BEGIN PUBLIC KEY")
}

func TestStandardPublicKeyHandlerWithEc256(t *testing.T) {
	t.Skip("EC Not yet implemented")
	configStandard := security.Config{
		Type: "standard",
		StandardConfig: security.StandardConfig{
			ECKeys: map[string]security.StandardKeyInfo{
				"ec": {
					PrivateKeyPath: "./testdata/access-provider-ec-private.pem",
					PublicKeyPath:  "./testdata/access-provider-ec-certificate.pem",
				},
			},
		},
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.PublicKey(context.Background(), &connect.Request[kaspb.PublicKeyRequest]{
		Msg: &kaspb.PublicKeyRequest{
			Algorithm: "ec:secp256r1",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Msg.GetPublicKey(), "BEGIN PUBLIC KEY")
}

func TestStandardPublicKeyHandlerV2WithEc256(t *testing.T) {
	t.Skip("EC Not yet implemented")
	configStandard := security.Config{
		Type: "standard",
		StandardConfig: security.StandardConfig{
			ECKeys: map[string]security.StandardKeyInfo{
				"ec": {
					PrivateKeyPath: "./testdata/access-provider-ec-private.pem",
					PublicKeyPath:  "./testdata/access-provider-ec-certificate.pem",
				},
			},
		},
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: c,
	}

	result, err := kas.PublicKey(context.Background(), &connect.Request[kaspb.PublicKeyRequest]{
		Msg: &kaspb.PublicKeyRequest{
			Algorithm: "ec:secp256r1",
			V:         "2",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Msg.GetPublicKey(), "BEGIN PUBLIC KEY")
}

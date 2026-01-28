package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyDetailsAdapter(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)

	rsaAdapter := &KeyDetailsAdapter{
		id:             trust.KeyIdentifier(material.rsaKid),
		algorithm:      ocrypto.KeyType(AlgorithmRSA2048),
		cryptoProvider: cryptoProvider,
	}

	ecAdapter := &KeyDetailsAdapter{
		id:             trust.KeyIdentifier(material.ecKid),
		algorithm:      ocrypto.KeyType(AlgorithmECP256R1),
		cryptoProvider: cryptoProvider,
	}

	assert.Equal(t, inProcessSystemName, rsaAdapter.System())
	assert.Equal(t, trust.KeyIdentifier(material.rsaKid), rsaAdapter.ID())
	assert.Equal(t, ocrypto.KeyType(AlgorithmRSA2048), rsaAdapter.Algorithm())
	assert.False(t, rsaAdapter.IsLegacy())

	_, err := rsaAdapter.ExportPrivateKey(context.Background())
	assert.Error(t, err)

	jwk, err := rsaAdapter.ExportPublicKey(context.Background(), trust.KeyTypeJWK)
	require.NoError(t, err)
	assert.True(t, json.Valid([]byte(jwk)))

	pemKey, err := rsaAdapter.ExportPublicKey(context.Background(), trust.KeyTypePKCS8)
	require.NoError(t, err)
	assert.Contains(t, pemKey, "PUBLIC KEY")

	_, err = rsaAdapter.ExportCertificate(context.Background())
	assert.Error(t, err)

	_, err = ecAdapter.ExportPublicKey(context.Background(), trust.KeyTypeJWK)
	assert.Error(t, err)

	ecPublic, err := ecAdapter.ExportPublicKey(context.Background(), trust.KeyTypePKCS8)
	require.NoError(t, err)
	assert.Contains(t, ecPublic, "PUBLIC KEY")

	cert, err := ecAdapter.ExportCertificate(context.Background())
	require.NoError(t, err)
	assert.Equal(t, material.ecPublicPEM, cert)

	cfg := ecAdapter.ProviderConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, inProcessSystemName, cfg.Manager)
	assert.Equal(t, "static", cfg.Name)
}

func TestInProcessProviderMetadata(t *testing.T) {
	cryptoProvider, _ := newStandardCryptoForTest(t, true, false)
	provider := NewSecurityProviderAdapter(cryptoProvider, nil, nil).(*InProcessProvider)

	assert.Equal(t, inProcessSystemName, provider.Name())
	assert.Equal(t, inProcessSystemName, provider.String())
	assert.Equal(t, slog.KindString, provider.LogValue().Kind())
	assert.Equal(t, inProcessSystemName, provider.LogValue().String())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	assert.Same(t, provider, provider.WithLogger(logger))
	assert.Same(t, logger, provider.logger)
}

func TestInProcessProviderKeyLookup(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)
	provider := NewSecurityProviderAdapter(
		cryptoProvider,
		[]string{material.rsaKid},
		[]string{material.ecKid},
	).(*InProcessProvider)

	defaultKey, err := provider.FindKeyByAlgorithm(context.Background(), AlgorithmRSA2048, false)
	require.NoError(t, err)
	assert.Equal(t, trust.KeyIdentifier(material.rsaKid), defaultKey.ID())

	legacyKey, err := provider.FindKeyByAlgorithm(context.Background(), AlgorithmECP256R1, true)
	require.NoError(t, err)
	assert.Equal(t, trust.KeyIdentifier(material.ecKid), legacyKey.ID())

	byID, err := provider.FindKeyByID(context.Background(), trust.KeyIdentifier(material.rsaKid))
	require.NoError(t, err)
	assert.Equal(t, ocrypto.KeyType(AlgorithmRSA2048), byID.Algorithm())

	_, err = provider.FindKeyByID(context.Background(), trust.KeyIdentifier("missing"))
	assert.ErrorIs(t, err, ErrCertNotFound)

	keys, err := provider.ListKeys(context.Background())
	require.NoError(t, err)
	assert.Len(t, keys, 2)

	legacyOnly, err := provider.ListKeysWith(context.Background(), trust.ListKeyOptions{LegacyOnly: true})
	require.NoError(t, err)
	require.Len(t, legacyOnly, 1)
	assert.Equal(t, trust.KeyIdentifier(material.ecKid), legacyOnly[0].ID())
}

func TestInProcessProviderDecrypt(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)
	provider := NewSecurityProviderAdapter(
		cryptoProvider,
		[]string{material.rsaKid},
		[]string{material.ecKid},
	).(*InProcessProvider)

	rsaDetails, err := provider.FindKeyByID(context.Background(), trust.KeyIdentifier(material.rsaKid))
	require.NoError(t, err)

	rsaKey := cryptoProvider.keysByID[material.rsaKid].(StandardRSACrypto)
	rawRSA := make([]byte, 32)
	_, err = rand.Read(rawRSA)
	require.NoError(t, err)
	cipherRSA, err := rsaKey.asymEncryption.Encrypt(rawRSA)
	require.NoError(t, err)

	protected, err := provider.Decrypt(context.Background(), rsaDetails, cipherRSA, nil)
	require.NoError(t, err)
	assert.Equal(t, rawRSA, exportProtectedKey(t, protected))

	_, err = provider.Decrypt(context.Background(), rsaDetails, cipherRSA, []byte("bad"))
	assert.Error(t, err)

	ecDetails, err := provider.FindKeyByID(context.Background(), trust.KeyIdentifier(material.ecKid))
	require.NoError(t, err)

	encryptor, err := ocrypto.FromPublicPEMWithSalt(material.ecPublicPEM, TDFSalt(), nil)
	require.NoError(t, err)
	rawEC := make([]byte, 32)
	_, err = rand.Read(rawEC)
	require.NoError(t, err)
	cipherEC, err := encryptor.Encrypt(rawEC)
	require.NoError(t, err)

	protected, err = provider.Decrypt(context.Background(), ecDetails, cipherEC, encryptor.EphemeralKey())
	require.NoError(t, err)
	assert.Equal(t, rawEC, exportProtectedKey(t, protected))

	_, err = provider.Decrypt(context.Background(), ecDetails, cipherEC, nil)
	assert.Error(t, err)
}

func TestInProcessProviderDeriveKey(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, false, true)
	provider := NewSecurityProviderAdapter(cryptoProvider, nil, []string{material.ecKid}).(*InProcessProvider)

	ecDetails, err := provider.FindKeyByID(context.Background(), trust.KeyIdentifier(material.ecKid))
	require.NoError(t, err)

	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), ephemeralKey.PublicKey.X, ephemeralKey.PublicKey.Y)

	protected, err := provider.DeriveKey(context.Background(), ecDetails, compressed, elliptic.P256())
	require.NoError(t, err)

	publicDER, err := x509.MarshalPKIXPublicKey(&ephemeralKey.PublicKey)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	symmetricKey, err := ocrypto.ComputeECDHKey([]byte(material.ecPrivatePEM), publicPEM)
	require.NoError(t, err)
	expected, err := ocrypto.CalculateHKDF(TDFSalt(), symmetricKey)
	require.NoError(t, err)

	assert.Equal(t, expected, exportProtectedKey(t, protected))
}

func TestInProcessProviderGenerateECSessionKey(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, false, true)
	provider := NewSecurityProviderAdapter(cryptoProvider, nil, nil).(*InProcessProvider)

	encapsulator, err := provider.GenerateECSessionKey(context.Background(), material.ecPublicPEM)
	require.NoError(t, err)

	pemKey, err := encapsulator.PublicKeyAsPEM()
	require.NoError(t, err)
	assert.Contains(t, pemKey, "PUBLIC KEY")

	encrypted, err := encapsulator.Encrypt([]byte("data"))
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEmpty(t, encapsulator.EphemeralKey())
}

func TestInProcessProviderDetermineKeyType(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)
	provider := NewSecurityProviderAdapter(cryptoProvider, nil, nil).(*InProcessProvider)

	keyType, err := provider.determineKeyType(context.Background(), material.rsaKid)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSA2048, keyType)

	keyType, err = provider.determineKeyType(context.Background(), material.ecKid)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECP256R1, keyType)

	_, err = provider.determineKeyType(context.Background(), "missing")
	assert.Error(t, err)
}

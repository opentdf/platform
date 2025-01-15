package recrypt

import (
	"log/slog"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/suite"
)

type StandardTestSuite struct {
	suite.Suite
	*Standard
}

func (s *StandardTestSuite) SetupSuite() {
	s.Standard = NewStandard()
}

func TestTDF(t *testing.T) {
	suite.Run(t, new(StandardTestSuite))
}

func (s *StandardTestSuite) TestListingKeys() {
	_, err := s.List()
	s.Require().NoError(err)
}

func (s *StandardTestSuite) TestRSA() {
	key, err := s.GenerateKey("rsa:2048", "test-key")
	defer func() { s.Require().NoError(s.DestroyKey("test-key")) }()
	s.Require().NoError(err)
	s.Equal(KeyIdentifier("test-key"), key)

	keys, err := s.List()
	s.Require().NoError(err)
	s.NotEmpty(keys)
	// uses testify.Suite to assert that keys contains a KeyDetails with ID "test-key"
	var kaskd *KeyDetails
	s.Condition(func() bool {
		for _, k := range keys {
			slog.Info("checking key", "key", k)
			if k.ID == "test-key" {
				kaskd = &k
				return true
			}
		}
		return false
	}, "Key %s not found in list %v", "test-key", keys)

	s.Require().NotNil(kaskd)

	policy := sdk.PolicyObject{}
	dek, kao, err := s.CreateKeyAccessObject("http://kas.us", kaskd.ID, kaskd.Public, policy)
	s.Require().NoError(err)
	s.Len(dek, 32)
	s.Equal("http://kas.us", kao.KasURL)

	// Use the key to encrypt a value, then decrypt it.
	// use SDK to produce wrapped key?
	wk, err := ocrypto.Base64Decode([]byte(kao.WrappedKey))
	s.Require().NoError(err)

	decrypted, err := s.Unwrap(kaskd.ID, wk)
	s.Require().NoError(err)
	auk, ok := decrypted.(aesUnwrappedKey)
	s.Require().True(ok)
	s.Equal(dek, auk.value)
}

func (s *StandardTestSuite) TestEC() {
	key, err := s.GenerateKey("ec:secp256r1", "ec-key")
	defer func() { s.Require().NoError(s.DestroyKey("ec-key")) }()
	s.Require().NoError(err)
	s.Equal(KeyIdentifier("ec-key"), key)

	keys, err := s.List()
	s.Require().NoError(err)
	s.NotEmpty(keys)
	// uses testify.Suite to assert that keys contains a KeyDetails with ID "test-key"
	var kaskd *KeyDetails
	s.Condition(func() bool {
		for _, k := range keys {
			slog.Info("checking key", "key", k)
			if k.ID == KeyIdentifier("ec-key") {
				kaskd = &k
				slog.Info("found EC key pair", "kid", "ec-key", "public", k.Public)
				return true
			}
		}
		return false
	}, "Key %s not found in list %v", "test-key", keys)

	s.Require().NotNil(kaskd)

	kasPublicKey, err := ocrypto.ECPubKeyFromPem([]byte(kaskd.Public))
	s.Require().NoError(err)

	sk, err := NewECKeyPair()
	s.Require().NoError(err)

	skdh, err := sk.ECDH()
	s.Require().NoError(err)
	ecdhSecret, err := ocrypto.ComputeECDHKeyFromECDHKeys(kasPublicKey, skdh)
	s.Require().NoError(err)

	aesKey, err := ocrypto.CalculateHKDF(versionSalt(), ecdhSecret)
	s.Require().NoError(err)

	// We can create an AES GCM instance with the derived key
	_, err = ocrypto.NewAESGcm(aesKey)
	s.Require().NoError(err)

	compressedPubKey, err := ocrypto.CompressedECPublicKey(ocrypto.ECCModeSecp256r1, sk.PublicKey)
	s.Require().NoError(err)
	actual, err := s.Derive(kaskd.ID, compressedPubKey)
	s.Require().NoError(err)
	auk, ok := actual.(aesUnwrappedKey)
	s.Require().True(ok)
	s.Equal(aesKey, auk.value)
}

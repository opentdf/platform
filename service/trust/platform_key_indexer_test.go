package trust

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/suite"
)

type PlatformKeyIndexTestSuite struct {
	suite.Suite
	rsaKey KeyDetails
}

func (s *PlatformKeyIndexTestSuite) SetupTest() {
	s.rsaKey = &KasKeyAdapter{
		key: &policy.KasKey{
			KasId: "test-kas-id",
			Key: &policy.AsymmetricKey{
				Id:           "test-id",
				KeyId:        "test-key-id",
				KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
				KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3SEw0TkVrOFpDa0JzNjZXQVpWagpIS3NseDRseWdmaXN3aW42RUx5OU9OczZLVDRYa1crRGxsdExtck14bHZkbzVRaDg1UmFZS01mWUdDTWtPM0dGCkFsK0JOeWFOM1kwa0N1QjNPU2ErTzdyMURhNVZteVVuaEJNbFBrYnVPY1Y0cjlLMUhOSGd3eDl2UFp3RjRpQW8KQStEY1VBcWFEeHlvYjV6enNGZ0hUNjJHLzdLdEtiZ2hYT1dCanRUYUl1ZHpsK2FaSjFPemY0U1RkOXhST2QrMQordVo2VG1ocmFEUm9zdDUrTTZUN0toL2lGWk40TTFUY2hwWXU1TDhKR2tVaG9YaEdZcHUrMGczSzlqYlh6RVh5CnpJU3VXN2d6SGRWYUxvcnBkQlNkRHpOWkNvTFVoL0U1T3d5TFZFQkNKaDZJVUtvdWJ5WHVucnIxQnJmK2tLbEsKeHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
				},
				ProviderConfig: &policy.KeyProviderConfig{
					Id:   "test-provider-id",
					Name: "openbao",
				},
			},
		},
	}
}
func (s *PlatformKeyIndexTestSuite) TearDownTest() {}

func (s *PlatformKeyIndexTestSuite) TestKeyDetails() {
	s.Equal("test-key-id", string(s.rsaKey.ID()))
	s.Equal("ALGORITHM_RSA_2048", s.rsaKey.Algorithm())
	s.False(s.rsaKey.IsLegacy())
	s.Equal("openbao", s.rsaKey.System())
}

func (s *PlatformKeyIndexTestSuite) TestKeyExportPublicKey_JWKFormat() {
	// Export JWK format
	jwkString, err := s.rsaKey.ExportPublicKey(context.Background(), KeyTypeJWK)
	s.Require().NoError(err)
	s.Require().NotEmpty(jwkString)

	rsaKey, err := jwk.ParseKey([]byte(jwkString))
	s.Require().NoError(err)
	s.Require().NotNil(rsaKey)
}

func (s *PlatformKeyIndexTestSuite) TestKeyExportPublicKey_PKCSFormat() {
	// Export JWK format
	pem, err := s.rsaKey.ExportPublicKey(context.Background(), KeyTypePKCS8)
	s.Require().NoError(err)
	s.Require().NotEmpty(pem)

	keyAdapter, ok := s.rsaKey.(*KasKeyAdapter)
	s.Require().True(ok)
	pubCtx := keyAdapter.key.GetKey().GetPublicKeyCtx()
	s.Require().NotEmpty(pubCtx)
	base64Pem := ocrypto.Base64Encode([]byte(pem))
	s.Equal(pubCtx.GetPem(), string(base64Pem))
}

func TestNewPlatformKeyIndexTestSuite(t *testing.T) {
	suite.Run(t, new(PlatformKeyIndexTestSuite))
}

package integration

import (
	"encoding/base64"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/pkg/db"
)

func (s *KasRegistryKeySuite) Test_CreateKasKey_PEMPrivateKey_Fail() {
	pemPrivateKey := "-----BEGIN PRIVATE KEY-----\nZg==\n-----END PRIVATE KEY-----\n"
	encodedPem := base64.StdEncoding.EncodeToString([]byte(pemPrivateKey))
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        validKeyID1,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: encodedPem,
			KeyId:      validKeyID1,
		},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrUnencryptedPrivateKey.Error())
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_RotateKey_PEMPrivateKey_Fail() {
	keyMap := s.setupKeysForRotate(s.kasKeys[0].KeyAccessServerID)
	pemPrivateKey := "-----BEGIN PRIVATE KEY-----\nZg==\n-----END PRIVATE KEY-----\n"
	encodedPem := base64.StdEncoding.EncodeToString([]byte(pemPrivateKey))
	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:         validKeyID1,
		Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx:  &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{WrappedKey: encodedPem, KeyId: validKeyID1},
	}
	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrUnencryptedPrivateKey.Error())
	s.Nil(rotatedInKey)
}

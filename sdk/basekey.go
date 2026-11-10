package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"google.golang.org/protobuf/encoding/protojson"
)

// Should match:
// https://github.com/opentdf/platform/blob/main/service/wellknownconfiguration/wellknown_configuration.go#L25
const (
	baseKeyWellKnown = "base_key"
	baseKeyAlg       = "algorithm"
	baseKeyPublicKey = "public_key"
)

// TODO: Move this function to ocrypto?
func getKasKeyAlg(alg string) policy.Algorithm {
	switch alg {
	case string(ocrypto.RSA2048Key):
		return policy.Algorithm_ALGORITHM_RSA_2048
	case string(ocrypto.RSA4096Key):
		return policy.Algorithm_ALGORITHM_RSA_4096
	case string(ocrypto.EC256Key):
		return policy.Algorithm_ALGORITHM_EC_P256
	case string(ocrypto.EC384Key):
		return policy.Algorithm_ALGORITHM_EC_P384
	case string(ocrypto.EC521Key):
		return policy.Algorithm_ALGORITHM_EC_P521
	default:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

// TODO: Move this function to ocrypto?
func formatAlg(alg policy.Algorithm) (string, error) {
	switch alg {
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return string(ocrypto.RSA2048Key), nil
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return string(ocrypto.RSA4096Key), nil
	case policy.Algorithm_ALGORITHM_EC_P256:
		return string(ocrypto.EC256Key), nil
	case policy.Algorithm_ALGORITHM_EC_P384:
		return string(ocrypto.EC384Key), nil
	case policy.Algorithm_ALGORITHM_EC_P521:
		return string(ocrypto.EC521Key), nil
	case policy.Algorithm_ALGORITHM_UNSPECIFIED:
		fallthrough
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// GetBaseKey retrieves the platform base KAS key from the well-known configuration.
// The returned key material is expected to be public (algorithm, KID, PEM).
func (s SDK) GetBaseKey(ctx context.Context) (*policy.SimpleKasKey, error) {
	return getBaseKey(ctx, s)
}

func getBaseKey(ctx context.Context, s SDK) (*policy.SimpleKasKey, error) {
	req := &wellknownconfiguration.GetWellKnownConfigurationRequest{}
	response, err := s.wellknownConfiguration.GetWellKnownConfiguration(ctx, req)
	if err != nil {
		return nil, errors.Join(errors.New("unable to retrieve config information, and none was provided"), err)
	}
	configuration := response.GetConfiguration()
	if configuration == nil {
		return nil, ErrWellKnowConfigEmpty
	}

	configMap := configuration.AsMap()
	if len(configMap) == 0 {
		return nil, ErrWellKnowConfigEmpty
	}

	baseKeyStructure, ok := configMap[baseKeyWellKnown]
	if !ok {
		return nil, ErrBaseKeyNotFound
	}

	baseKeyMap, ok := baseKeyStructure.(map[string]interface{})
	if !ok {
		return nil, ErrBaseKeyInvalidFormat
	}

	simpleKasKey, err := parseSimpleKasKey(baseKeyMap)
	if err != nil {
		return nil, err
	}

	return simpleKasKey, nil
}

func parseSimpleKasKey(baseKeyMap map[string]interface{}) (*policy.SimpleKasKey, error) {
	simpleKasKey := &policy.SimpleKasKey{}

	if len(baseKeyMap) == 0 {
		return nil, ErrBaseKeyEmpty
	}

	publicKey, ok := baseKeyMap[baseKeyPublicKey].(map[string]interface{})
	if !ok {
		return nil, ErrBaseKeyInvalidFormat
	}

	alg, ok := publicKey[baseKeyAlg].(string)
	if !ok {
		return nil, ErrBaseKeyInvalidFormat
	}
	publicKey[baseKeyAlg] = getKasKeyAlg(alg)
	baseKeyMap[baseKeyPublicKey] = publicKey
	configJSON, err := json.Marshal(baseKeyMap)
	if err != nil {
		return nil, errors.Join(ErrMarshalBaseKeyFailed, err)
	}

	err = protojson.Unmarshal(configJSON, simpleKasKey)
	if err != nil {
		return nil, errors.Join(ErrUnmarshalBaseKeyFailed, err)
	}
	return simpleKasKey, nil
}

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
	baseKeyWellKnown   = "base_key"
	baseKeyAlg         = "algorithm"
	baseKeyPublicKey   = "public_key"
	wellKnownConfigKey = "configuration"
)

var (
	errWellKnownConfigFormat  = errors.New("well-known configuration has invalid format")
	errBaseKeyNotFound        = errors.New("base key not found in well-known configuration")
	errBaseKeyInvalidFormat   = errors.New("base key has invalid format")
	errBaseKeyEmpty           = errors.New("base key is empty or not provided")
	errMarshalBaseKeyFailed   = errors.New("failed to marshal base key configuration")
	errUnmarshalBaseKeyFailed = errors.New("failed to unmarshal base key configuration")
)

// TODO: Move this function to ocrypto?
func getKasKeyAlg(alg string) policy.Algorithm {
	switch alg {
	case string(ocrypto.RSA2048Key):
		return policy.Algorithm_ALGORITHM_RSA_2048
	case rsa4096:
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
		return rsa4096, nil
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
	configStructure, ok := configuration.AsMap()[wellKnownConfigKey]
	if !ok {
		return nil, err
	}

	configMap, ok := configStructure.(map[string]interface{})
	if !ok {
		return nil, errWellKnownConfigFormat
	}

	simpleKasKey, err := parseSimpleKasKey(configMap)
	if err != nil {
		return nil, err
	}

	return simpleKasKey, nil
}

func parseSimpleKasKey(configMap map[string]interface{}) (*policy.SimpleKasKey, error) {
	simpleKasKey := &policy.SimpleKasKey{}
	baseKey, ok := configMap[baseKeyWellKnown]
	if !ok {
		return nil, errBaseKeyNotFound
	}

	baseKeyMap, ok := baseKey.(map[string]interface{})
	if !ok {
		return nil, errBaseKeyInvalidFormat
	}
	if len(baseKeyMap) == 0 {
		return nil, errBaseKeyEmpty
	}

	publicKey, ok := baseKeyMap[baseKeyPublicKey].(map[string]interface{})
	if !ok {
		return nil, errBaseKeyInvalidFormat
	}

	alg, ok := publicKey[baseKeyAlg].(string)
	if !ok {
		return nil, errBaseKeyInvalidFormat
	}
	publicKey[baseKeyAlg] = getKasKeyAlg(alg)
	baseKeyMap[baseKeyPublicKey] = publicKey
	configJSON, err := json.Marshal(baseKey)
	if err != nil {
		return nil, errors.Join(errMarshalBaseKeyFailed, err)
	}

	err = protojson.Unmarshal(configJSON, simpleKasKey)
	if err != nil {
		return nil, errors.Join(errUnmarshalBaseKeyFailed, err)
	}
	return simpleKasKey, nil
}

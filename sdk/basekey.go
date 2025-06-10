package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"google.golang.org/protobuf/encoding/protojson"
)

// Should match:
// https://github.com/opentdf/platform/blob/main/service/wellknownconfiguration/wellknown_configuration.go#L25
const baseKeyWellKnown = "base_key"

// TODO: Move this function to ocrypto?
func getKasKeyAlg(alg string) policy.Algorithm {
	switch alg {
	case "rsa:2048":
		return policy.Algorithm_ALGORITHM_RSA_2048
	case "rsa:4096":
		return policy.Algorithm_ALGORITHM_RSA_4096
	case "ec:secp256r1":
		return policy.Algorithm_ALGORITHM_EC_P256
	case "ec:secp384r1":
		return policy.Algorithm_ALGORITHM_EC_P384
	case "ec:secp521r1":
		return policy.Algorithm_ALGORITHM_EC_P521
	default:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

// TODO: Move this function to ocrypto?
func formatAlg(alg policy.Algorithm) (string, error) {
	switch alg {
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return "rsa:2048", nil
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return "rsa:4096", nil
	case policy.Algorithm_ALGORITHM_EC_P256:
		return "ec:secp256r1", nil
	case policy.Algorithm_ALGORITHM_EC_P384:
		return "ec:secp384r1", nil
	case policy.Algorithm_ALGORITHM_EC_P521:
		return "ec:secp512r1", nil
	case policy.Algorithm_ALGORITHM_UNSPECIFIED:
		fallthrough
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func (s SDK) getBaseKey(ctx context.Context) (*policy.SimpleKasKey, error) {
	simpleKasKey := &policy.SimpleKasKey{}

	req := &wellknownconfiguration.GetWellKnownConfigurationRequest{}
	response, err := s.wellknownConfiguration.GetWellKnownConfiguration(ctx, req)
	if err != nil {
		return nil, errors.Join(errors.New("unable to retrieve config information, and none was provided"), err)
	}
	configuration := response.GetConfiguration()
	if configuration == nil {
		return nil, ErrWellKnowConfigEmpty
	}
	configStructure, ok := configuration.AsMap()[baseKeyWellKnown]
	if !ok {
		return nil, errors.New("base key not found in well-known configuration")
	}
	configMap, ok := configStructure.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid base key format")
	}
	if len(configMap) == 0 {
		return nil, errors.New("base key is empty")
	}

	publicKey, ok := configMap["public_key"].(map[string]interface{})
	if !ok {
		return nil, errors.New("public key structure not found in base key configuration")
	}

	publicKey["algorithm"] = getKasKeyAlg(publicKey["algorithm"].(string))
	configMap["public_key"] = publicKey
	configJSON, err := json.Marshal(configMap)
	if err != nil {
		return nil, errors.Join(errors.New("base key marshal failed"), err)
	}

	err = protojson.Unmarshal(configJSON, simpleKasKey)
	if err != nil {
		return nil, errors.Join(errors.New("unable to unmarshal base key"), err)
	}

	return simpleKasKey, nil
}

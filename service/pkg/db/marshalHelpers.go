package db

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"google.golang.org/protobuf/encoding/protojson"
)

// Marshal policy metadata is used by the MarshalCreateMetadata and MarshalUpdateMetadata functions to enable
// the creation and update of policy metadata without exposing it to developers. Take note of the immutableMetadata and
// mutableMetadata parameters. The mutableMetadata is the metadata that is passed in by the developer. The immutableMetadata
// is created by the service.
func marshalMetadata(mutableMetadata *common.MetadataMutable) ([]byte, *common.Metadata, error) {
	m := &common.Metadata{
		Labels: mutableMetadata.GetLabels(),
	}
	j, err := protojson.Marshal(m)
	return j, m, err
}

func MarshalCreateMetadata(metadata *common.MetadataMutable) ([]byte, *common.Metadata, error) {
	return marshalMetadata(metadata)
}

func MarshalUpdateMetadata(m *common.MetadataMutable, b common.MetadataUpdateEnum, getExtendableMetadata func() (*common.Metadata, error)) ([]byte, *common.Metadata, error) {
	// No metadata update
	if m == nil {
		return nil, nil, nil
	}

	if b == *common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE.Enum() {
		return marshalMetadata(m)
	}

	if b == *common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND.Enum() {
		if getExtendableMetadata == nil {
			return nil, nil, errors.New("getExtendableMetadata is required for extend metadata update")
		}

		existing, err := getExtendableMetadata()
		if err != nil {
			return nil, nil, err
		}
		if existing == nil || existing.Labels == nil {
			return marshalMetadata(m)
		}

		// merge labels
		next := &common.MetadataMutable{
			Labels: existing.GetLabels(),
		}
		for k := range m.GetLabels() {
			if v, ok := m.GetLabels()[k]; ok {
				next.Labels[k] = v
			}
		}
		return marshalMetadata(next)
	}

	return nil, nil, fmt.Errorf("unknown metadata update type: %s", b.String())
}

func KeyAccessServerProtoJSON(keyAccessServerJSON []byte) ([]*policy.KeyAccessServer, error) {
	var (
		keyAccessServers []*policy.KeyAccessServer
		raw              []json.RawMessage
	)
	if err := json.Unmarshal(keyAccessServerJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		kas := policy.KeyAccessServer{}
		if err := protojson.Unmarshal(r, &kas); err != nil {
			return nil, err
		}
		keyAccessServers = append(keyAccessServers, &kas)
	}
	return keyAccessServers, nil
}

func GrantedPolicyObjectProtoJSON(grantsJSON []byte) ([]*kasregistry.GrantedPolicyObject, error) {
	var (
		policyObjectGrants []*kasregistry.GrantedPolicyObject
		raw                []json.RawMessage
	)
	if grantsJSON == nil {
		return nil, nil
	}

	if err := json.Unmarshal(grantsJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		po := kasregistry.GrantedPolicyObject{}
		if err := protojson.Unmarshal(r, &po); err != nil {
			return nil, err
		}
		policyObjectGrants = append(policyObjectGrants, &po)
	}
	return policyObjectGrants, nil
}

func MappedPolicyObjectProtoJSON(mappingsJSON []byte) ([]*kasregistry.MappedPolicyObject, error) {
	var (
		policyObjectMappings []*kasregistry.MappedPolicyObject
		raw                  []json.RawMessage
	)
	if mappingsJSON == nil {
		return nil, nil
	}

	if err := json.Unmarshal(mappingsJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		mapping := kasregistry.MappedPolicyObject{}
		if err := protojson.Unmarshal(r, &mapping); err != nil {
			return nil, err
		}
		policyObjectMappings = append(policyObjectMappings, &mapping)
	}
	return policyObjectMappings, nil
}

func KasKeysProtoJSON(keysJSON []byte) ([]*policy.KasKey, error) {
	var (
		keys []*policy.KasKey
		raw  []json.RawMessage
	)
	if err := json.Unmarshal(keysJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		k := policy.KasKey{}
		if err := protojson.Unmarshal(r, &k); err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, nil
}

func FormatAlg(alg policy.Algorithm) (string, error) {
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

func SimpleKasKeysProtoJSON(keysJSON []byte) ([]*policy.SimpleKasKey, error) {
	var (
		keys []*policy.SimpleKasKey
		raw  []json.RawMessage
	)
	if err := json.Unmarshal(keysJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		k, err := UnmarshalSimpleKasKey([]byte(r))
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal simple kas key: %w", err)
		}
		if k != nil {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func UnmarshalSimpleKasKey(keysJSON []byte) (*policy.SimpleKasKey, error) {
	var key *policy.SimpleKasKey
	if keysJSON != nil {
		key = &policy.SimpleKasKey{}
		if err := protojson.Unmarshal(keysJSON, key); err != nil {
			return nil, err
		}
	}
	return key, nil
}

func CertificatesProtoJSON(certsJSON []byte) ([]*policy.Certificate, error) {
	var (
		certs []*policy.Certificate
		raw   []json.RawMessage
	)
	if err := json.Unmarshal(certsJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		c, err := UnmarshalCertificate([]byte(r))
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
		}
		if c != nil {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func UnmarshalCertificate(certJSON []byte) (*policy.Certificate, error) {
	var cert *policy.Certificate
	if certJSON != nil {
		cert = &policy.Certificate{}
		if err := protojson.Unmarshal(certJSON, cert); err != nil {
			return nil, err
		}
	}
	return cert, nil
}

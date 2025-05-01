package db

import (
	"encoding/json"
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
			return nil, nil, fmt.Errorf("getExtendableMetadata is required for extend metadata update")
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

func AsymKeysProtoJSON(keysJSON []byte) ([]*policy.AsymmetricKey, error) {
	var (
		keys []*policy.AsymmetricKey
		raw  []json.RawMessage
	)
	if err := json.Unmarshal(keysJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		k := policy.AsymmetricKey{}
		if err := protojson.Unmarshal(r, &k); err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, nil
}

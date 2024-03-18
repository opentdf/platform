package db

import (
	"encoding/json"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	kasr "github.com/opentdf/platform/protocol/go/kasregistry"
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
	mJson, err := protojson.Marshal(m)
	return mJson, m, err
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
			Labels: existing.Labels,
		}
		for k := range m.GetLabels() {
			if v, ok := m.Labels[k]; ok {
				next.Labels[k] = v
			}
		}
		return marshalMetadata(next)
	}

	return nil, nil, fmt.Errorf("unknown metadata update type: %s", b.String())
}

func KeyAccessServerProtoJSON(keyAccessServerJSON []byte) ([]*kasr.KeyAccessServer, error) {
	var (
		keyAccessServers []*kasr.KeyAccessServer
		raw              []json.RawMessage
	)
	if err := json.Unmarshal(keyAccessServerJSON, &raw); err != nil {
		return nil, err
	}
	for _, r := range raw {
		kas := kasr.KeyAccessServer{}
		if err := protojson.Unmarshal(r, &kas); err != nil {
			return nil, err
		}
		keyAccessServers = append(keyAccessServers, &kas)
	}
	return keyAccessServers, nil
}

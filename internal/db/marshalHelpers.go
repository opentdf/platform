package db

import (
	"encoding/json"

	"github.com/opentdf/platform/protocol/go/common"
	kasr "github.com/opentdf/platform/protocol/go/kasregistry"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Marshal policy metadata is used by the MarshalCreateMetadata and MarshalUpdateMetadata functions to enable
// the creation and update of policy metadata without exposing it to developers. Take note of the immutableMetadata and
// mutableMetadata parameters. The mutableMetadata is the metadata that is passed in by the developer. The immutableMetadata
// is created by the service.
func marshalMetadata(mutableMetadata *common.MetadataMutable, immutableMetadata *common.Metadata) ([]byte, *common.Metadata, error) {
	m := &common.Metadata{
		CreatedAt:   immutableMetadata.GetCreatedAt(),
		UpdatedAt:   immutableMetadata.GetUpdatedAt(),
		Labels:      mutableMetadata.GetLabels(),
		Description: mutableMetadata.GetDescription(),
	}
	mJson, err := protojson.Marshal(m)
	return mJson, m, err
}

func MarshalCreateMetadata(metadata *common.MetadataMutable) ([]byte, *common.Metadata, error) {
	m := &common.Metadata{
		CreatedAt: timestamppb.Now(),
		UpdatedAt: timestamppb.Now(),
	}
	return marshalMetadata(metadata, m)
}

func MarshalUpdateMetadata(existingMetadata *common.Metadata, metadata *common.MetadataMutable) ([]byte, *common.Metadata, error) {
	m := &common.Metadata{
		CreatedAt: existingMetadata.GetCreatedAt(),
		UpdatedAt: timestamppb.Now(),
	}
	return marshalMetadata(metadata, m)
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

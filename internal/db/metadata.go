package db

import (
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Marshal policy metadata is used by the marshalCreateMetadata and marshalUpdateMetadata functions to enable
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

func marshalCreateMetadata(metadata *common.MetadataMutable) ([]byte, *common.Metadata, error) {
	m := &common.Metadata{
		CreatedAt: timestamppb.Now(),
		UpdatedAt: timestamppb.Now(),
	}
	return marshalMetadata(metadata, m)
}

func marshalUpdateMetadata(existingMetadata *common.Metadata, metadata *common.MetadataMutable) ([]byte, *common.Metadata, error) {
	m := &common.Metadata{
		CreatedAt: existingMetadata.GetCreatedAt(),
		UpdatedAt: timestamppb.Now(),
	}
	return marshalMetadata(metadata, m)
}

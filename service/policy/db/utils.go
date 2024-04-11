package db

import (
	"log/slog"

	"github.com/opentdf/platform/protocol/go/common"
	"google.golang.org/protobuf/encoding/protojson"
)

func constructMetadata(table string, isJSON bool) string {
	if table != "" {
		table += "."
	}
	metadata := "JSON_STRIP_NULLS(JSON_BUILD_OBJECT('labels', " + table + "metadata->'labels', 'created_at', " + table + "created_at, 'updated_at', " + table + "updated_at))"

	if isJSON {
		metadata = "'metadata', " + metadata + ", "
	} else {
		metadata += " AS metadata"
	}
	return metadata
}

var createSuffix = "RETURNING id, " + constructMetadata("", false)

func unmarshalMetadata(metadataJSON []byte, m *common.Metadata) error {
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			slog.Error("could not unmarshal metadata", slog.String("error", err.Error()))
			return err
		}
	}
	return nil
}

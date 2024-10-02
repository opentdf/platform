package db

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
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
			return fmt.Errorf("failed to unmarshal metadataJSON [%s]: %w", string(metadataJSON), err)
		}
	}
	return nil
}

func unmarshalAttributeValue(attributeValueJSON []byte, av *policy.Value) error {
	if attributeValueJSON != nil {
		if err := protojson.Unmarshal(attributeValueJSON, av); err != nil {
			return fmt.Errorf("failed to unmarshal attributeValueJSON [%s]: %w", string(attributeValueJSON), err)
		}
	}
	return nil
}

func pgtypeUUID(s string) pgtype.UUID {
	u, err := uuid.Parse(s)

	return pgtype.UUID{
		Bytes: [16]byte(u),
		Valid: err == nil,
	}
}

func pgtypeText(s string) pgtype.Text {
	return pgtype.Text{
		String: s,
		Valid:  s != "",
	}
}

package db

import (
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
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

func unmarshalMetadata(metadataJSON []byte, m *common.Metadata, logger *logger.Logger) error {
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			logger.Error("failed to unmarshal metadata", slog.String("error", err.Error()), slog.String("metadataJSON", string(metadataJSON)))
			return err
		}
	}
	return nil
}

func unmarshalAttributeValue(attributeValueJSON []byte, av *policy.Value, logger *logger.Logger) error {
	if attributeValueJSON != nil {
		if err := protojson.Unmarshal(attributeValueJSON, av); err != nil {
			logger.Error("failed to unmarshal attribute value", slog.String("error", err.Error()), slog.String("attributeValueJSON", string(attributeValueJSON)))
			return err
		}
	}
	return nil
}

func pgtypeUUIDFromString(value string) pgtype.UUID {
	uuidValue, err := uuid.Parse(value)
	return pgtype.UUID{
		Bytes: [16]byte(uuidValue),
		Valid: err == nil,
	}
}

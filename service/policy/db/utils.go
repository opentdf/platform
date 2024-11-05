package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/encoding/protojson"
)

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

func unmarshalSubjectConditionSet(subjectConditionSetJSON []byte, scs *policy.SubjectConditionSet) error {
	if subjectConditionSetJSON != nil {
		if err := protojson.Unmarshal(subjectConditionSetJSON, scs); err != nil {
			return fmt.Errorf("failed to unmarshal scsJSON [%s]: %w", string(subjectConditionSetJSON), err)
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

func pgtypeBool(b bool) pgtype.Bool {
	return pgtype.Bool{
		Bool:  b,
		Valid: true,
	}
}

// Helper function for swallowing the error in a Pgx Transaction rollback per the documentation
func TxRollback(ctx context.Context, tx pgx.Tx) {
	//nolint noop https://pkg.go.dev/github.com/jackc/pgx#hdr-Transactions
	tx.Rollback(ctx)
}

package db

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/encoding/protojson"
)

type paginatedRequest interface {
	GetPagination() *policy.PageRequest
}

func getRequestedLimitOffset(r paginatedRequest) (int32, int32) {
	page := r.GetPagination()
	return getListLimit(page.GetLimit()), page.GetOffset()
}

// Note: Policy Object LIST count is defaulted to 250 if not provided. This may change at any time and is an internal
// concern of the policy services that should not be relied upon for stability.
const defaultObjectListCount = 250

// Defaults the LIST limit to internal default limit value if not provided
func getListLimit(l int32) int32 {
	if l > 0 {
		return l
	}
	return defaultObjectListCount
}

// Returns next page's offset if another page within total, or else returns 0
func getNextOffset(current, limit, total int32) int32 {
	next := current + limit
	if next <= total {
		return next
	}
	return 0
}

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

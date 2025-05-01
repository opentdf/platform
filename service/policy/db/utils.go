package db

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/encoding/protojson"
)

// Gathers request pagination limit/offset or configured default
func (c PolicyDBClient) getRequestedLimitOffset(page *policy.PageRequest) (int32, int32) {
	return getListLimit(page.GetLimit(), c.listCfg.limitDefault), page.GetOffset()
}

func getListLimit(limit int32, fallback int32) int32 {
	if limit > 0 {
		return limit
	}
	return fallback
}

// Returns next page's offset if has not yet reached total, or else returns 0
func getNextOffset(currentOffset, limit, total int32) int32 {
	next := currentOffset + limit
	if next < total {
		return next
	}
	return 0
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

func unmarshalAllActionsProto(stdActionsJSON []byte, customActionsJSON []byte, actions *[]*policy.Action) error {
	var (
		stdActions    = new([]*policy.Action)
		customActions = new([]*policy.Action)
	)
	if err := unmarshalActionsProto(stdActionsJSON, stdActions); err != nil {
		return fmt.Errorf("failed to unmarshal standard actions array [%s]: %w", string(stdActionsJSON), err)
	}
	if err := unmarshalActionsProto(customActionsJSON, customActions); err != nil {
		return fmt.Errorf("failed to unmarshal custom actions array [%s]: %w", string(customActionsJSON), err)
	}
	*actions = append(*actions, *stdActions...)
	*actions = append(*actions, *customActions...)

	return nil
}

func unmarshalActionsProto(actionsJSON []byte, actions *[]*policy.Action) error {
	var raw []json.RawMessage

	if actionsJSON != nil {
		if err := json.Unmarshal(actionsJSON, &raw); err != nil {
			return fmt.Errorf("failed to unmarshal actions array [%s]: %w", string(actionsJSON), err)
		}

		for _, r := range raw {
			a := policy.Action{}
			if err := protojson.Unmarshal(r, &a); err != nil {
				return fmt.Errorf("failed to unmarshal action [%s]: %w", string(r), err)
			}
			*actions = append(*actions, &a)
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

func pgtypeInt4(i int32, valid bool) pgtype.Int4 {
	return pgtype.Int4{
		Int32: i,
		Valid: valid,
	}
}

func UUIDToString(uuid pgtype.UUID) string {
	if !uuid.Valid {
		return ""
	}

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid.Bytes[0:4],
		uuid.Bytes[4:6],
		uuid.Bytes[6:8],
		uuid.Bytes[8:10],
		uuid.Bytes[10:16],
	)
}

package db

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/pkg/db"
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

func unmarshalResourceMappingGroup(rmgroupJSON []byte, rmg *policy.ResourceMappingGroup) error {
	if rmgroupJSON != nil {
		if err := protojson.Unmarshal(rmgroupJSON, rmg); err != nil {
			return fmt.Errorf("failed to unmarshal rmgroupJSON [%s]: %w", string(rmgroupJSON), err)
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

func unmarshalPrivatePublicKeyContext(pubCtx, privCtx []byte) (*policy.PublicKeyCtx, *policy.PrivateKeyCtx, error) {
	var pubKey *policy.PublicKeyCtx
	var privKey *policy.PrivateKeyCtx
	if pubCtx != nil {
		pubKey = &policy.PublicKeyCtx{}
		if err := protojson.Unmarshal(pubCtx, pubKey); err != nil {
			return nil, nil, errors.Join(fmt.Errorf("failed to unmarshal public key context [%s]: %w", string(pubCtx), err), db.ErrUnmarshalValueFailed)
		}
	}
	if privCtx != nil {
		privKey = &policy.PrivateKeyCtx{}
		if err := protojson.Unmarshal(privCtx, privKey); err != nil {
			return nil, nil, errors.Join(errors.New("failed to unmarshal private key context"), db.ErrUnmarshalValueFailed)
		}
	}
	return pubKey, privKey, nil
}

func unmarshalObligationTriggers(triggersJSON []byte) ([]*policy.ObligationTrigger, error) {
	obligationTriggers := make([]*policy.ObligationTrigger, 0)
	if triggersJSON == nil {
		return obligationTriggers, nil
	}

	raw := []json.RawMessage{}
	if err := json.Unmarshal(triggersJSON, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal triggers array [%s]: %w", string(triggersJSON), err)
	}

	triggers := make([]*policy.ObligationTrigger, 0, len(raw))
	for _, r := range raw {
		t := &policy.ObligationTrigger{}
		if err := protojson.Unmarshal(r, t); err != nil {
			return nil, fmt.Errorf("failed to unmarshal trigger [%s]: %w", string(r), err)
		}
		triggers = append(triggers, t)
	}

	return triggers, nil
}

func unmarshalObligationTrigger(triggerJSON []byte) (*policy.ObligationTrigger, error) {
	trigger := &policy.ObligationTrigger{}
	if triggerJSON == nil {
		return trigger, nil
	}

	if err := protojson.Unmarshal(triggerJSON, trigger); err != nil {
		return nil, errors.Join(fmt.Errorf("failed to unmarshal obligation trigger context [%s]: %w", string(triggerJSON), err), db.ErrUnmarshalValueFailed)
	}
	return trigger, nil
}

func unmarshalObligations(obligationsJSON []byte) ([]*policy.Obligation, error) {
	if obligationsJSON == nil {
		return nil, nil
	}

	raw := []json.RawMessage{}
	if err := json.Unmarshal(obligationsJSON, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal obligations array [%s]: %w", string(obligationsJSON), err)
	}

	obls := make([]*policy.Obligation, 0, len(raw))
	for _, r := range raw {
		o := &policy.Obligation{}
		if err := protojson.Unmarshal(r, o); err != nil {
			return nil, fmt.Errorf("failed to unmarshal obligation [%s]: %w", string(r), err)
		}
		obls = append(obls, o)
	}

	return obls, nil
}

func unmarshalObligationValues(valuesJSON []byte) ([]*policy.ObligationValue, error) {
	if valuesJSON == nil {
		return nil, nil
	}

	raw := []json.RawMessage{}
	if err := json.Unmarshal(valuesJSON, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal values array [%s]: %w", string(valuesJSON), err)
	}

	values := make([]*policy.ObligationValue, 0, len(raw))
	for _, r := range raw {
		v := &policy.ObligationValue{}
		if err := protojson.Unmarshal(r, v); err != nil {
			return nil, fmt.Errorf("failed to unmarshal value [%s]: %w", string(r), err)
		}
		values = append(values, v)
	}

	return values, nil
}

func unmarshalNamespace(namespaceJSON []byte, namespace *policy.Namespace) error {
	if namespaceJSON != nil {
		if err := protojson.Unmarshal(namespaceJSON, namespace); err != nil {
			return fmt.Errorf("failed to unmarshal namespaceJSON [%s]: %w", string(namespaceJSON), err)
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

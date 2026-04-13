package db

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

// Sort field constants shared across all List endpoint sort helpers.
const (
	sortFieldName      = "name"
	sortFieldCreatedAt = "created_at"
	sortFieldUpdatedAt = "updated_at"
	sortFieldUri       = "uri"
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

func getSortDirection(direction policy.SortDirection) string {
	switch direction {
	case policy.SortDirection_SORT_DIRECTION_DESC:
		return "DESC"
	case policy.SortDirection_SORT_DIRECTION_UNSPECIFIED, policy.SortDirection_SORT_DIRECTION_ASC:
		return "ASC"
	default:
		return ""
	}
}

// GetNamespacesSortParams maps the strongly-typed NamespacesSort enum to
// SQL-compatible field name and direction strings.
// Returns empty strings when sort is nil or empty (backward compatible —
// callers fall back to default ORDER BY created_at DESC).
func GetNamespacesSortParams(sort []*namespaces.NamespacesSort) (string, string) {
	if len(sort) == 0 || sort[0] == nil {
		return "", ""
	}
	s := sort[0]

	var field string
	switch s.GetField() {
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_NAME:
		field = sortFieldName
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_FQN:
		field = "fqn"
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_CREATED_AT:
		field = sortFieldCreatedAt
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UPDATED_AT:
		field = sortFieldUpdatedAt
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UNSPECIFIED:
		return "", ""
	default:
		return "", ""
	}

	return field, getSortDirection(s.GetDirection())
}

// GetSubjectConditionSetsSortParams maps the strongly-typed SubjectConditionSetsSort enum to
// SQL-compatible field name and direction strings.
// Returns empty strings when sort is nil or empty (backward compatible —
// callers fall back to default ORDER BY created_at DESC).
func GetSubjectConditionSetsSortParams(sort []*subjectmapping.SubjectConditionSetsSort) (string, string) {
	if len(sort) == 0 || sort[0] == nil {
		return "", ""
	}
	s := sort[0]

	var field string
	switch s.GetField() {
	case subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_CREATED_AT:
		field = sortFieldCreatedAt
	case subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UPDATED_AT:
		field = sortFieldUpdatedAt
	case subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UNSPECIFIED:
		return "", ""
	default:
		return "", ""
	}

	return field, getSortDirection(s.GetDirection())
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

// GetSubjectMappingsSortParams maps the strongly-typed SubjectMappingsSort enum to
// SQL-compatible field name and direction strings.
// Returns empty strings when sort is nil or empty (backward compatible —
// callers fall back to default ORDER BY created_at DESC).
func GetSubjectMappingsSortParams(sort []*subjectmapping.SubjectMappingsSort) (string, string) {
	if len(sort) == 0 || sort[0] == nil {
		return "", ""
	}
	s := sort[0]

	var field string
	switch s.GetField() {
	case subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_CREATED_AT:
		field = sortFieldCreatedAt
	case subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UPDATED_AT:
		field = sortFieldUpdatedAt
	case subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UNSPECIFIED:
		return "", ""
	default:
		return "", ""
	}

	return field, getSortDirection(s.GetDirection())
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

// GetAttributesSortParams maps the strongly-typed AttributesSort enum to
// SQL-compatible field name and direction strings.
// Returns empty strings when sort is nil or empty (backward compatible —
// callers fall back to default ORDER BY created_at DESC).
func GetAttributesSortParams(sort []*attributes.AttributesSort) (string, string) {
	if len(sort) == 0 || sort[0] == nil {
		return "", ""
	}
	s := sort[0]

	var field string
	switch s.GetField() {
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_NAME:
		field = sortFieldName
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_CREATED_AT:
		field = sortFieldCreatedAt
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UPDATED_AT:
		field = sortFieldUpdatedAt
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UNSPECIFIED:
		return "", ""
	default:
		return "", ""
	}

	return field, getSortDirection(s.GetDirection())
}

// GetKeyAccessServersSortParams maps the strongly-typed KeyAccessServersSort enum to
// SQL-compatible field name and direction strings.
// Returns empty strings when sort is nil or empty (backward compatible —
// callers fall back to default ORDER BY created_at DESC).
func GetKeyAccessServersSortParams(sort []*kasregistry.KeyAccessServersSort) (string, string) {
	if len(sort) == 0 || sort[0] == nil {
		return "", ""
	}
	s := sort[0]

	var field string
	switch s.GetField() {
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_NAME:
		field = sortFieldName
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_URI:
		field = sortFieldUri
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_CREATED_AT:
		field = sortFieldCreatedAt
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UPDATED_AT:
		field = sortFieldUpdatedAt
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UNSPECIFIED:
		return "", ""
	default:
		return "", ""
	}

	return field, getSortDirection(s.GetDirection())
}

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
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

// Sort field constants shared across all List endpoint sort helpers.
const (
	sortFieldName      = "name"
	sortFieldCreatedAt = "created_at"
	sortFieldUpdatedAt = "updated_at"
	sortFieldFQN       = "fqn"
	sortFieldURI       = "uri"
	sortFieldKeyID     = "key_id"
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

// getSortDirection maps the direction enum to a SQL string.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getSortDirection(direction policy.SortDirection) string {
	switch direction {
	case policy.SortDirection_SORT_DIRECTION_DESC:
		return "DESC"
	case policy.SortDirection_SORT_DIRECTION_ASC:
		return "ASC"
	case policy.SortDirection_SORT_DIRECTION_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// getNamespacesSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getNamespacesSortField(field namespaces.SortNamespacesType) string {
	switch field {
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_NAME:
		return sortFieldName
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_FQN:
		return sortFieldFQN
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetNamespacesSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetNamespacesSortParams(sort []*namespaces.NamespacesSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getNamespacesSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
}

// getSubjectConditionSetsSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getSubjectConditionSetsSortField(field subjectmapping.SortSubjectConditionSetsType) string {
	switch field {
	case subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetSubjectConditionSetsSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetSubjectConditionSetsSortParams(sort []*subjectmapping.SubjectConditionSetsSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getSubjectConditionSetsSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
}

// getObligationsSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getObligationsSortField(field obligations.SortObligationsType) string {
	switch field {
	case obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_NAME:
		return sortFieldName
	case obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_FQN:
		return sortFieldFQN
	case obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetObligationsSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetObligationsSortParams(sort []*obligations.ObligationsSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getObligationsSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
}

// getRegisteredResourcesSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getRegisteredResourcesSortField(field registeredresources.SortRegisteredResourcesType) string {
	switch field {
	case registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_NAME:
		return sortFieldName
	case registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetRegisteredResourcesSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetRegisteredResourcesSortParams(sort []*registeredresources.RegisteredResourcesSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getRegisteredResourcesSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
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

// getSubjectMappingsSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getSubjectMappingsSortField(field subjectmapping.SortSubjectMappingsType) string {
	switch field {
	case subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetSubjectMappingsSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetSubjectMappingsSortParams(sort []*subjectmapping.SubjectMappingsSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getSubjectMappingsSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
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

// getAttributesSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getAttributesSortField(field attributes.SortAttributesType) string {
	switch field {
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_NAME:
		return sortFieldName
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetAttributesSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetAttributesSortParams(sort []*attributes.AttributesSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getAttributesSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
}

// getKasKeysSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getKasKeysSortField(field kasregistry.SortKasKeysType) string {
	switch field {
	case kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_KEY_ID:
		return sortFieldKeyID
	case kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetKasKeysSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetKasKeysSortParams(sort []*kasregistry.KasKeysSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getKasKeysSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
}

// getKeyAccessServersSortField maps the field enum to a SQL column name.
// UNSPECIFIED returns empty so SQL can apply its per-query default.
func getKeyAccessServersSortField(field kasregistry.SortKeyAccessServersType) string {
	switch field {
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_NAME:
		return sortFieldName
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_URI:
		return sortFieldURI
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_CREATED_AT:
		return sortFieldCreatedAt
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UPDATED_AT:
		return sortFieldUpdatedAt
	case kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UNSPECIFIED:
		fallthrough
	default:
		return ""
	}
}

// GetKeyAccessServersSortParams resolves sort field and direction independently,
// returning SQL-compatible strings. Empty strings delegate defaults to SQL.
func GetKeyAccessServersSortParams(sort []*kasregistry.KeyAccessServersSort) (string, string) {
	if len(sort) == 0 {
		return "", ""
	}
	return getKeyAccessServersSortField(sort[0].GetField()), getSortDirection(sort[0].GetDirection())
}

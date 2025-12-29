package db

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

// sqliteTimestampRegex matches SQLite datetime format: "YYYY-MM-DD HH:MM:SS"
var sqliteTimestampRegex = regexp.MustCompile(`"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})"`)

// sqliteBooleanRegex matches SQLite boolean values stored as integers in JSON
// Matches patterns like "active":1 or "active":0 (with possible whitespace)
var sqliteBooleanTrueRegex = regexp.MustCompile(`("(?:active|is_standard)")\s*:\s*1`)
var sqliteBooleanFalseRegex = regexp.MustCompile(`("(?:active|is_standard)")\s*:\s*0`)

// escapedJSONFieldRegex matches JSON fields that contain escaped JSON strings.
// SQLite stores nested objects as escaped strings like "public_key":"{\"remote\":\"...\"}"
// This regex captures the field name and the escaped JSON content to allow unescaping.
var escapedJSONFieldRegex = regexp.MustCompile(`"(public_key|cached|remote)"\s*:\s*"(\{[^"]*(?:\\.[^"]*)*\})"`)

// normalizeSQLiteTimestamps converts SQLite-specific JSON formats to protojson-compatible formats:
// 1. SQLite datetime format to RFC 3339 (e.g., "2025-12-29 21:06:39" -> "2025-12-29T21:06:39Z")
// 2. SQLite boolean integers to JSON booleans (e.g., "active":1 -> "active":true)
// 3. Escaped JSON strings to proper JSON objects (e.g., "public_key":"{\"remote\":\"...\"}" -> "public_key":{"remote":"..."})
func normalizeSQLiteTimestamps(jsonBytes []byte) []byte {
	if jsonBytes == nil {
		return nil
	}
	// Replace "YYYY-MM-DD HH:MM:SS" with "YYYY-MM-DDTHH:MM:SSZ"
	result := sqliteTimestampRegex.ReplaceAll(jsonBytes, []byte(`"${1}T${2}Z"`))
	// Replace boolean integers with boolean values
	result = sqliteBooleanTrueRegex.ReplaceAll(result, []byte(`${1}:true`))
	result = sqliteBooleanFalseRegex.ReplaceAll(result, []byte(`${1}:false`))
	// Normalize escaped JSON fields (like public_key)
	result = normalizeEscapedJSONFields(result)
	return result
}

// normalizeEscapedJSONFields converts fields containing escaped JSON strings to proper JSON objects.
// This is needed for SQLite compatibility where nested objects are stored as escaped strings.
func normalizeEscapedJSONFields(jsonBytes []byte) []byte {
	if jsonBytes == nil {
		return nil
	}

	// Replace escaped JSON string fields with actual JSON objects
	result := escapedJSONFieldRegex.ReplaceAllFunc(jsonBytes, func(match []byte) []byte {
		// Extract the field name and escaped JSON content
		submatches := escapedJSONFieldRegex.FindSubmatch(match)
		if len(submatches) != 3 {
			return match
		}

		fieldName := string(submatches[1])
		escapedJSON := string(submatches[2])

		// Unescape the JSON string
		var unescaped string
		if err := json.Unmarshal([]byte(`"`+escapedJSON+`"`), &unescaped); err != nil {
			return match
		}

		// Return the field with proper JSON object
		return []byte(fmt.Sprintf(`"%s":%s`, fieldName, unescaped))
	})

	return result
}

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
		// Normalize SQLite timestamps to RFC 3339 format for protojson
		normalized := normalizeSQLiteTimestamps(metadataJSON)
		if err := protojson.Unmarshal(normalized, m); err != nil {
			return fmt.Errorf("failed to unmarshal metadataJSON [%s]: %w", string(metadataJSON), err)
		}
	}
	return nil
}

func unmarshalAttributeValue(attributeValueJSON []byte, av *policy.Value) error {
	if attributeValueJSON != nil {
		normalized := normalizeSQLiteTimestamps(attributeValueJSON)
		if err := protojson.Unmarshal(normalized, av); err != nil {
			return fmt.Errorf("failed to unmarshal attributeValueJSON [%s]: %w", string(attributeValueJSON), err)
		}
	}
	return nil
}

func unmarshalSubjectConditionSet(subjectConditionSetJSON []byte, scs *policy.SubjectConditionSet) error {
	if subjectConditionSetJSON != nil {
		normalized := normalizeSQLiteTimestamps(subjectConditionSetJSON)
		if err := protojson.Unmarshal(normalized, scs); err != nil {
			return fmt.Errorf("failed to unmarshal scsJSON [%s]: %w", string(subjectConditionSetJSON), err)
		}
	}
	return nil
}

func unmarshalResourceMappingGroup(rmgroupJSON []byte, rmg *policy.ResourceMappingGroup) error {
	if rmgroupJSON != nil {
		normalized := normalizeSQLiteTimestamps(rmgroupJSON)
		if err := protojson.Unmarshal(normalized, rmg); err != nil {
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
			normalized := normalizeSQLiteTimestamps(r)
			if err := protojson.Unmarshal(normalized, &a); err != nil {
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
		normalized := normalizeSQLiteTimestamps(pubCtx)
		if err := protojson.Unmarshal(normalized, pubKey); err != nil {
			return nil, nil, errors.Join(fmt.Errorf("failed to unmarshal public key context [%s]: %w", string(pubCtx), err), db.ErrUnmarshalValueFailed)
		}
	}
	if privCtx != nil {
		privKey = &policy.PrivateKeyCtx{}
		normalized := normalizeSQLiteTimestamps(privCtx)
		if err := protojson.Unmarshal(normalized, privKey); err != nil {
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
		normalized := normalizeSQLiteTimestamps(r)
		if err := protojson.Unmarshal(normalized, t); err != nil {
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

	normalized := normalizeSQLiteTimestamps(triggerJSON)
	if err := protojson.Unmarshal(normalized, trigger); err != nil {
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
		normalized := normalizeSQLiteTimestamps(r)
		if err := protojson.Unmarshal(normalized, o); err != nil {
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
		normalized := normalizeSQLiteTimestamps(r)
		if err := protojson.Unmarshal(normalized, v); err != nil {
			return nil, fmt.Errorf("failed to unmarshal value [%s]: %w", string(r), err)
		}
		values = append(values, v)
	}

	return values, nil
}

func unmarshalNamespace(namespaceJSON []byte, namespace *policy.Namespace) error {
	if namespaceJSON != nil {
		normalized := normalizeSQLiteTimestamps(namespaceJSON)
		if err := protojson.Unmarshal(normalized, namespace); err != nil {
			return fmt.Errorf("failed to unmarshal namespaceJSON [%s]: %w", string(namespaceJSON), err)
		}
		// Post-process KasKeys to decode base64-encoded PEM values (SQLite compatibility)
		decodeBase64PemInKasKeys(namespace.GetKasKeys())
	}
	return nil
}

// decodeBase64PemInKasKeys decodes base64-encoded PEM values in SimpleKasKey objects.
// This is needed for SQLite compatibility where PostgreSQL decodes base64 in the query,
// but SQLite returns raw base64.
func decodeBase64PemInKasKeys(keys []*policy.SimpleKasKey) {
	for _, key := range keys {
		if key.GetPublicKey() != nil && key.GetPublicKey().GetPem() != "" {
			pem := key.GetPublicKey().GetPem()
			// Check if the PEM looks like base64 (doesn't start with "-----BEGIN")
			if len(pem) > 0 && pem[0] != '-' {
				decoded, err := base64.StdEncoding.DecodeString(pem)
				if err == nil {
					key.PublicKey.Pem = string(decoded)
				}
			}
		}
	}
}

func pgtypeUUID(s string) pgtype.UUID {
	u, err := uuid.Parse(s)

	return pgtype.UUID{
		Bytes: [16]byte(u),
		Valid: err == nil,
	}
}

func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
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

func pgtypeBoolFromPtr(b *bool) pgtype.Bool {
	if b == nil {
		return pgtype.Bool{Valid: false}
	}
	return pgtype.Bool{
		Bool:  *b,
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

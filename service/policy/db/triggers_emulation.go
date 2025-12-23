package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// This file contains application-layer emulation of PostgreSQL triggers for SQLite.
// These functions should be called after the corresponding database operations
// when using SQLite, as SQLite doesn't support the complex trigger logic.

// CascadeDeactivateNamespace deactivates all attribute definitions and their values
// when a namespace is deactivated. This emulates the PostgreSQL trigger:
// cascade_deactivation('attribute_definitions', 'namespace_id')
func (c *PolicyDBClient) CascadeDeactivateNamespace(ctx context.Context, namespaceID string) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via trigger
	}

	return c.RunInTx(ctx, func(txClient *PolicyDBClient) error {
		db := txClient.router.SQLDB()

		// Get all definition IDs in this namespace
		rows, err := db.QueryContext(ctx,
			"SELECT id FROM attribute_definitions WHERE namespace_id = ?",
			namespaceID)
		if err != nil {
			return fmt.Errorf("failed to query definitions for namespace: %w", err)
		}
		defer rows.Close()

		var definitionIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("failed to scan definition id: %w", err)
			}
			definitionIDs = append(definitionIDs, id)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("error iterating definitions: %w", err)
		}

		// Deactivate all definitions in this namespace
		_, err = db.ExecContext(ctx,
			"UPDATE attribute_definitions SET active = 0 WHERE namespace_id = ?",
			namespaceID)
		if err != nil {
			return fmt.Errorf("failed to deactivate definitions: %w", err)
		}

		// Deactivate all values for each definition
		for _, defID := range definitionIDs {
			if err := txClient.cascadeDeactivateDefinitionValues(ctx, defID); err != nil {
				return err
			}
		}

		return nil
	})
}

// CascadeDeactivateDefinition deactivates all attribute values when a definition
// is deactivated. This emulates the PostgreSQL trigger:
// cascade_deactivation('attribute_values', 'attribute_definition_id')
func (c *PolicyDBClient) CascadeDeactivateDefinition(ctx context.Context, definitionID string) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via trigger
	}

	return c.cascadeDeactivateDefinitionValues(ctx, definitionID)
}

func (c *PolicyDBClient) cascadeDeactivateDefinitionValues(ctx context.Context, definitionID string) error {
	db := c.router.SQLDB()
	_, err := db.ExecContext(ctx,
		"UPDATE attribute_values SET active = 0 WHERE attribute_definition_id = ?",
		definitionID)
	if err != nil {
		return fmt.Errorf("failed to deactivate values for definition %s: %w", definitionID, err)
	}
	return nil
}

// KeyRotationResult contains the result of a key rotation operation.
type KeyRotationResult struct {
	PreviousActiveKeyID string
	MappingsCopied      int
}

// EmulateKeyRotation handles the key rotation logic that PostgreSQL handles via
// the update_active_key trigger. When a new key is inserted for a KAS+algorithm
// combination that already has an active key, this function:
// 1. Copies all mappings from the old active key to the new key
// 2. Deactivates the old key
// 3. Activates the new key
func (c *PolicyDBClient) EmulateKeyRotation(ctx context.Context, newKeyID, kasID string, algorithm int) (*KeyRotationResult, error) {
	if !c.IsSQLite() {
		return nil, nil // PostgreSQL handles this via trigger
	}

	var result KeyRotationResult

	err := c.RunInTx(ctx, func(txClient *PolicyDBClient) error {
		db := txClient.router.SQLDB()

		// Find existing active key for this KAS + algorithm
		var currentActiveKeyID sql.NullString
		err := db.QueryRowContext(ctx,
			`SELECT id FROM key_access_server_keys
			 WHERE key_access_server_id = ? AND key_algorithm = ? AND key_status = 1
			 AND id != ?`,
			kasID, algorithm, newKeyID).Scan(&currentActiveKeyID)

		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to find current active key: %w", err)
		}

		// If no active key exists, just activate the new one
		if !currentActiveKeyID.Valid {
			_, err = db.ExecContext(ctx,
				"UPDATE key_access_server_keys SET key_status = 1 WHERE id = ?",
				newKeyID)
			if err != nil {
				return fmt.Errorf("failed to activate new key: %w", err)
			}
			return nil
		}

		result.PreviousActiveKeyID = currentActiveKeyID.String

		// Copy namespace mappings
		res, err := db.ExecContext(ctx,
			`INSERT INTO attribute_namespace_public_key_map (namespace_id, key_id)
			 SELECT namespace_id, ? FROM attribute_namespace_public_key_map WHERE key_id = ?`,
			newKeyID, currentActiveKeyID.String)
		if err != nil {
			return fmt.Errorf("failed to copy namespace mappings: %w", err)
		}
		count, _ := res.RowsAffected()
		result.MappingsCopied += int(count)

		// Copy definition mappings
		res, err = db.ExecContext(ctx,
			`INSERT INTO attribute_definition_public_key_map (definition_id, key_id)
			 SELECT definition_id, ? FROM attribute_definition_public_key_map WHERE key_id = ?`,
			newKeyID, currentActiveKeyID.String)
		if err != nil {
			return fmt.Errorf("failed to copy definition mappings: %w", err)
		}
		count, _ = res.RowsAffected()
		result.MappingsCopied += int(count)

		// Copy value mappings
		res, err = db.ExecContext(ctx,
			`INSERT INTO attribute_value_public_key_map (value_id, key_id)
			 SELECT value_id, ? FROM attribute_value_public_key_map WHERE key_id = ?`,
			newKeyID, currentActiveKeyID.String)
		if err != nil {
			return fmt.Errorf("failed to copy value mappings: %w", err)
		}
		count, _ = res.RowsAffected()
		result.MappingsCopied += int(count)

		// Deactivate old key
		_, err = db.ExecContext(ctx,
			"UPDATE key_access_server_keys SET key_status = 2 WHERE id = ?", // 2 = inactive
			currentActiveKeyID.String)
		if err != nil {
			return fmt.Errorf("failed to deactivate old key: %w", err)
		}

		// Activate new key
		_, err = db.ExecContext(ctx,
			"UPDATE key_access_server_keys SET key_status = 1 WHERE id = ?", // 1 = active
			newKeyID)
		if err != nil {
			return fmt.Errorf("failed to activate new key: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateKeyWasMapped sets the was_mapped flag on a key when it's mapped to
// a namespace, definition, or value. This emulates the update_was_mapped trigger.
func (c *PolicyDBClient) UpdateKeyWasMapped(ctx context.Context, keyID string) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via trigger
	}

	db := c.router.SQLDB()
	_, err := db.ExecContext(ctx,
		"UPDATE key_access_server_keys SET legacy = 1 WHERE id = ?", // Using legacy as was_mapped equivalent
		keyID)
	if err != nil {
		return fmt.Errorf("failed to update was_mapped for key %s: %w", keyID, err)
	}
	return nil
}

// selectorConditionJSON represents the structure of subject condition JSON for selector extraction
type selectorConditionJSON struct {
	SubjectSets []selectorSubjectSet `json:"subject_sets"`
}

// selectorSubjectSet is part of the condition structure
type selectorSubjectSet struct {
	ConditionGroups []selectorConditionGroup `json:"conditionGroups"`
}

// selectorConditionGroup is part of the condition structure
type selectorConditionGroup struct {
	Conditions []selectorCondition `json:"conditions"`
}

// selectorCondition is the innermost condition structure
type selectorCondition struct {
	SubjectExternalSelectorValue string `json:"subjectExternalSelectorValue"`
}

// ExtractSelectorValues extracts unique selector values from the condition JSONB.
// This emulates the extract_selector_values trigger that maintains the
// selector_values column on subject_condition_set.
func ExtractSelectorValues(conditionJSON []byte) ([]string, error) {
	if len(conditionJSON) == 0 {
		return nil, nil
	}

	var condition selectorConditionJSON
	if err := json.Unmarshal(conditionJSON, &condition); err != nil {
		// Try alternate structure where condition itself is the array
		var subjectSets []selectorSubjectSet
		if err2 := json.Unmarshal(conditionJSON, &subjectSets); err2 != nil {
			return nil, fmt.Errorf("failed to unmarshal condition JSON: %w (also tried array: %v)", err, err2)
		}
		condition.SubjectSets = subjectSets
	}

	// Extract unique selector values
	seen := make(map[string]struct{})
	var values []string

	for _, ss := range condition.SubjectSets {
		for _, cg := range ss.ConditionGroups {
			for _, c := range cg.Conditions {
				if c.SubjectExternalSelectorValue != "" {
					if _, exists := seen[c.SubjectExternalSelectorValue]; !exists {
						seen[c.SubjectExternalSelectorValue] = struct{}{}
						values = append(values, c.SubjectExternalSelectorValue)
					}
				}
			}
		}
	}

	return values, nil
}

// UpdateSelectorValues updates the selector_values column for a subject_condition_set.
// This should be called after INSERT or UPDATE on subject_condition_set when using SQLite.
func (c *PolicyDBClient) UpdateSelectorValues(ctx context.Context, subjectConditionSetID string, conditionJSON []byte) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via trigger
	}

	values, err := ExtractSelectorValues(conditionJSON)
	if err != nil {
		return fmt.Errorf("failed to extract selector values: %w", err)
	}

	// Convert to JSON array for storage
	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return fmt.Errorf("failed to marshal selector values: %w", err)
	}

	db := c.router.SQLDB()
	_, err = db.ExecContext(ctx,
		"UPDATE subject_condition_set SET selector_values = ? WHERE id = ?",
		string(valuesJSON), subjectConditionSetID)
	if err != nil {
		return fmt.Errorf("failed to update selector_values: %w", err)
	}

	return nil
}

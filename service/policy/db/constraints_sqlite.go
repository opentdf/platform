package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/opentdf/platform/service/pkg/db"
)

// This file contains application-layer emulation of PostgreSQL constraints for SQLite.
// These constraints must be validated before INSERT/UPDATE operations when using SQLite.

// ErrActiveKeyExists is returned when attempting to create a second active key
// for the same KAS and algorithm combination.
var ErrActiveKeyExists = errors.New("an active key already exists for this KAS and algorithm")

// ValidateUniqueActiveKey ensures there is at most one active key per KAS per algorithm.
// This emulates the PostgreSQL EXCLUDE constraint:
//
//	CONSTRAINT unique_active_key EXCLUDE (
//	    key_access_server_id WITH =,
//	    alg WITH =
//	) WHERE (is_active)
//
// Call this BEFORE inserting or updating a key to active status.
func (c *PolicyDBClient) ValidateUniqueActiveKey(ctx context.Context, kasID string, algorithm int, excludeKeyID string) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via EXCLUDE constraint
	}

	sqlDB := c.router.SQLDB()

	var existingID string
	var err error

	if excludeKeyID != "" {
		// Check for existing active key, excluding the key being updated
		err = sqlDB.QueryRowContext(ctx,
			`SELECT id FROM key_access_server_keys
			 WHERE key_access_server_id = ?
			   AND key_algorithm = ?
			   AND key_status = 1
			   AND id != ?
			 LIMIT 1`,
			kasID, algorithm, excludeKeyID).Scan(&existingID)
	} else {
		// Check for any existing active key
		err = sqlDB.QueryRowContext(ctx,
			`SELECT id FROM key_access_server_keys
			 WHERE key_access_server_id = ?
			   AND key_algorithm = ?
			   AND key_status = 1
			 LIMIT 1`,
			kasID, algorithm).Scan(&existingID)
	}

	if err == sql.ErrNoRows {
		return nil // No conflict, safe to proceed
	}
	if err != nil {
		return fmt.Errorf("failed to check for existing active key: %w", err)
	}

	// An active key exists
	return fmt.Errorf("%w: key %s is active for KAS %s with algorithm %d",
		ErrActiveKeyExists, existingID, kasID, algorithm)
}

// ValidateKeyNotMapped checks if a key has any mappings before deletion.
// This emulates the PostgreSQL trigger that restricts key deletion when mapped.
func (c *PolicyDBClient) ValidateKeyNotMapped(ctx context.Context, keyID string) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via trigger
	}

	sqlDB := c.router.SQLDB()

	// Check namespace mappings
	var count int
	err := sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attribute_namespace_public_key_map WHERE key_id = ?`,
		keyID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check namespace mappings: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: key %s has %d namespace mappings",
			db.ErrForeignKeyViolation, keyID, count)
	}

	// Check definition mappings
	err = sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attribute_definition_public_key_map WHERE key_id = ?`,
		keyID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check definition mappings: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: key %s has %d definition mappings",
			db.ErrForeignKeyViolation, keyID, count)
	}

	// Check value mappings
	err = sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attribute_value_public_key_map WHERE key_id = ?`,
		keyID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check value mappings: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: key %s has %d value mappings",
			db.ErrForeignKeyViolation, keyID, count)
	}

	return nil
}

// ValidateProviderNotReferenced checks if a provider has any keys before deletion.
// This emulates the PostgreSQL trigger that restricts provider_config deletion.
func (c *PolicyDBClient) ValidateProviderNotReferenced(ctx context.Context, providerID string) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via trigger
	}

	sqlDB := c.router.SQLDB()

	var count int
	err := sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM key_access_server_keys WHERE provider_config_id = ?`,
		providerID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check key references: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: provider %s has %d keys referencing it",
			db.ErrForeignKeyViolation, providerID, count)
	}

	return nil
}

// ValidateUniqueProviderName ensures provider names are unique per manager.
// This emulates the PostgreSQL UNIQUE constraint on (provider_name, manager).
func (c *PolicyDBClient) ValidateUniqueProviderName(ctx context.Context, providerName, manager, excludeID string) error {
	if !c.IsSQLite() {
		return nil // PostgreSQL handles this via UNIQUE constraint
	}

	sqlDB := c.router.SQLDB()

	var existingID string
	var err error

	if excludeID != "" {
		err = sqlDB.QueryRowContext(ctx,
			`SELECT id FROM provider_config
			 WHERE provider_name = ? AND manager = ? AND id != ?
			 LIMIT 1`,
			providerName, manager, excludeID).Scan(&existingID)
	} else {
		err = sqlDB.QueryRowContext(ctx,
			`SELECT id FROM provider_config
			 WHERE provider_name = ? AND manager = ?
			 LIMIT 1`,
			providerName, manager).Scan(&existingID)
	}

	if err == sql.ErrNoRows {
		return nil // No conflict
	}
	if err != nil {
		return fmt.Errorf("failed to check for existing provider: %w", err)
	}

	return fmt.Errorf("%w: provider with name %q and manager %q already exists (id: %s)",
		db.ErrUniqueConstraintViolation, providerName, manager, existingID)
}

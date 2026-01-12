// Package casbin provides a Casbin-based authorization implementation.
package casbin

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/opentdf/platform/service/logger"
	"gorm.io/gorm"
)

// CreateSQLAdapter creates a GORM-backed Casbin adapter.
// The casbin_rule table is created in the specified schema before adapter initialization.
//
// Parameters:
//   - gormDB: An existing GORM database connection
//   - schema: Database schema name where the table will be created
//   - log: Logger for operation logging
//
// Returns the adapter and any error encountered during creation.
func CreateSQLAdapter(gormDB *gorm.DB, schema string, log *logger.Logger) (persist.Adapter, error) {
	if gormDB == nil {
		return nil, fmt.Errorf("gormDB is required for SQL adapter")
	}

	log.Info("initializing SQL-backed Casbin adapter",
		slog.String("schema", schema),
	)

	// Pre-create the schema and casbin_rule table
	// This avoids the "no schema has been selected" error from gorm-adapter's AutoMigrate
	if schema != "" {
		// Create schema if it doesn't exist
		createSchemaSQL := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)
		if err := gormDB.Exec(createSchemaSQL).Error; err != nil {
			return nil, fmt.Errorf("failed to create schema: %w", err)
		}

		// Create table in the schema
		createTableSQL := fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s.casbin_rule (
				id bigserial PRIMARY KEY,
				ptype varchar(100),
				v0 varchar(100),
				v1 varchar(100),
				v2 varchar(100),
				v3 varchar(100),
				v4 varchar(100),
				v5 varchar(100)
			)
		`, schema)

		if err := gormDB.Exec(createTableSQL).Error; err != nil {
			return nil, fmt.Errorf("failed to create casbin_rule table: %w", err)
		}

		log.Debug("casbin_rule table ensured in schema", slog.String("schema", schema))
	}

	// Create the GORM adapter
	// NewAdapterByDB will detect the existing table and use it
	adapter, err := gormadapter.NewAdapterByDB(gormDB)
	if err != nil {
		return nil, fmt.Errorf("failed to create GORM casbin adapter: %w", err)
	}

	log.Info("SQL-backed Casbin adapter created successfully")
	return adapter, nil
}

// SeedPoliciesIfEmpty seeds the SQL policy store with default policies if empty.
// This is called on first v2 initialization to populate the database with
// the embedded default policy and any configured extensions.
//
// Seeding only occurs when:
// 1. The SQL store has no existing policies (p rules)
// 2. The SQL store has no existing grouping policies (g rules)
//
// After seeding, the SQL store becomes the source of truth for policies.
//
// Parameters:
//   - enforcer: The Casbin enforcer with SQL adapter
//   - csvPolicy: The CSV policy content to seed from (builtin + extensions)
//   - log: Logger for operation logging
//
// Returns an error if seeding fails.
func SeedPoliciesIfEmpty(enforcer *casbin.Enforcer, csvPolicy string, log *logger.Logger) error {
	// Check if the store already has policies
	existingPolicies, _ := enforcer.GetPolicy()
	existingGroupings, _ := enforcer.GetGroupingPolicy()

	if len(existingPolicies) > 0 || len(existingGroupings) > 0 {
		log.Info("SQL policy store already has policies, skipping seed",
			slog.Int("policies", len(existingPolicies)),
			slog.Int("groupings", len(existingGroupings)),
		)
		return nil
	}

	log.Info("seeding SQL policy store with default policies")

	// Parse the CSV policy and add each rule
	policies, groupings := parsePolicyCSV(csvPolicy)

	// Add policies
	for _, policy := range policies {
		if len(policy) == 0 {
			continue
		}
		// AddPolicy expects variadic string args
		_, err := enforcer.AddPolicy(stringsToInterfaces(policy)...)
		if err != nil {
			log.Warn("failed to add policy during seed",
				slog.Any("policy", policy),
				slog.String("error", err.Error()),
			)
			// Continue seeding other policies
		}
	}

	// Add grouping policies
	for _, grouping := range groupings {
		if len(grouping) == 0 {
			continue
		}
		_, err := enforcer.AddGroupingPolicy(stringsToInterfaces(grouping)...)
		if err != nil {
			log.Warn("failed to add grouping policy during seed",
				slog.Any("grouping", grouping),
				slog.String("error", err.Error()),
			)
			// Continue seeding other groupings
		}
	}

	// Save all policies to the adapter
	if err := enforcer.SavePolicy(); err != nil {
		return fmt.Errorf("failed to save seeded policies: %w", err)
	}

	log.Info("SQL policy store seeded successfully",
		slog.Int("policies", len(policies)),
		slog.Int("groupings", len(groupings)),
	)

	return nil
}

// parsePolicyCSV parses a CSV policy string into policies and grouping policies.
// Returns separate slices for p (policies) and g (groupings) rules.
func parsePolicyCSV(csv string) (policies [][]string, groupings [][]string) {
	lines := strings.Split(csv, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		// Trim whitespace from each part
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		ruleType := parts[0]
		ruleContent := parts[1:]

		switch ruleType {
		case "p":
			policies = append(policies, ruleContent)
		case "g":
			groupings = append(groupings, ruleContent)
		}
	}
	return policies, groupings
}

// stringsToInterfaces converts a string slice to an interface slice.
// Required because casbin's AddPolicy expects ...interface{}.
func stringsToInterfaces(strs []string) []interface{} {
	result := make([]interface{}, len(strs))
	for i, s := range strs {
		result[i] = s
	}
	return result
}

// CreateCSVAdapter creates a string adapter from CSV content.
// This is a convenience wrapper for creating the fallback CSV adapter.
func CreateCSVAdapter(csvPolicy string) persist.Adapter {
	return stringadapter.NewAdapter(csvPolicy)
}

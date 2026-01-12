package casbin

import (
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/opentdf/platform/service/logger"
	"gorm.io/gorm"
)

// CasbinRule represents a policy rule in the database.
// This matches the structure used by the official gorm-adapter.
type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"size:100;index:idx_casbin_rule"`
	V0    string `gorm:"size:100;index:idx_casbin_rule"`
	V1    string `gorm:"size:100;index:idx_casbin_rule"`
	V2    string `gorm:"size:100;index:idx_casbin_rule"`
	V3    string `gorm:"size:100;index:idx_casbin_rule"`
	V4    string `gorm:"size:100;index:idx_casbin_rule"`
	V5    string `gorm:"size:100;index:idx_casbin_rule"`
}

// TableName returns the table name for CasbinRule.
func (CasbinRule) TableName() string {
	return "casbin_rule"
}

// sqlAdapter is a custom SQL adapter for Casbin v2 using GORM.
type sqlAdapter struct {
	db     *gorm.DB
	logger *logger.Logger
}

// createSQLAdapter creates a Casbin SQL adapter using GORM.
// It automatically migrates the casbin_rule table in the configured schema.
func createSQLAdapter(gormDB *gorm.DB, schema string, log *logger.Logger) (persist.Adapter, error) {
	if gormDB == nil {
		return nil, fmt.Errorf("gormDB is required for SQL adapter")
	}

	// Set schema search path if provided
	if schema != "" {
		if err := gormDB.Exec(fmt.Sprintf("SET search_path TO %s", schema)).Error; err != nil {
			return nil, fmt.Errorf("failed to set search_path to %s: %w", schema, err)
		}
		log.Debug("set schema search_path", "schema", schema)
	}

	// Auto-migrate the casbin_rule table
	if err := gormDB.AutoMigrate(&CasbinRule{}); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate casbin_rule table: %w", err)
	}

	log.Info("SQL adapter created successfully",
		"schema", schema,
		"table", "casbin_rule",
	)

	return &sqlAdapter{
		db:     gormDB,
		logger: log,
	}, nil
}

// LoadPolicy loads all policy rules from the database.
func (a *sqlAdapter) LoadPolicy(model model.Model) error {
	var rules []CasbinRule
	if err := a.db.Find(&rules).Error; err != nil {
		return err
	}

	for _, rule := range rules {
		a.loadPolicyLine(rule, model)
	}

	return nil
}

// SavePolicy saves all policy rules to the database.
func (a *sqlAdapter) SavePolicy(model model.Model) error {
	// Start a transaction
	return a.db.Transaction(func(tx *gorm.DB) error {
		// Delete all existing rules
		if err := tx.Where("1 = 1").Delete(&CasbinRule{}).Error; err != nil {
			return err
		}

		// Insert new rules
		for ptype, ast := range model["p"] {
			for _, rule := range ast.Policy {
				if err := a.savePolicyLine(tx, ptype, rule); err != nil {
					return err
				}
			}
		}

		for ptype, ast := range model["g"] {
			for _, rule := range ast.Policy {
				if err := a.savePolicyLine(tx, ptype, rule); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

// AddPolicy adds a policy rule to the database.
func (a *sqlAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.savePolicyLine(a.db, ptype, rule)
}

// RemovePolicy removes a policy rule from the database.
func (a *sqlAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	query := a.db.Where("ptype = ?", ptype)
	for i, v := range rule {
		query = query.Where(fmt.Sprintf("v%d = ?", i), v)
	}
	return query.Delete(&CasbinRule{}).Error
}

// RemoveFilteredPolicy removes policy rules that match the filter from the database.
func (a *sqlAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := a.db.Where("ptype = ?", ptype)

	for i, v := range fieldValues {
		if v == "" {
			continue
		}
		query = query.Where(fmt.Sprintf("v%d = ?", fieldIndex+i), v)
	}

	return query.Delete(&CasbinRule{}).Error
}

// loadPolicyLine loads a single policy line into the model.
func (a *sqlAdapter) loadPolicyLine(rule CasbinRule, model model.Model) {
	var p []string

	if rule.V0 != "" {
		p = append(p, rule.V0)
	}
	if rule.V1 != "" {
		p = append(p, rule.V1)
	}
	if rule.V2 != "" {
		p = append(p, rule.V2)
	}
	if rule.V3 != "" {
		p = append(p, rule.V3)
	}
	if rule.V4 != "" {
		p = append(p, rule.V4)
	}
	if rule.V5 != "" {
		p = append(p, rule.V5)
	}

	// Determine section (p or g)
	sec := "p"
	if rule.Ptype[0] == 'g' {
		sec = "g"
	}

	// Add the rule to the model
	if ast, ok := model[sec][rule.Ptype]; ok {
		ast.Policy = append(ast.Policy, p)
	}
}

// savePolicyLine saves a single policy line to the database.
func (a *sqlAdapter) savePolicyLine(tx *gorm.DB, ptype string, rule []string) error {
	line := CasbinRule{Ptype: ptype}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return tx.Create(&line).Error
}

// seedPoliciesIfEmpty checks if the SQL policy store is empty and seeds it
// with the embedded default policy if needed.
func seedPoliciesIfEmpty(adapter persist.Adapter, csvPolicy string, log *logger.Logger) error {
	sqlAdapter, ok := adapter.(*sqlAdapter)
	if !ok {
		return errors.New("adapter is not a SQL adapter")
	}

	// Check if casbin_rule has any policies
	var count int64
	if err := sqlAdapter.db.Model(&CasbinRule{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check if policy store is empty: %w", err)
	}

	if count > 0 {
		log.Info("SQL policy store already has policies, skipping seed",
			"policyCount", count,
		)
		return nil
	}

	log.Info("SQL policy store is empty, seeding from embedded policy")

	// Parse CSV policy and insert into database
	if err := seedFromCSV(sqlAdapter, csvPolicy); err != nil {
		return fmt.Errorf("failed to seed policies: %w", err)
	}

	log.Info("successfully seeded SQL policy store")
	return nil
}

// seedFromCSV parses a CSV policy and saves it to the SQL adapter
func seedFromCSV(adapter *sqlAdapter, csvPolicy string) error {
	lines := splitNonEmpty(csvPolicy, '\n')

	var rules []CasbinRule

	for _, line := range lines {
		// Skip comments and empty lines
		trimmed := trimSpace(line)
		if trimmed == "" || startsWithHash(trimmed) {
			continue
		}

		// Parse the line
		parts := splitNonEmpty(line, ',')
		if len(parts) == 0 {
			continue
		}

		// Trim spaces from each part
		for i := range parts {
			parts[i] = trimSpace(parts[i])
		}

		ptype := parts[0]

		// Create CasbinRule based on type
		rule := CasbinRule{
			Ptype: ptype,
		}

		// Assign V0-V5 based on the number of parts
		if len(parts) > 1 {
			rule.V0 = parts[1]
		}
		if len(parts) > 2 {
			rule.V1 = parts[2]
		}
		if len(parts) > 3 {
			rule.V2 = parts[3]
		}
		if len(parts) > 4 {
			rule.V3 = parts[4]
		}
		if len(parts) > 5 {
			rule.V4 = parts[5]
		}
		if len(parts) > 6 {
			rule.V5 = parts[6]
		}

		rules = append(rules, rule)
	}

	// Bulk insert all rules
	if len(rules) > 0 {
		if err := adapter.db.Create(&rules).Error; err != nil {
			return fmt.Errorf("failed to insert policy rules: %w", err)
		}
	}

	return nil
}

// Helper functions for string parsing without importing strings package unnecessarily
func splitNonEmpty(s string, sep byte) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			if i > start {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)

	// Trim leading whitespace
	for start < end && isSpace(s[start]) {
		start++
	}

	// Trim trailing whitespace
	for end > start && isSpace(s[end-1]) {
		end--
	}

	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func startsWithHash(s string) bool {
	return len(s) > 0 && s[0] == '#'
}

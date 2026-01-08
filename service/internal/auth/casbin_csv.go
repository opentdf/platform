package auth

import (
	"fmt"
	"strings"
)

// csvPolicyBuilder handles building CSV policy strings from configuration.
// This is separated to make it easier to support other adapters (e.g., SQL) in the future.
type csvPolicyBuilder struct {
	basePolicy string
	lines      []string
}

// newCSVPolicyBuilder creates a new CSV policy builder with the base policy.
func newCSVPolicyBuilder(basePolicy string) *csvPolicyBuilder {
	return &csvPolicyBuilder{
		basePolicy: basePolicy,
		lines:      []string{basePolicy},
	}
}

// addRoleMapping adds a group-to-role mapping line (g, user, role).
func (b *csvPolicyBuilder) addRoleMapping(user, role string) {
	b.lines = append(b.lines, fmt.Sprintf("g, %s, role:%s", user, role))
}

// addExtension appends extension policy lines.
func (b *csvPolicyBuilder) addExtension(extension string) {
	if extension != "" {
		b.lines = append(b.lines, extension)
	}
}

// build returns the complete CSV policy string.
func (b *csvPolicyBuilder) build() string {
	return strings.Join(b.lines, "\n")
}

// validateCSVPolicy validates a CSV policy string for correct format.
// This validation is specific to CSV/string adapters and should be skipped for other adapters (e.g., SQL).
func validateCSVPolicy(csv string) error {
	policyLines := strings.Split(csv, "\n")
	for i, line := range policyLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip empty/comment lines
		}
		fields := strings.Split(line, ",")
		for j := range fields {
			fields[j] = strings.TrimSpace(fields[j])
		}
		switch fields[0] {
		case "p":
			// Policy line: expect at least 5 fields: p, sub, obj, act, eft
			const expectedFields = 5
			if len(fields) < expectedFields {
				return fmt.Errorf("malformed casbin policy line %d: %q (expected at least 5 fields)", i+1, line)
			}

			sub, obj, act, eft := fields[1], fields[2], fields[3], fields[4]
			if sub == "" || obj == "" || act == "" {
				return fmt.Errorf("malformed casbin policy line %d: %q (resource and action fields must not be empty)", i+1, line)
			}
			if eft != "allow" && eft != "deny" {
				return fmt.Errorf("malformed casbin policy line %d: %q (effect must be 'allow' or 'deny')", i+1, line)
			}
		case "g":
			const expectedFields = 3
			// Grouping line: expect at least 3 fields: g, user, role
			if len(fields) < expectedFields {
				return fmt.Errorf("malformed casbin grouping line %d: %q (expected at least 3 fields)", i+1, line)
			}
		default:
			// Unknown line type, fail-safe: error
			return fmt.Errorf("malformed casbin policy line %d: %q (unknown line type, must start with 'p' or 'g')", i+1, line)
		}
	}
	return nil
}

// buildCSVPolicy constructs the CSV policy string from configuration.
// Returns the policy string, whether it's the default policy, and whether it was extended.
func buildCSVPolicy(c CasbinConfig) (policy string, isDefault bool, isExtended bool) {
	// Determine base policy
	basePolicy := c.Csv
	isDefault = false
	if basePolicy == "" {
		if c.Builtin != "" {
			basePolicy = c.Builtin
		} else {
			basePolicy = builtinPolicy
		}
		isDefault = true
	}

	builder := newCSVPolicyBuilder(basePolicy)

	// Add role mappings from RoleMap
	for role, user := range c.RoleMap {
		builder.addRoleMapping(user, role)
	}

	// Add extension policy
	if c.Extension != "" {
		builder.addExtension(c.Extension)
		isExtended = true
	}

	// Add default group mappings if no RoleMap or Extension provided
	if c.RoleMap == nil && c.Extension == "" {
		builder.addRoleMapping("opentdf-admin", "admin")
		builder.addRoleMapping("opentdf-standard", "standard")
	}

	return builder.build(), isDefault, isExtended
}

// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package db

import (
	"database/sql/driver"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

type AttributeDefinitionRule string

const (
	AttributeDefinitionRuleUNSPECIFIED AttributeDefinitionRule = "UNSPECIFIED"
	AttributeDefinitionRuleALLOF       AttributeDefinitionRule = "ALL_OF"
	AttributeDefinitionRuleANYOF       AttributeDefinitionRule = "ANY_OF"
	AttributeDefinitionRuleHIERARCHY   AttributeDefinitionRule = "HIERARCHY"
)

func (e *AttributeDefinitionRule) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = AttributeDefinitionRule(s)
	case string:
		*e = AttributeDefinitionRule(s)
	default:
		return fmt.Errorf("unsupported scan type for AttributeDefinitionRule: %T", src)
	}
	return nil
}

type NullAttributeDefinitionRule struct {
	AttributeDefinitionRule AttributeDefinitionRule `json:"attribute_definition_rule"`
	Valid                   bool                    `json:"valid"` // Valid is true if AttributeDefinitionRule is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullAttributeDefinitionRule) Scan(value interface{}) error {
	if value == nil {
		ns.AttributeDefinitionRule, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.AttributeDefinitionRule.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullAttributeDefinitionRule) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.AttributeDefinitionRule), nil
}

// Table to store the definitions of attributes
type AttributeDefinition struct {
	// Primary key for the table
	ID string `json:"id"`
	// Foreign key to the parent namespace of the attribute definition
	NamespaceID string `json:"namespace_id"`
	// Name of the attribute (i.e. organization or classification), unique within the namespace
	Name string `json:"name"`
	// Rule for the attribute (see protos for options)
	Rule AttributeDefinitionRule `json:"rule"`
	// Metadata for the attribute definition (see protos for structure)
	Metadata []byte `json:"metadata"`
	// Active/Inactive state
	Active    bool               `json:"active"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
	// Order of value ids for the attribute (important for hierarchy rule)
	ValuesOrder []string `json:"values_order"`
}

// Table to store the grants of key access servers (KASs) to attribute definitions
type AttributeDefinitionKeyAccessGrant struct {
	// Foreign key to the attribute definition
	AttributeDefinitionID string `json:"attribute_definition_id"`
	// Foreign key to the KAS registration
	KeyAccessServerID string `json:"key_access_server_id"`
}

// Table to store the fully qualified names of attributes for reverse lookup at their object IDs
type AttributeFqn struct {
	// Primary key for the table
	ID string `json:"id"`
	// Foreign key to the namespace of the attribute
	NamespaceID pgtype.UUID `json:"namespace_id"`
	// Foreign key to the attribute definition
	AttributeID pgtype.UUID `json:"attribute_id"`
	// Foreign key to the attribute value
	ValueID pgtype.UUID `json:"value_id"`
	// Fully qualified name of the attribute (i.e. https://<namespace>/attr/<attribute name>/value/<value>)
	Fqn string `json:"fqn"`
}

// Table to store the parent namespaces of platform policy attributes and related policy objects
type AttributeNamespace struct {
	// Primary key for the table
	ID string `json:"id"`
	// Name of the namespace (i.e. example.com)
	Name string `json:"name"`
	// Active/Inactive state
	Active bool `json:"active"`
	// Metadata for the namespace (see protos for structure)
	Metadata  []byte             `json:"metadata"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

// Table to store the grants of key access servers (KASs) to attribute namespaces
type AttributeNamespaceKeyAccessGrant struct {
	// Foreign key to the namespace of the KAS grant
	NamespaceID string `json:"namespace_id"`
	// Foreign key to the KAS registration
	KeyAccessServerID string `json:"key_access_server_id"`
}

// Table to store the values of attributes
type AttributeValue struct {
	// Primary key for the table
	ID string `json:"id"`
	// Foreign key to the parent attribute definition
	AttributeDefinitionID string `json:"attribute_definition_id"`
	// Value of the attribute (i.e. "manager" or "admin" on an attribute for titles), unique within the definition
	Value string `json:"value"`
	// Metadata for the attribute value (see protos for structure)
	Metadata []byte `json:"metadata"`
	// Active/Inactive state
	Active    bool               `json:"active"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

// Table to store the grants of key access servers (KASs) to attribute values
type AttributeValueKeyAccessGrant struct {
	// Foreign key to the attribute value
	AttributeValueID string `json:"attribute_value_id"`
	// Foreign key to the KAS registration
	KeyAccessServerID string `json:"key_access_server_id"`
}

// Table to store the known registrations of key access servers (KASs)
type KeyAccessServer struct {
	// Primary key for the table
	ID string `json:"id"`
	// URI of the KAS
	Uri string `json:"uri"`
	// Public key of the KAS (see protos for structure/options)
	PublicKey []byte `json:"public_key"`
	// Metadata for the KAS (see protos for structure)
	Metadata  []byte             `json:"metadata"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

// Table to store associated terms that should map resource data to attribute values
type ResourceMapping struct {
	// Primary key for the table
	ID string `json:"id"`
	// Foreign key to the attribute value
	AttributeValueID string `json:"attribute_value_id"`
	// Terms to match against resource data (i.e. translations "roi", "rey", or "kung" in a terms list could map to the value "/attr/card/value/king")
	Terms []string `json:"terms"`
	// Metadata for the resource mapping (see protos for structure)
	Metadata  []byte             `json:"metadata"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
	// Foreign key to the parent group of the resource mapping (optional, a resource mapping may not be in a group)
	GroupID pgtype.UUID `json:"group_id"`
}

// Table to store the groups of resource mappings by unique namespace and group name combinations
type ResourceMappingGroup struct {
	// Primary key for the table
	ID string `json:"id"`
	// Foreign key to the namespace of the attribute
	NamespaceID string `json:"namespace_id"`
	// Name for the group of resource mappings
	Name      string             `json:"name"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
	Metadata  []byte             `json:"metadata"`
}

// Table to store sets of conditions that logically entitle subject entity representations to attribute values via a subject mapping
type SubjectConditionSet struct {
	// Primary key for the table
	ID string `json:"id"`
	// Conditions that must be met for the subject entity to be entitled to the attribute value (see protos for JSON structure)
	Condition []byte `json:"condition"`
	// Metadata for the condition set (see protos for structure)
	Metadata  []byte             `json:"metadata"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

// Table to store conditions that logically entitle subject entity representations to attribute values
type SubjectMapping struct {
	// Primary key for the table
	ID string `json:"id"`
	// Foreign key to the attribute value
	AttributeValueID string `json:"attribute_value_id"`
	// Metadata for the subject mapping (see protos for structure)
	Metadata  []byte             `json:"metadata"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
	// Foreign key to the condition set that entitles the subject entity to the attribute value
	SubjectConditionSetID pgtype.UUID `json:"subject_condition_set_id"`
	// Actions that the subject entity can perform on the attribute value (see protos for details)
	Actions []byte `json:"actions"`
}

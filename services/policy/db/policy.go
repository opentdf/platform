package db

import (
	"github.com/opentdf/opentdf-v2-poc/internal/db"
)

var (
	ResourceMappingTable string
	NamespacesTable      string
	AttributeValueTable  string
	AttributeTable       string
)

const (
	StateInactive    = "INACTIVE"
	StateActive      = "ACTIVE"
	StateAny         = "ANY"
	StateUnspecified = "UNSPECIFIED"
)

type PolicyDbClient struct {
	db.Client
}

func WithPolicyDbClient(c db.Client) *PolicyDbClient {
	ResourceMappingTable = db.Tables.ResourceMappings.Name()
	NamespacesTable = db.Tables.Namespaces.Name()
	AttributeValueTable = db.Tables.AttributeValues.Name()
	AttributeTable = db.Tables.Attributes.Name()

	return &PolicyDbClient{c}
}

package access

import (
	"errors"

	"github.com/google/uuid"
	attrs "github.com/virtru/access-pdp/attributes"
)

const (
	ErrPolicyDataAttributeParse = Error("policy data attribute invalid")
)

type Policy struct {
	UUID uuid.UUID  `json:"uuid"`
	Body PolicyBody `json:"body"`
}

type PolicyBody struct {
	DataAttributes []Attribute `json:"dataAttributes"`
	Dissem         []string    `json:"dissem"`
}

func getNamespacesFromAttributes(body PolicyBody) ([]string, error) {
	// extract the namespace from an attribute uri
	var dataAttributes = body.DataAttributes
	namespaces := make(map[string]bool)
	for _, attr := range dataAttributes {
		instance, err := attrs.ParseInstanceFromURI(attr.URI)
		if err != nil {
			return nil, errors.Join(ErrPolicyDataAttributeParse, err)
		}
		namespaces[instance.Authority] = true
	}

	// get unique
	keys := make([]string, len(namespaces))
	index := 0
	for key := range namespaces {
		keys[index] = key
		index++
	}

	return keys, nil
}

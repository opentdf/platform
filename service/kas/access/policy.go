package access

import (
	"github.com/google/uuid"
)

type Policy struct {
	UUID uuid.UUID  `json:"uuid"`
	Body PolicyBody `json:"body"`
}

type PolicyBody struct {
	DataAttributes []Attribute `json:"dataAttributes"`
	Dissem         []string    `json:"dissem"`
}

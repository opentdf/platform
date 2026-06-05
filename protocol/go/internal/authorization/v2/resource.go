package authorizationv2

import (
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
)

// ForAttributeValues returns a Resource containing the given attribute value FQNs.
// This is the most common Resource variant, used when authorizing against
// attribute values attached to data (e.g. those on a TDF).
// At least one FQN is required; calling with zero arguments panics.
func ForAttributeValues(fqns ...string) *authorizationv2.Resource {
	if len(fqns) == 0 {
		panic("ForAttributeValues requires at least one FQN")
	}
	return &authorizationv2.Resource{
		Resource: &authorizationv2.Resource_AttributeValues_{
			AttributeValues: &authorizationv2.Resource_AttributeValues{
				Fqns: fqns,
			},
		},
	}
}

// ForRegisteredResourceValueFqn returns a Resource that references a single
// registered resource value by its fully qualified name, as stored in platform policy.
func ForRegisteredResourceValueFqn(fqn string) *authorizationv2.Resource {
	return &authorizationv2.Resource{
		Resource: &authorizationv2.Resource_RegisteredResourceValueFqn{
			RegisteredResourceValueFqn: fqn,
		},
	}
}

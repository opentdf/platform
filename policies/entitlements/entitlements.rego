package opentdf.entitlements

import rego.v1

entitlements[entity_id] := attrs if {
	some mapping in data.mappings
	entity_id := input.entity.email_address
	attrs := [attr |
		some claim in input.entity.claims
		acse_evaluate(claim, mapping.operator, mapping.subject_values)
		attr := mapping.descriptor.fqn
	]
}

# Function to evaluate subject mapping based on operator
acse_evaluate(value, operator, list) if {
	operator == 1
	value in list
} else if {
	operator == 2
	not value in list
}

package opentdf.entitlements

import rego.v1

entitlements[entity_id] := attrs if {
	some condition_group in input.subjectset.condition_groups
	entity_id := input.entity.email_address
	attrs := [attr |
		some claim in input.entity.claims
		some condition in condition_group.conditions
		evaluate_condition(claim, condition.operator, condition.subject_values)
		attr := condition.subject_attribute
	]
}

# Function to evaluate subject condition based on operator
evaluate_condition(value, operator, list) if {
	operator == 1
	value in list
} else if {
	operator == 2
	not value in list
}

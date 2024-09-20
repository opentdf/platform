package opentdf.conditions

import rego.v1

# condition_group
condition_group_evaluate(payload, boolean_operator, conditions) if {
	# AND
	boolean_operator == 1
	some condition in conditions
	condition_evaluate(payload[condition.subject_external_field], condition.operator, condition.subject_external_values)
} else if {
	# OR
	boolean_operator == 2
	payload[key]
	some condition in conditions
	condition_evaluate(payload[condition.subject_external_field], condition.operator, condition.subject_external_values)
}

# condition
condition_evaluate(property_values, operator, values) if {
	# IN
	operator == 1
	some property_value in property_values
	property_value in values
} else if {
	# NOT IN
	operator == 2
	some property_value in property_values
	not property_value in values
}


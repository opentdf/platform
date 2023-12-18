package opentdf.entitlement

import future.keywords.if

generated_entitlements := attrs if {

  attrs := [attr |
    mapping := input.mappings[_]
    attr := process_mapping(mapping)
  ]
}

process_mapping(mapping) = attr if {
  user_value := input.entity_attrs[mapping.subject_attribute]
  user_value != null # Ensure user_value exists
  acse_evaluate(user_value, mapping.operator, mapping.subject_values)
  attr := mapping.descriptor.fqn
}

# Function to evaluate subject mapping based on operator
acse_evaluate(value, operator, list) if {
  operator == 1
  is_in(value,list)
} else if {
  operator == 2
  not is_in(value, list)
}

# Helper function to determine if a value is in the list
is_in(value, list) if {
  value == list[_]
}
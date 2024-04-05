package opentdf.entitlements_test

import data.opentdf.entitlements
import rego.v1

default condition_result := false

condition_result if {
    print(input)
	payload := input.payload
	print(payload)
	condition := input.condition
	print(condition)
	result = entitlements.condition_evaluate(payload[condition.subject_external_field], condition.operator, condition.subject_external_values)
}

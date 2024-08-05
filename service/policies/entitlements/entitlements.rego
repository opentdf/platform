package opentdf.entitlements

import rego.v1


attributes := subjectmapping.resolve(input.attribute_mappings, input.ers_response)

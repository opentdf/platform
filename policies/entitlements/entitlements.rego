package opentdf.entitlements

import rego.v1

idp_config = {"config": {
	"url": input.idp.url,
	"realm": input.idp.realm,
	"clientid": input.idp.client,
	"clientsecret": input.idp.secret,
	"legacykeycloak": input.idp.legacy,
}}
idp_request = {"entities": [{
	"id": input.entity.id,
	"emailAddress": input.entity.email_address,
}]}


attributes := [attribute |
	# external entity
	response := keycloak.resolve.entities(idp_request, idp_config)
	entity_representations := response.entityRepresentations
	some entity_representation in entity_representations
	some prop in entity_representation.additionalProps

	# mapppings
 	some subject_mapping in input.attribute_mappings[attribute].value.subject_mappings
    some subject_set in subject_mapping.subject_condition_set.subject_sets
	some condition_group in subject_set.condition_groups
    cgbool_evaluate(prop.attributes, condition_group.boolean_operator, condition_group.conditions)
]

# condition_group
cgbool_evaluate(external_property, boolean_operator, conditions) if {
	# AND
	boolean_operator == 1
	external_property[key]
	some condition in conditions
	condition.subject_external_field == key
	external_property[key] in condition.subject_external_values
} else if {
	# OR
	boolean_operator == 2
	external_property[key]
	some condition in conditions
	condition.subject_external_field == key
	cbool_evaluate(external_property[key], condition.operator, condition.subject_external_values)
}

# condition
cbool_evaluate(properties, operator, values) if {
	# AND
	operator == 1
	some property in properties
	some value in values
	property == value
} else if {
	# OR
	operator == 2
	some property in properties
	some value in values
	property == value
}

# get IdP entity
resolve_entities := keycloak.resolve.entities(idp_request, idp_config)

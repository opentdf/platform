package opentdf.entitlements

import rego.v1

config = {
"config":{
            "url": "http://localhost:8888",
            "realm": "tdf",
            "clientid":"tdf-entity-resolution-service",
            "clientsecret": "5Byk7Hh6l0E1hJDZfF8CQbG9vqh2FeIe",
            "legacykeycloak": true
        }
}
req = {
  "entities": [
              {
                "id": "e1",
                "emailAddress": "a@a.af"
              }
            ]
}


attributes := [attribute |
 	some subject_mapping in input.attribute_mappings[attribute].value.subject_mappings
    some subject_set in subject_mapping.subject_condition_set.subject_sets
	some condition_group in subject_set.condition_groups
	condition_group.boolean_operator == 1 # AND
	# get IdP entity
	res := keycloak.resolve.entities(req, config)
	# TODO check conditions against subject_external
]

# get IdP entity
entities := [entity |
    response := keycloak.resolve.entities(req, config)
    entity_reps := response.entityRepresentations
    some entity_rep in entity_reps
    some prop in entity_rep.additionalProps
    # attribute map TODO handle
    entity = prop.attributes
]

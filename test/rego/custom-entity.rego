package opentdf.entitlements

import rego.v1

entity := {
    "entityRepresentations": [
      {
        "additionalProps":[
          {
            "org": {
              "name": "marketing",
            },
            "team": {
              "name": "CoolTool"
            },
            "data": [
              {
                "favorite_things":["futbol"]
              }
            ],
            "attributes": {
              "superhero_name": ["thor"],
              "superhero_group": ["avengers"]
            }
          }
        ],
        "originalId": "custom-rego"
      }
    ]
		
	}

get_entitlements(entity) := res if {
    res := subjectmapping.resolve(input.attribute_mappings, entity)
}

attributes := get_entitlements(entity)

package opentdf.entitlements

import rego.v1

ers_request := {"entities": [input.entity]}

response := http.send({
		"method" : "POST",
		"url": input.ers_url,
		"body": ers_request,
		"headers": {
			"Authorization":  concat(" ", ["Bearer", input.auth_token])
		},
		"raise_error": false,
	})

handle_response(response) := res if {
    response.status_code == 0
    res := sprintf("error connecting to entity resolution: %v", [response])
}
handle_response(response) := res if {
    response.status_code == 200
    res := subjectmapping.resolve(input.attribute_mappings, response.body)
}
handle_response(response) := res if {
	response.status_code > 200
    res := sprintf("error from entity resolution: %v", [response])
}
handle_response(response) := res if {
	response.status_code != 0
	response.status_code != 200
	response.status_code < 200
    res := sprintf("unexpected code from entity resolution: %v", [response])
}

attributes := handle_response(response)

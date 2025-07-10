-------------------------
-- For Testing Only!!!!!!!!!
-------------------------
-- name: AssignKeyAccessServerToAttribute :execrows
INSERT INTO attribute_definition_key_access_grants (attribute_definition_id, key_access_server_id)
VALUES ($1, $2);

-- name: AssignKeyAccessServerToNamespace :execrows
INSERT INTO attribute_namespace_key_access_grants (namespace_id, key_access_server_id)
VALUES ($1, $2);

-- name: AssignKeyAccessServerToAttributeValue :execrows
INSERT INTO attribute_value_key_access_grants (attribute_value_id, key_access_server_id)
VALUES ($1, $2);
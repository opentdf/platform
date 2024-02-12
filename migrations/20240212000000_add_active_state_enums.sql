-- +goose Up
-- +goose StatementBegin

CREATE TYPE active_state AS ENUM ('ACTIVE', 'INACTIVE', 'UNSPECIFIED');

ALTER TABLE attribute_namespaces ADD COLUMN state active_state NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE attribute_definitions ADD COLUMN state active_state NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE attribute_values ADD COLUMN state active_state NOT NULL DEFAULT 'ACTIVE';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- If rolling back, all soft deletes should become hard deletes.
DELETE FROM attribute_namespaces WHERE state = 'INACTIVE';
DELETE FROM attribute_definitions WHERE state = 'INACTIVE';
DELETE FROM attribute_values WHERE state = 'INACTIVE';

-- There should be no UNSPECIFIED states, but only preserve active rows just in case.
DELETE FROM attribute_namespaces WHERE state = 'UNSPECIFIED';
DELETE FROM attribute_definitions WHERE state = 'UNSPECIFIED';
DELETE FROM attribute_values WHERE state = 'UNSPECIFIED';

ALTER TABLE attribute_namespaces DROP COLUMN state;
ALTER TABLE attribute_definitions DROP COLUMN state;
ALTER TABLE attribute_values DROP COLUMN state;

DROP TYPE active_state;

-- +goose StatementEnd
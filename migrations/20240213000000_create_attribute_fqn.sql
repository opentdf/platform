-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS attribute_fqns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id UUID REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
  attribute_id UUID REFERENCES attribute_definitions(id) ON DELETE CASCADE,
  value_id UUID REFERENCES attribute_values(id) ON DELETE CASCADE,
  fqn TEXT NOT NULL,
  UNIQUE NULLS NOT DISTINCT (namespace_id, attribute_id, value_id),
  UNIQUE (fqn)
);

-- +goose StatementEnd

-- +goose Down

DROP TABLE attribute_fqn;

-- +goose StatementBegin
-- +goose StatementEnd

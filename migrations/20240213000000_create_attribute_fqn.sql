-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS attribute_fqn (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id UUID REFERENCES attribute_namespaces(id),
  attribute_id UUID REFERENCES attribute_definitions(id),
  value_id UUID REFERENCES attribute_values(id),
  fqn TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down

DROP TABLE attribute_fqn;

-- +goose StatementBegin
-- +goose StatementEnd

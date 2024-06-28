-- +goose Up
-- +goose StatementBegin

-- For enhanced performance we are adding an index on the fqn column
CREATE INDEX idx_attribute_fqns_fqn ON attribute_fqns (fqn);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_attribute_fqns_fqn;

-- +goose StatementEnd
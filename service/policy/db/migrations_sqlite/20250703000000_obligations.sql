-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS obligation_definitions (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (namespace_id, name)
);

CREATE TABLE IF NOT EXISTS obligation_values_standard (
    id TEXT PRIMARY KEY,
    obligation_definition_id TEXT NOT NULL REFERENCES obligation_definitions(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (obligation_definition_id, value)
);

CREATE TABLE IF NOT EXISTS obligation_triggers (
    id TEXT PRIMARY KEY,
    obligation_value_id TEXT NOT NULL REFERENCES obligation_values_standard(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    attribute_value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    client_id TEXT DEFAULT NULL,
    UNIQUE(obligation_value_id, action_id, attribute_value_id)
);

CREATE TABLE IF NOT EXISTS obligation_fulfillers (
    id TEXT PRIMARY KEY,
    obligation_value_id TEXT NOT NULL REFERENCES obligation_values_standard(id) ON DELETE CASCADE,
    conditionals TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Updated_at triggers
CREATE TRIGGER IF NOT EXISTS obligation_definitions_updated_at
AFTER UPDATE ON obligation_definitions
BEGIN
    UPDATE obligation_definitions SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS obligation_values_standard_updated_at
AFTER UPDATE ON obligation_values_standard
BEGIN
    UPDATE obligation_values_standard SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS obligation_triggers_updated_at
AFTER UPDATE ON obligation_triggers
BEGIN
    UPDATE obligation_triggers SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS obligation_fulfillers_updated_at
AFTER UPDATE ON obligation_fulfillers
BEGIN
    UPDATE obligation_fulfillers SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    WHERE id = NEW.id;
END;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS obligation_fulfillers;
DROP TABLE IF EXISTS obligation_triggers;
DROP TABLE IF EXISTS obligation_values_standard;
DROP TABLE IF EXISTS obligation_definitions;

-- +goose StatementEnd

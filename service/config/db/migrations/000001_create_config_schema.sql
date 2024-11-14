-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS config (
  service VARCHAR NOT NULL,
  version VARCHAR NOT NULL,
  aliases VARCHAR[],
  value JSONB NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (service, version)
);

CREATE OR REPLACE FUNCTION update_updated_at() 
RETURNS TRIGGER 
LANGUAGE plpgsql
AS
$$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER config_updated_at
  BEFORE UPDATE ON config
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd
-- +goose Down

DROP TRIGGER IF EXISTS config_updated_at ON config;

DROP FUNCTION IF EXISTS update_updated_at();

DROP TABLE IF EXISTS config;


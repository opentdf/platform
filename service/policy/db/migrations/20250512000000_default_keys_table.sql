-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS default_kas_keys (
  id UUID DEFAULT gen_random_uuid() CONSTRAINT default_key_pkey PRIMARY KEY,
  key_access_server_key_id UUID CONSTRAINT key_access_server_key_id_fkey REFERENCES key_access_server_keys(id) ON DELETE RESTRICT,
  tdf_type VARCHAR(255) NOT NULL,  
  CONSTRAINT unique_tdf_type UNIQUE (tdf_type) -- Ensure only one row per tdf_type
);

-- Trigger Function
CREATE OR REPLACE FUNCTION upsert_default_kas_keys()
RETURNS TRIGGER AS $$
BEGIN
  -- Check if a row exists with the same tdf_type and key_access_server_id
  IF EXISTS (
    SELECT 1
    FROM default_kas_keys
    WHERE tdf_type = NEW.tdf_type
  ) THEN
    -- Update the existing row
    UPDATE default_kas_keys
    SET key_access_server_key_id = NEW.key_access_server_key_id
    WHERE tdf_type = NEW.tdf_type;

    RETURN NULL;  -- Important: Returning NULL prevents the original INSERT from proceeding, as the upsert has already happened

  ELSE
    -- Insert a new row (the original INSERT will proceed)
    RETURN NEW;  -- Important: Returning NEW allows the original INSERT to proceed
  END IF;
END;
$$ LANGUAGE 'plpgsql';

-- Trigger
CREATE TRIGGER before_insert_or_update_default_kas_keys
BEFORE INSERT ON default_kas_keys
FOR EACH ROW
EXECUTE FUNCTION upsert_default_kas_keys();
-- +goose StatementEnd



-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS before_insert_or_update_default_kas_keys ON default_kas_keys;
DROP FUNCTION IF EXISTS upsert_default_kas_keys;

DROP TABLE IF EXISTS default_kas_keys;
-- +goose StatementEnd
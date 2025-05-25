-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS base_keys (
  id UUID DEFAULT gen_random_uuid() CONSTRAINT base_key_pkey PRIMARY KEY,
  key_access_server_key_id UUID CONSTRAINT key_access_server_key_id_fkey REFERENCES key_access_server_keys(id) ON DELETE RESTRICT
);

-- Trigger Function
CREATE OR REPLACE FUNCTION upsert_base_keys()
RETURNS TRIGGER AS $$
BEGIN
  -- Check if a row exists with the same tdf_type and key_access_server_id
  IF (
      SELECT count(*)
      FROM base_keys
    ) > 0 THEN
      -- Update the existing row
    UPDATE base_keys
    SET key_access_server_key_id = NEW.key_access_server_key_id;

    RETURN NULL;  -- Important: Returning NULL prevents the original INSERT from proceeding, as the upsert has already happened

  ELSE
    -- Insert a new row (the original INSERT will proceed)
    RETURN NEW;  -- Important: Returning NEW allows the original INSERT to proceed
  END IF;
END;
$$ LANGUAGE 'plpgsql';

-- Trigger
CREATE TRIGGER before_insert_or_update_base_keys
BEFORE INSERT ON base_keys
FOR EACH ROW
EXECUTE FUNCTION upsert_base_keys();
-- +goose StatementEnd



-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS before_insert_or_update_base_keys ON base_keys;
DROP FUNCTION IF EXISTS upsert_base_keys;

DROP TABLE IF EXISTS base_keys;
-- +goose StatementEnd
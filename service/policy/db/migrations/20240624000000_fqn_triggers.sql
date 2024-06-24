-- +goose Up
-- +goose StatementBegin

-- Handle FQN updates
CREATE OR REPLACE FUNCTION generate_fqn(namespace_id UUID, attribute_id UUID, value_id UUID)
RETURNS TEXT AS $$
DECLARE
  ns_name TEXT;
  attr_name TEXT;
  val_name TEXT;
BEGIN
  -- Select names based on provided IDs
  IF namespace_id IS NOT NULL THEN
    SELECT LOWER(n.name) INTO ns_name FROM attribute_namespaces n WHERE n.id = namespace_id;
  END IF;

  IF attribute_id IS NOT NULL THEN
    SELECT LOWER(a.name) INTO attr_name FROM attribute_definitions a WHERE a.id = attribute_id;
  END IF;

  IF value_id IS NOT NULL THEN
    SELECT LOWER(v.value) INTO val_name FROM attribute_values v WHERE v.id = value_id;
  END IF;

  -- Construct FQN based on defined columns
  IF namespace_id IS NOT NULL AND attribute_id IS NULL AND value_id IS NULL THEN
    RETURN CONCAT('https://', ns_name);
  ELSIF namespace_id IS NOT NULL AND attribute_id IS NOT NULL AND value_id IS NULL THEN
    RETURN CONCAT('https://', ns_name, '/attr/', attr_name);
  ELSIF namespace_id IS NOT NULL AND attribute_id IS NOT NULL AND value_id IS NOT NULL THEN
    RETURN CONCAT('https://', ns_name, '/attr/', attr_name, '/value/', val_name);
  ELSE
    RAISE EXCEPTION 'Invalid FQN construction scenario';
  END IF;
END;
$$ LANGUAGE plpgsql;

-- CREATE OR REPLACE FUNCTION update_fqn_trigger_function()
-- RETURNS TRIGGER AS $$
-- BEGIN
--   NEW.fqn := generate_fqn(NEW.namespace_id, NEW.attribute_id, NEW.value_id);
--   RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;

-- -- Trigger function to update FQN on insert or update of attribute_fqns
-- CREATE OR REPLACE FUNCTION update_fqn_trigger_function()
-- RETURNS TRIGGER AS $$
-- BEGIN
--   NEW.fqn := generate_fqn(NEW.namespace_id, NEW.attribute_id, NEW.value_id);
--   RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;

-- -- Trigger on attribute_fqns
-- CREATE TRIGGER update_fqn_trigger
-- BEFORE INSERT OR UPDATE ON attribute_fqns
-- FOR EACH ROW
-- EXECUTE FUNCTION update_fqn_trigger_function();

-- -- Trigger function for updating FQN from attribute_namespaces
-- CREATE OR REPLACE FUNCTION update_fqn_from_namespace()
-- RETURNS TRIGGER AS $$
-- BEGIN
--   UPDATE attribute_fqns
--   SET fqn = generate_fqn(namespace_id, attribute_id, value_id)
--   WHERE namespace_id = NEW.id;
--   RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;

-- CREATE TRIGGER namespace_name_update_insert_trigger
-- AFTER INSERT OR UPDATE OF name ON attribute_namespaces
-- FOR EACH ROW
-- EXECUTE FUNCTION update_fqn_from_namespace();

-- -- Trigger function for updating FQN from attribute_definitions
-- CREATE OR REPLACE FUNCTION update_fqn_from_attribute()
-- RETURNS TRIGGER AS $$
-- BEGIN
--   UPDATE attribute_fqns
--   SET fqn = generate_fqn(namespace_id, attribute_id, value_id)
--   WHERE attribute_id = NEW.id;
--   RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;

-- CREATE TRIGGER attribute_name_update_insert_trigger
-- AFTER INSERT OR UPDATE OF name ON attribute_definitions
-- FOR EACH ROW
-- EXECUTE FUNCTION update_fqn_from_attribute();

-- -- Trigger function for updating FQN from attribute_values
-- CREATE OR REPLACE FUNCTION update_fqn_from_value()
-- RETURNS TRIGGER AS $$
-- BEGIN
--   UPDATE attribute_fqns
--   SET fqn = generate_fqn(namespace_id, attribute_id, value_id)
--   WHERE value_id = NEW.id;
--   RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;

-- CREATE TRIGGER value_name_update_insert_trigger
-- AFTER INSERT OR UPDATE OF value ON attribute_values
-- FOR EACH ROW
-- EXECUTE FUNCTION update_fqn_from_value();


-- Function to update FQN for all related rows based on namespace_id
CREATE OR REPLACE FUNCTION update_fqns_from_namespace()
RETURNS TRIGGER AS $$
DECLARE
  schema_name TEXT := TG_TABLE_SCHEMA;
BEGIN
  EXECUTE format('
    UPDATE %I.attribute_fqns
    SET fqn = generate_fqn(namespace_id, attribute_id, value_id)
    WHERE namespace_id = $1', schema_name)
  USING NEW.id;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Function to update FQN for all related rows based on attribute_id
CREATE OR REPLACE FUNCTION update_fqns_from_attribute()
RETURNS TRIGGER AS $$
DECLARE
  schema_name TEXT := TG_TABLE_SCHEMA;
BEGIN
  EXECUTE format('
    UPDATE %I.attribute_fqns
    SET fqn = generate_fqn(namespace_id, attribute_id, value_id)
    WHERE attribute_id = $1', schema_name)
  USING NEW.id;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Function to update FQN for all related rows based on value_id
CREATE OR REPLACE FUNCTION update_fqns_from_value()
RETURNS TRIGGER AS $$
DECLARE
  schema_name TEXT := TG_TABLE_SCHEMA;
BEGIN
  EXECUTE format('
    UPDATE %I.attribute_fqns
    SET fqn = generate_fqn(namespace_id, attribute_id, value_id)
    WHERE value_id = $1', schema_name)
  USING NEW.id;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger for attribute_namespaces
CREATE TRIGGER namespace_name_update_insert_trigger
AFTER INSERT OR UPDATE OF name ON attribute_namespaces
FOR EACH ROW
EXECUTE FUNCTION update_fqns_from_namespace();

-- Trigger for attribute_definitions
CREATE TRIGGER attribute_name_update_insert_trigger
AFTER INSERT OR UPDATE OF name ON attribute_definitions
FOR EACH ROW
EXECUTE FUNCTION update_fqns_from_attribute();

-- Trigger for attribute_values
CREATE TRIGGER value_name_update_insert_trigger
AFTER INSERT OR UPDATE OF value ON attribute_values
FOR EACH ROW
EXECUTE FUNCTION update_fqns_from_value();

-- +goose StatementEnd

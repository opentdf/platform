-- +goose Up
-- +goose StatementBegin

-- 1. Create new 'actions' table
CREATE TABLE IF NOT EXISTS
    actions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR NOT NULL,
        is_standard BOOLEAN NOT NULL DEFAULT FALSE,
        metadata JSONB,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
        CONSTRAINT actions_name_unique UNIQUE (name) 
    );

COMMENT ON TABLE actions IS 'Table to store actions for use in ABAC decisioning';

COMMENT ON COLUMN actions.id IS 'Unique identifier for the action';

COMMENT ON COLUMN actions.name IS 'Unique name of the action, e.g. read, write, etc.';

COMMENT ON COLUMN actions.is_standard IS 'Whether the action is standard (proto-enum) or custom (user-defined).';

COMMENT ON COLUMN actions.metadata IS 'Metadata for the action (see protos for structure)';

CREATE TRIGGER actions_updated_at
  BEFORE UPDATE ON actions
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- 2. Insert standard CRUD actions from protos
INSERT INTO actions (name, is_standard) VALUES
    ('create', TRUE),
    ('read', TRUE),
    ('update', TRUE),
    ('delete', TRUE);

-- 3. Persist subject mapping relations from marshaled proto actions to actions table rows.

-- 3a. Validate custom actions align with new proto requirements as they were very loose previously.
-- 3a. Validate custom actions
DO $$
DECLARE
    invalid_action text;
    invalid_count int;
BEGIN
    WITH custom_actions AS (
        SELECT DISTINCT elem->>'custom' AS custom_action_name
        FROM subject_mappings sm
        CROSS JOIN LATERAL jsonb_array_elements(sm.actions) AS elem
        WHERE elem->>'custom' IS NOT NULL
    ),
    invalid_actions AS (
        SELECT custom_action_name
        FROM custom_actions
        WHERE 
          LENGTH(custom_action_name) > 253 OR
          LENGTH(custom_action_name) < 1 OR
          custom_action_name !~ '^[a-zA-Z0-9]' OR
          custom_action_name !~ '[a-zA-Z0-9]$' OR
          custom_action_name ~ '[^a-zA-Z0-9_-]'
    )
    SELECT COUNT(*) INTO invalid_count FROM invalid_actions;
    
    IF invalid_count > 0 THEN
        SELECT custom_action_name INTO invalid_action FROM invalid_actions LIMIT 1;
        RAISE EXCEPTION 'Invalid custom action name found: % (and % others). Names must be 1-253 characters, start and end with alphanumeric, and contain only alphanumeric, underscore, or hyphen.', 
                        invalid_action, invalid_count - 1;
    END IF;
END $$;

-- 3b. Extract unique custom actions from subject_mappings.actions and insert into actions table.
WITH custom_actions AS (
    SELECT DISTINCT elem->>'custom' AS custom_action_name
    FROM subject_mappings sm
    CROSS JOIN LATERAL jsonb_array_elements(sm.actions) AS elem
    WHERE elem->>'custom' IS NOT NULL
)
INSERT INTO actions (name, is_standard)
SELECT LOWER(custom_action_name), FALSE
FROM custom_actions
WHERE LOWER(custom_action_name) NOT IN (SELECT name FROM actions)
ON CONFLICT (name) DO NOTHING;

-- Add temporary column to hold actions row ids that match the old actions column marshaled proto values.
ALTER TABLE subject_mappings ADD COLUMN actions_uuid UUID[];

-- 3c. Map the old actions column to the new actions_uuid column.
-- | old actions column JSON array element    | new row with actions.name column value |
-- | ---------------------------------------- | -------------------------------------- |
-- | {"standard": "STANDARD_ACTION_TRANSMIT"} | create                                 |
-- | {"standard": "STANDARD_ACTION_DECRYPT"}  | read                                   |
-- | {"custom": "custom_action_name"}         | custom_action_name                     |
UPDATE subject_mappings
SET actions_uuid = (
    SELECT array_agg(a.id)
    FROM (
        SELECT 
            CASE 
                WHEN elem->>'standard' = 'STANDARD_ACTION_TRANSMIT' THEN 'create'
                WHEN elem->>'standard' = 'STANDARD_ACTION_DECRYPT' THEN 'read'
                WHEN elem->>'custom' IS NOT NULL THEN elem->>'custom'
                ELSE NULL
            END AS action_name
        FROM jsonb_array_elements(subject_mappings.actions) AS elem
        WHERE elem->>'standard' IS NOT NULL OR elem->>'custom' IS NOT NULL
    ) s
    JOIN actions a ON s.action_name = a.name
);

-- Verify data was properly converted from marshaled protos to actions table row ids.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM subject_mappings WHERE actions_uuid IS NULL) THEN
        RAISE EXCEPTION 'Migration failed: Some rows have NULL actions_uuid';
    END IF;
END $$;

-- 3c. Drop the old JSONB column and rename the new UUID[] column to the old name.
ALTER TABLE subject_mappings DROP COLUMN actions;
ALTER TABLE subject_mappings RENAME COLUMN actions_uuid TO actions;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- 1. Add a temporary JSONB column to hold the original format
ALTER TABLE subject_mappings ADD COLUMN actions_jsonb JSONB;

-- 2. Convert the UUID[] action references back to the original JSONB format
UPDATE subject_mappings sm
SET actions_jsonb = (
    SELECT jsonb_agg(
        CASE
            WHEN a.name = 'create' THEN jsonb_build_object('standard', 'STANDARD_ACTION_TRANSMIT')
            WHEN a.name = 'read' THEN jsonb_build_object('standard', 'STANDARD_ACTION_DECRYPT')
            -- Note: update / delete standard action enums in updated proto cannot be backported
            ELSE jsonb_build_object('custom', a.name)
        END
    )
    FROM unnest(sm.actions) AS action_id
    JOIN actions a ON a.id = action_id
);

-- 3. Verify the conversion worked
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM subject_mappings WHERE actions_jsonb IS NULL AND actions IS NOT NULL) THEN
        RAISE EXCEPTION 'Down migration failed: Some rows have NULL actions_jsonb';
    END IF;
END $$;

-- 4. Drop the UUID[] column and rename the JSONB column back to actions
ALTER TABLE subject_mappings DROP COLUMN actions;
ALTER TABLE subject_mappings RENAME COLUMN actions_jsonb TO actions;

-- 5. Drop the actions table
DROP TABLE actions;

-- +goose StatementEnd
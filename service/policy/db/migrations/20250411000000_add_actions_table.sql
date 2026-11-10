-- +goose Up
-- +goose StatementBegin

-- 1. Create new 'actions' table
CREATE TABLE IF NOT EXISTS
    actions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR NOT NULL,
        is_standard BOOLEAN NOT NULL DEFAULT FALSE,
        metadata JSONB,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
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

-- 1a. Create intermediary table to hold the mapping of actions to subject_mappings (potentially many to many)
CREATE TABLE IF NOT EXISTS subject_mapping_actions (
    subject_mapping_id UUID NOT NULL REFERENCES subject_mappings(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (subject_mapping_id, action_id)
);

CREATE INDEX IF NOT EXISTS idx_subject_mapping_actions_subject ON subject_mapping_actions(subject_mapping_id);
CREATE INDEX IF NOT EXISTS idx_subject_mapping_actions_action ON subject_mapping_actions(action_id);

-- 2. Insert standard CRUD actions from protos
INSERT INTO actions (name, is_standard) VALUES
    ('create', TRUE),
    ('read', TRUE),
    ('update', TRUE),
    ('delete', TRUE);

-- 3. Persist subject mapping relations from marshaled proto actions to actions table rows.

-- 3a. Validate custom actions align with new proto requirements as they were very loose previously.
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


-- 3c. Map the old actions column to the new relation table.
-- | old actions column JSON array element    | actions.name of the new relation       |
-- | ---------------------------------------- | -------------------------------------- |
-- | {"standard": "STANDARD_ACTION_TRANSMIT"} | create                                 |
-- | {"standard": "STANDARD_ACTION_DECRYPT"}  | read                                   |
-- | {"custom": "custom_action_name"}         | custom_action_name                     |
INSERT INTO subject_mapping_actions (subject_mapping_id, action_id)
SELECT 
    sm.id, 
    a.id
FROM 
    subject_mappings sm,
    LATERAL jsonb_array_elements(sm.actions) AS elem,
    LATERAL (
        SELECT a.id 
        FROM actions a
        WHERE a.name = CASE 
            WHEN elem->>'standard' = 'STANDARD_ACTION_TRANSMIT' THEN 'create'
            WHEN elem->>'standard' = 'STANDARD_ACTION_DECRYPT' THEN 'read'
            WHEN elem->>'custom' IS NOT NULL THEN LOWER(elem->>'custom')
            ELSE NULL
        END
    ) a;

-- 3d. Verify data was properly converted from marshaled protos to actions table row ids.
DO $$
DECLARE
    expected_count BIGINT;
    actual_count BIGINT;
BEGIN
    SELECT COUNT(*) INTO expected_count
    FROM 
        subject_mappings sm,
        LATERAL jsonb_array_elements(sm.actions) AS elem
    WHERE 
        elem->>'standard' IS NOT NULL OR elem->>'custom' IS NOT NULL;
        
    SELECT COUNT(*) INTO actual_count 
    FROM subject_mapping_actions;
    
    IF expected_count != actual_count THEN
        RAISE EXCEPTION 'Migration verification failed: Expected % relationships, found %', 
                        expected_count, actual_count;
    END IF;
END $$;

-- 3e. Drop the old JSONB column
ALTER TABLE subject_mappings DROP COLUMN actions;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- 1. Add a temporary JSONB column to subject_mappings
ALTER TABLE subject_mappings ADD COLUMN actions JSONB DEFAULT '[]'::JSONB;

-- 2. Convert the intermediary table relationships back to JSONB format
UPDATE subject_mappings sm
SET actions = (
    SELECT jsonb_agg(
        CASE
            WHEN a.name = 'create' THEN jsonb_build_object('standard', 'STANDARD_ACTION_TRANSMIT')
            WHEN a.name = 'read' THEN jsonb_build_object('standard', 'STANDARD_ACTION_DECRYPT')
            WHEN a.is_standard = TRUE THEN jsonb_build_object('standard', a.name)
            ELSE jsonb_build_object('custom', a.name)
        END
    )
    FROM subject_mapping_actions sma
    JOIN actions a ON a.id = sma.action_id
    WHERE sma.subject_mapping_id = sm.id
);

-- 3. Set empty arrays to NULL to match original schema behavior (if needed)
UPDATE subject_mappings
SET actions = NULL
WHERE actions = '[]'::JSONB;

-- 4. Verify the migration worked correctly
DO $$
DECLARE
    expected_count BIGINT;
    actual_count BIGINT;
    subject_mappings_with_actions BIGINT;
    subject_mappings_with_relations BIGINT;
BEGIN
    -- Count total elements that should be in the JSONB arrays
    SELECT COUNT(*) INTO expected_count
    FROM subject_mapping_actions;
    
    -- Count total elements that are in the JSONB arrays
    SELECT SUM(jsonb_array_length(actions)) INTO actual_count
    FROM subject_mappings
    WHERE actions IS NOT NULL;
    
    -- Count subject_mappings that have actions
    SELECT COUNT(*) INTO subject_mappings_with_actions
    FROM subject_mappings
    WHERE actions IS NOT NULL;
    
    -- Count subject_mappings that had relationships
    SELECT COUNT(DISTINCT subject_mapping_id) INTO subject_mappings_with_relations
    FROM subject_mapping_actions;
    
    IF expected_count != actual_count THEN
        RAISE EXCEPTION 'Migration verification failed: Expected % elements in JSONB arrays, found %', 
                        expected_count, actual_count;
    END IF;
    
    IF subject_mappings_with_actions != subject_mappings_with_relations THEN
        RAISE EXCEPTION 'Migration verification failed: Expected % subject_mappings with actions, found %', 
                        subject_mappings_with_relations, subject_mappings_with_actions;
    END IF;
END $$;

-- 5. Drop the intermediary table
DROP TABLE subject_mapping_actions;

-- 6. Drop the actions table
DROP TABLE actions;

-- +goose StatementEnd
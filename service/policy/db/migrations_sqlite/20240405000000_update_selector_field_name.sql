-- +goose Up
-- +goose StatementBegin

-- This migration renames 'subject_external_field' to 'subject_external_selector_value'
-- in the JSON condition column of subject_condition_set.
--
-- PostgreSQL uses jsonb_set with nested aggregations.
-- SQLite's json functions are more limited, so we handle this with
-- a simpler approach using json_replace for the field rename.
--
-- Note: SQLite's JSON functions work on TEXT columns.
-- The condition column stores JSON as TEXT.

-- Create a temporary table with the updated structure
CREATE TEMPORARY TABLE temp_scs_update AS
SELECT
    id,
    REPLACE(condition, '"subject_external_field"', '"subject_external_selector_value"') as condition
FROM subject_condition_set
WHERE condition IS NOT NULL;

-- Update the original table
UPDATE subject_condition_set
SET condition = (
    SELECT temp_scs_update.condition
    FROM temp_scs_update
    WHERE temp_scs_update.id = subject_condition_set.id
)
WHERE id IN (SELECT id FROM temp_scs_update);

DROP TABLE temp_scs_update;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Reverse the rename: 'subject_external_selector_value' back to 'subject_external_field'
CREATE TEMPORARY TABLE temp_scs_downgrade AS
SELECT
    id,
    REPLACE(condition, '"subject_external_selector_value"', '"subject_external_field"') as condition
FROM subject_condition_set
WHERE condition IS NOT NULL;

UPDATE subject_condition_set
SET condition = (
    SELECT temp_scs_downgrade.condition
    FROM temp_scs_downgrade
    WHERE temp_scs_downgrade.id = subject_condition_set.id
)
WHERE id IN (SELECT id FROM temp_scs_downgrade);

DROP TABLE temp_scs_downgrade;

-- +goose StatementEnd

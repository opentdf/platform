-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS subject_condition_set (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR UNIQUE,
    metadata JSONB,
    condition JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS subject_mapping_condition_set_pivot (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_mapping_id UUID REFERENCES subject_mappings(id) ON DELETE CASCADE,
    subject_condition_set_id UUID,
    UNIQUE (subject_mapping_id, subject_condition_set_id)
);

ALTER TABLE IF EXISTS subject_mappings ADD COLUMN subject_condition_set_pivot_ids UUID[], ADD COLUMN actions VARCHAR[];

WITH subject_mappings_migration_data AS (
   SELECT
        JSON_BUILD_OBJECT(
            'created_at', metadata::json->'created_at',
            'updated_at', metadata::json->'updated_at'
        ) AS metadata,
        JSON_BUILD_OBJECT(
        'subject_sets',
            JSON_BUILD_ARRAY(
                JSON_BUILD_OBJECT(
                    'condition_groups', JSON_BUILD_ARRAY(
                        JSON_BUILD_OBJECT(
                            'boolean_operator', 'AND',
                            'conditions', JSON_BUILD_ARRAY(
                                JSON_BUILD_OBJECT(
                                    'operator', operator,
                                    'subject_external_field', subject_attribute,
                                    'subject_external_values', subject_attribute_values
                                )
                            )
                        )
                    )
                )
            )
        ) AS condition_json,
        id AS sm_id
    FROM subject_mappings
),
-- populate the pivot table
pivot_insert AS (
    INSERT INTO subject_mapping_condition_set_pivot(subject_mapping_id, subject_condition_set_id)
    SELECT subject_mappings_migration_data.sm_id, gen_random_uuid()
    FROM subject_mappings_migration_data
    RETURNING id AS pivot_id, subject_mapping_id, subject_condition_set_id
),
-- populate the condition set table
insert_subject_condition_set AS (
    INSERT INTO subject_condition_set(metadata, condition, id)
    SELECT metadata, condition_json, subject_condition_set_id
    FROM subject_mappings_migration_data JOIN pivot_insert ON subject_mappings_migration_data.sm_id = pivot_insert.subject_mapping_id
)
-- populate the subject_mappings column with the new pivot id
UPDATE subject_mappings
SET subject_condition_set_pivot_ids = (
    SELECT ARRAY_AGG(pivot_insert.pivot_id)
    FROM pivot_insert
    WHERE subject_mappings.id = pivot_insert.subject_mapping_id
);

ALTER TABLE subject_mapping_condition_set_pivot ADD FOREIGN KEY (subject_condition_set_id) REFERENCES subject_condition_set(id) ON DELETE CASCADE;

/* Example of the built 'condition' JSON that maps to the protos:
{
    "subject_sets": [
        {
            "condition_groups": [
                {
                    "conditions": [
                        {
                            "operator": "IN",
                            "subject_external_field": "subject_attribute1",
                            "subject_external_values": [
                                "value1",
                                "value2"
                            ]
                        }
                    ],
                    "boolean_operator": "AND"
                }
            ]
        }
    ]
}
*/


ALTER TABLE IF EXISTS subject_mappings DROP COLUMN operator, DROP COLUMN subject_attribute, DROP COLUMN subject_attribute_values;
DROP TYPE IF EXISTS subject_mappings_operator;

-- +goose StatementEnd

-- +goose Down

ALTER TABLE IF EXISTS subject_mappings ADD COLUMN operator VARCHAR, ADD COLUMN subject_attribute VARCHAR, ADD COLUMN subject_attribute_values VARCHAR[];
--- populate the old columns with the new data
WITH subject_mappings_migration_data AS (
   SELECT
        (condition->'subject_sets'->0->'condition_groups'->0->'conditions'->0->'operator')::TEXT AS operator,
        (condition->'subject_sets'->0->'condition_groups'->0->'conditions'->0->'subject_external_field')::TEXT AS subject_attribute,
        (condition->'subject_sets'->0->'condition_groups'->0->'conditions'->0->'subject_external_values')::TEXT AS subject_attribute_values,
        id AS set_id
    FROM subject_condition_set
)
UPDATE subject_mappings
SET operator = subject_mappings_migration_data.operator,
    subject_attribute = subject_mappings_migration_data.subject_attribute,
    subject_attribute_values = ARRAY(
        SELECT subject_mappings_migration_data.subject_attribute_values
    )
FROM subject_mappings_migration_data
JOIN subject_mapping_condition_set_pivot ON subject_mappings_migration_data.set_id = subject_mapping_condition_set_pivot.subject_condition_set_id
WHERE subject_mapping_condition_set_pivot.subject_mapping_id = subject_mappings.id;

ALTER TABLE IF EXISTS subject_mappings DROP COLUMN subject_condition_set_pivot_ids, DROP COLUMN actions;

DROP TABLE subject_mapping_condition_set_pivot;
DROP TABLE subject_condition_set;
CREATE TYPE subject_mappings_operator AS ENUM ('UNSPECIFIED', 'IN', 'NOT_IN');

-- +goose StatementBegin
-- +goose StatementEnd
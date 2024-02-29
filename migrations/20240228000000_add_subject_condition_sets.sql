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
    subject_condition_set_id UUID REFERENCES subject_condition_set(id) ON DELETE CASCADE
);

INSERT INTO subject_condition_set(metadata, condition) VALUES (
    SELECT JSON_AGG(JSON_BUILD_OBJECT(
        'created_at', subject_mappings.created_at,
        'updated_at', subject_mappings.updated_at,
    )),
    SELECT JSON_AGG(JSON_BUILD_OBJECT(
        'subject_sets', JSON_BUILD_ARRAY(
            JSON_BUILD_OBJECT(
                'condition_groups', JSON_BUILD_ARRAY(
                    JSON_BUILD_OBJECT(
                        'boolean_operator', 'AND',
                        JSON_BUILD_ARRAY(
                            JSON_BUILD_OBJECT(
                                'operator', subject_mappings.operator,
                                'subject_attribute', subject_mappings.subject_attribute,
                                'subject_attribute_values', subject_mappings.subject_attribute_values
                            )
                        )
                    )
                )
            )
        ),
    ))
)

ALTER TABLE IF EXISTS subject_mappings DROP COLUMN operator, DROP COLUMN subject_attribute, DROP COLUMN subject_attribute_values;
ALTER TABLE IF EXISTS subject_mappings ADD COLUMN subject_condition_set_pivot_ids UUID[], ADD COLUMN actions VARCHAR[];
DROP TYPE IF EXISTS subject_mappings_operator;

-- +goose StatementEnd

-- +goose Down

DROP TABLE subject_condition_set;
DROP TABLE subject_mapping_condition_set_pivot;
CREATE TYPE subject_mappings_operator AS ENUM ('UNSPECIFIED', 'IN', 'NOT_IN');



-- +goose StatementBegin
-- +goose StatementEnd
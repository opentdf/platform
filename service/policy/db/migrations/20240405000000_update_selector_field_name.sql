-- +goose Up
-- +goose StatementBegin
UPDATE subject_condition_set
SET condition = jsonb_set(
    condition,
    '{0,condition_groups}',
    (
        SELECT jsonb_agg(
                   jsonb_build_object(
                       'boolean_operator', cg->>'boolean_operator',
                       'conditions',
                       (
                           SELECT jsonb_agg(
                               jsonb_build_object(
                                   'operator', con->>'operator',
                                   'subject_external_selector_value', con->>'subject_external_field',
                                   'subject_external_values', con->'subject_external_values'
                               )
                           )
                           FROM jsonb_array_elements(cg->'conditions') AS con
                       )
                   )
               )
        FROM jsonb_array_elements(condition->0->'condition_groups') AS cg
    )
)
WHERE condition IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE subject_condition_set
SET condition = jsonb_set(
    condition,
    '{0,condition_groups}',
    (
        SELECT jsonb_agg(
                   jsonb_build_object(
                       'boolean_operator', cg->>'boolean_operator',
                       'conditions',
                       (
                           SELECT jsonb_agg(
                               jsonb_build_object(
                                   'operator', con->>'operator',
                                   'subject_external_field', con->>'subject_external_selector_value',
                                   'subject_external_values', con->'subject_external_values'
                               )
                           )
                           FROM jsonb_array_elements(cg->'conditions') AS con
                       )
                   )
               )
        FROM jsonb_array_elements(condition->0->'condition_groups') AS cg
    )
)
WHERE condition IS NOT NULL;

-- +goose StatementEnd
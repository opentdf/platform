-- +goose Up
-- +goose StatementBegin

CREATE OR REPLACE FUNCTION check_subject_selectors(condition jsonb, selectors text[]) RETURNS boolean AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM JSONB_ARRAY_ELEMENTS(condition) AS ss, 
             JSONB_ARRAY_ELEMENTS(ss->'conditionGroups') AS cg, 
             JSONB_ARRAY_ELEMENTS(cg->'conditions') AS each_condition
        WHERE (each_condition->>'subjectExternalSelectorValue' = ANY(selectors)) 
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP FUNCTION IF EXISTS check_subject_selectors(jsonb, text[]);

-- +goose StatementEnd
-- +goose Up
-- +goose StatementBegin
-- Add manager column to provider_config table
ALTER TABLE provider_config
ADD COLUMN manager VARCHAR(255);

-- Update existing records to have a default manager value for backward compatibility
UPDATE provider_config
SET
    manager = 'opentdf.io/unspecified'
WHERE
    manager IS NULL;

-- Make manager column NOT NULL now that all existing records have been updated
ALTER TABLE provider_config
ALTER COLUMN manager
SET NOT NULL;

-- Drop the existing unique constraint on provider_name
ALTER TABLE provider_config
DROP CONSTRAINT IF EXISTS provider_config_provider_name_key;

-- Add new composite unique constraint on provider_name + manager
ALTER TABLE provider_config
ADD CONSTRAINT provider_config_provider_name_manager_key UNIQUE (provider_name, manager);

-- Update column comments
COMMENT ON COLUMN provider_config.provider_name IS 'Name of the key provider instance.';

COMMENT ON COLUMN provider_config.manager IS 'Type of key manager (e.g., opentdf.io/basic, aws, azure, gcp)';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
-- Drop the composite unique constraint
ALTER TABLE provider_config
DROP CONSTRAINT IF EXISTS provider_config_provider_name_manager_key;

-- Before re-adding unique constraint on provider_name, clean up duplicates
-- Keep only the oldest record (earliest created_at) for each provider_name
DELETE FROM provider_config
WHERE
    id NOT IN (
        SELECT DISTINCT
            ON (provider_name) id
        FROM
            provider_config
        ORDER BY
            provider_name,
            created_at ASC
    );

-- Re-add the original unique constraint on provider_name only
ALTER TABLE provider_config
ADD CONSTRAINT provider_config_provider_name_key UNIQUE (provider_name);

-- Drop the manager column
ALTER TABLE provider_config
DROP COLUMN IF EXISTS manager;

-- Restore original comment
COMMENT ON COLUMN provider_config.provider_name IS 'Unique name for the key provider.';

-- +goose StatementEnd
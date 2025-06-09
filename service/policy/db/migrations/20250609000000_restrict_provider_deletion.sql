-- +goose Up
-- +goose StatementBegin

-- Do not delete provider configurations when they are referenced by asym_key
 ALTER TABLE key_access_server_keys
 DROP CONSTRAINT IF EXISTS key_access_server_keys_provider_config_fk;
 
 ALTER TABLE key_access_server_keys
 ADD CONSTRAINT key_access_server_keys_provider_config_fk 
 FOREIGN KEY (provider_config_id) 
 REFERENCES provider_config (id) 
 ON DELETE RESTRICT;



-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Revert changes for asym_key
 ALTER TABLE key_access_server_keys
 DROP CONSTRAINT IF EXISTS key_access_server_keys_provider_config_fk;
 
 ALTER TABLE key_access_server_keys
 ADD CONSTRAINT key_access_server_keys_provider_config_fk 
 FOREIGN KEY (provider_config_id) 
 REFERENCES provider_config (id);

-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- Do not delete keys when a key access server is deleted
ALTER TABLE key_access_server_keys
DROP CONSTRAINT key_access_server_fk;

ALTER TABLE key_access_server_keys
ADD CONSTRAINT key_access_server_fk 
FOREIGN KEY (key_access_server_id) 
REFERENCES key_access_servers (id) 
ON DELETE RESTRICT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Drop the foreign key constraint
ALTER TABLE key_access_server_keys
DROP CONSTRAINT key_access_server_fk;

ALTER TABLE key_access_server_keys
ADD CONSTRAINT key_access_server_fk 
FOREIGN KEY (key_access_server_id) 
REFERENCES key_access_servers (id) 
ON DELETE CASCADE;

-- +goose StatementEnd
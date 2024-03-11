-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS value_members
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    value_id UUID NOT NULL REFERENCES attribute_values(id),
    member_id UUID NOT NULL REFERENCES attribute_values(id),
    UNIQUE (value_id, member_id)
);

-- trigger to update attribute_values.members when value_member is added
CREATE OR REPLACE FUNCTION update_attribute_values_members()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        UPDATE attribute_values
        SET members = array_append(members, NEW.id)
        WHERE id = NEW.value_id;
        -- AND NEW.id <> ALL(members);
    END IF;
    RETURN NULL;
END
$$ language 'plpgsql';

CREATE TRIGGER value_members_insert
    AFTER
        INSERT
    ON value_members
    FOR EACH ROW
    EXECUTE PROCEDURE update_attribute_values_members();


-- trigger to update attribute_values.members when value_member is deleted
CREATE OR REPLACE FUNCTION delete_attribute_values_members()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        UPDATE attribute_values
        SET members = array_remove(members, OLD.id)
        WHERE id = OLD.value_id;
    END IF;
    RETURN NULL;
END
$$ language 'plpgsql';

CREATE TRIGGER value_members_delete
    AFTER
        DELETE
    ON value_members
    FOR EACH ROW
    EXECUTE PROCEDURE delete_attribute_values_members();


-- trigger to update attribute_values.members when attribute_value is deleted
CREATE OR REPLACE FUNCTION delete_attribute_values_members_on_attribute_value_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        UPDATE attribute_values
        SET members = array_remove(members, value_members.id)
        FROM value_members
        WHERE value_members.member_id = OLD.id;
    END IF;
    RETURN NULL;
END
$$ language 'plpgsql';

CREATE TRIGGER attribute_values_delete
    AFTER
        DELETE
    ON attribute_values
    FOR EACH ROW
    EXECUTE PROCEDURE delete_attribute_values_members_on_attribute_value_delete();

-- trigger to update value_members when attribute_value is deleted
CREATE OR REPLACE FUNCTION delete_value_members_on_attribute_value_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        DELETE FROM value_members
        WHERE value_members.value_id = OLD.id OR value_members.member_id = OLD.id;
    END IF;
    RETURN NULL;
END
$$ language 'plpgsql';

CREATE TRIGGER attribute_values_delete_value_members
    AFTER
        DELETE
    ON attribute_values
    FOR EACH ROW
    EXECUTE PROCEDURE delete_value_members_on_attribute_value_delete();

-- trigger to update value_members when attribute_value is updated
CREATE OR REPLACE FUNCTION update_value_members_on_attribute_value_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'UPDATE') THEN
        UPDATE value_members
        SET value_id = NEW.id
        WHERE value_id = OLD.id;
    END IF;
    RETURN NULL;
END
$$ language 'plpgsql';

CREATE TRIGGER attribute_values_update_value_members
    AFTER
        UPDATE
    ON attribute_values
    FOR EACH ROW
    EXECUTE PROCEDURE update_value_members_on_attribute_value_update();

-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
DROP TABLE IF EXISTS value_members;
-- +goose StatementEnd

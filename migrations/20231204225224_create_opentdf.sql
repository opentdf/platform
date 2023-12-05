CREATE SCHEMA IF NOT EXISTS opentdf;

CREATE TABLE IF NOT EXISTS opentdf.attribute
(
    id SERIAL PRIMARY KEY,
    -- state        VARCHAR NOT NULL,
    rule VARCHAR NOT NULL,
    name VARCHAR NOT NULL, -- ??? COLLATE NOCASE
    -- description  VARCHAR,
    values_array TEXT [],
    group_by_attr INTEGER REFERENCES opentdf.attribute (id),
    group_by_attrval VARCHAR,
    CONSTRAINT no_attrval_without_attrid
    CHECK (group_by_attrval IS NOT null OR group_by_attr IS null)
);

CREATE SCHEMA IF NOT EXISTS opentdf;

CREATE TABLE IF NOT EXISTS opentdf.resources
(
    id SERIAL PRIMARY KEY,
    namespace VARCHAR NOT NULL,
    version INTEGER NOT NULL,
    fqn VARCHAR,
    label VARCHAR,
    description VARCHAR,
    policytype VARCHAR NOT NULL,
    resource JSON
);

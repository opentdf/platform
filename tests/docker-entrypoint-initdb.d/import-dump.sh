#!/usr/bin/sh

# create schema and tables
psql -a -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -f /docker-entrypoint-initdb.d/opentdf-schema.sql
# import data using seed
psql -a -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -f /tests/"${SEED}"/opentdf.sql

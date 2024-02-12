#!/usr/bin/sh

# create schema
psql -c "CREATE SCHEMA IF NOT EXISTS ${PGSCHEMA}"
# set search path
psql -c "SET search_path TO ${PGSCHEMA}"
# create tables
goose up
# import data using seed
psql -f /tests/"${SEED}"/opentdf.sql

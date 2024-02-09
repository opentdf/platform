# OpenTDF tests

## Seed data

```mermaid

```

### Running with seed data



### New seed data

Create a terminal into docker compose container opentdfdb.  
Dump database

```shell
pg_dump -a opentdf
```

Create new folder to hold seed data in form of <category>-<size>

### Schema change

Dump schema.

```shell
pg_dump --schema-only --no-owner --no-acl -d opentdf
```

Remove "goose_db_version" section.

Update `tests/docker-entrypoint-initdb.d/opentdf-schema.sql`

# OpenTDF tests

## Seed data

```mermaid

```

### Running with seed data

Update your `opentdf.yaml` to run with `public` schema

```yaml
db:
  runMigrations: false
  schema: public
```

### New seed data

Create a terminal into docker compose container opentdfdb.  
Dump database

```shell
pg_dump --data-only --inserts --exclude-table-data=goose_db_version opentdf
```

Create new folder to hold seed data in form of <category>-<size>

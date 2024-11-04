# Policy Database

### Migrations

Migrations are configurable (see [service configuration readme](../../../docs/configuration.md)) and in Policy are powered by
[Goose](https://github.com/pressly/goose).

Goose runs [the migrations](./migrations/) sequentially, and each migration should have an associated ERD in markdown as well if there have been
changes to the table relations in the policy schema.

### Queries

Historically, queries have been written in Go with [squirrel](https://github.com/Masterminds/squirrel).

However, the path going forward is to migrate existing queries and write all new queries directly in SQL (see [./query.sql](./query.sql)),
and generate the Go type-safe functions to execute each query with the helpful tool [sqlc](https://github.com/sqlc-dev/sqlc).

To generate the Go code when you've added or updated a SQL query in `query.sql`, [install sqlc](https://docs.sqlc.dev/en/latest/overview/install.html),
then run the `generate` command.

From repo root:

```shell
make policy-sql-gen
```

From this directory in `/service/policy/db`:

```shell
brew install sqlc

sqlc generate
```

Other useful subcommands also exist on `sqlc`, like `vet`, `compile`, `verify`, and `diff`.

### Schema ERD

[Current schema](./schema_erd.md)

The schema in the policy database is managed through `Goose` migrations (see above), which are also read
into the `sqlc` generated code to execute db queries within Go.

However, we use a separate tool ([see ADR](../adr/0001-generate-policy-erd.md)) to generate an up-to-date
schema ERD containing the entirety of the policy database.

#### Generating

From the repo root:

1. Ensure your Policy postgres container is running
   - `docker compose up`
2. Ensure you have run the latest Goose migrations
   - To run all migrations: `go run ./service start`
   - To run only some migrations: `go run ./service migrate` with various subcommands as needed
3. Generate the schema
   - `make policy-erd-gen`

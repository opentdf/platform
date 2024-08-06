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
then run the `generate` command. In most cases:

```shell
brew install sqlc

sqlc generate
```

Other useful subcommands also exist on `sqlc`, like `vet`, `compile`, `verify`, and `diff`.

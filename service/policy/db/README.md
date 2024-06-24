# Policy Database

The platform Policy PostgreSQL database interactivity is facilitated through a few conventions.

### Migrations

Migrations are found within the [migrations directory](./migrations/).

Each migration file is named with a datestamp and description and run on startup and by CLI migrate command
through the tool [goose](https://github.com/pressly/goose).

There are Entity Relation Diagrams (ERDs) for migrations with a relationship where a visual aid would be useful.

### Squirrel (legacy)

The policy database queries were originally composed with [squirrel](https://github.com/Masterminds/squirrel)
to enable SQL in Go without an ORM.

### SQLC (current)

#### Background

A newer and more robust tool [sqlc](https://docs.sqlc.dev/en/latest/tutorials/getting-started-postgresql.html) is utilized
to generate Go query code and models directly from SQL statements.

This makes for easier debugging, more readable and maintainable query logic, and more featureful SQL as things like
common table expressions (CTEs), subqueries, and transactions are only supported through workarounds by squirrel.

#### Development

As a prerequisite, install `sqlc` with `brew install sqlc`.

To make or update a query, add your query within [query.sql](./queries/query.sql) following the sqlc [conventions and docs](https://docs.sqlc.dev/en/latest/tutorials/getting-started-postgresql.html#schema-and-queries:~:text=Next%2C%20create%20a%20query.sql%20file%20with%20the%20following%20five%20queries%3A).

Generate your Go code with `sqlc generate`, which will read the [config file](./sqlc.yaml) and output the generated
Go code to execute your SQL queries in the `db` package within the [queries](./queries/) directory.

Sqlc utilizes Goose for migrations as well ([see above](#migrations)) and should be used for all new db logic.

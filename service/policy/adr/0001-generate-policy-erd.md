# Generate Policy ERD with mermerd

To date, the Entity Relationship Diagram for platform policy has been actively extended throughout policy migrations, but there is no cohesive single ERD containing all changes at any given time.

As the schema has grown and we have evolved our tool usage (`sqlc`, `goose`, etc), there is a need to generate a single schema ERD with every table within.

Automation is expected to improve maintenance of an ERD containing the entire schema and lower burden on the maintainers; it's easier, faster, and less bug-prone.

### Generated Schema

We will generate a mermaid diagram `.md` schema with a Go tool called [mermerd](https://github.com/KarnerTh/mermerd) that is MIT licensed and actively maintained.

We will place it in `service/policy/db` alongside all DB code and link to it within documentation (see [generated mermerd ERD](../db/schema_erd.md)).

At a future time, we may desire to make the following enhancements:

1. automate its creation in CI with a job that commits the ERD to the repo
2. dynamically populate a connection string rather than hardcode
3. use a different tool that does not connect to the db (and reads from `sqlc` or `goose` code instead, though neither tool appears to provide ERD generation at this time)

This meets the current needs in an acceptable way without blocking any future enhancements.

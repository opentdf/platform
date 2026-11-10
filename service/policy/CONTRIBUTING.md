# Contributing to Policy

Policy in OpenTDF comprises a set of CRUD services rolled up into a single "policy" service
registered to the OpenTDF platform.

Each Policy Object is linked relationally at the database level (currently PostgreSQL), and
there are conventions to the services and codebase.

## Database

See the [database readme](./db/README.md) for context.

## Protos

New policy protos are expected to follow the following conventions (provided as a checklist for development
convenience).

- [ ] Fields are validated by in-proto validators as much as possible (reducing in-service validation logic).
    - [ ] Unit tests are written for the validation (see [./attributes/attributes_test.go](./attributes/attributes_test.go))
- [ ] Proto fields:
    - [ ] order required fields first, optional after
    - [ ] document required fields as `// Required` and optional as `// Optional`
    - [ ] reserve a reasonable number of field indexes for required (i.e. 1-100 used for required, 100+ are used for optional)
- [ ] Pagination follows conventions laid out [in the ADR](./adr/0002-pagination-list-rpcs.md)

## Services

- [ ] CRUD RPCs for Policy objects that retroactively affect access to existing TDFs are served by the [`unsafe` service](./unsafe/)
- [ ] Audit records follow the conventions [in the ADR](./adr/0000-current-state.md)
- [ ] CRUD RPCs that affect multiple objects employ transactions as documented [in the ADR](./adr/0003-database-transactions.md)
- [ ] Any write RPCs either employ a transaction for a read after write scenario, or populate responses from initial request + RETURNING
    clauses in SQL (proactively avoiding potential data consistency issues at future scale)
- [ ] Pagination follows conventions laid out [in the ADR](./adr/0002-pagination-list-rpcs.md)



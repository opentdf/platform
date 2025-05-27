### Changes

#### Function Approach

Provide a function for Subject Condition Set selector matching within the JSONB. 

Benefits:

1. Compiled execution plan
2. IMMUTABLE flag (which allows Postgresql to internally cache the results) [docs](https://www.postgresql.org/docs/current/sql-createfunction.html#:~:text=IMMUTABLE%20indicates%20that,the%20function%20value.)
3. Better query planning estimation

#### Indices

Index on any relations in the `matchSubjectMappings` query for fastest reads.
# Query-Specific Optimizations for OpenTDF

## Critical Query Patterns Identified

### 1. Complex Attribute Queries with Multiple JOINs

The `attributesSelect` function creates queries with:
- 5-7 LEFT JOINs
- JSON aggregations
- GROUP BY operations
- Nested subqueries

**Example Pattern:**
```sql
SELECT 
    ad.id, ad.name, ad.rule,
    JSON_AGG(JSON_BUILD_OBJECT(...)) AS values
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces an ON an.id = ad.namespace_id
LEFT JOIN (
    SELECT av.id, av.value, av.active, 
           COALESCE(JSON_AGG(...), '[]') AS members
    FROM attribute_values av
    LEFT JOIN attribute_value_members vm ON av.id = vm.value_id
    LEFT JOIN attribute_values vmv ON vm.member_id = vmv.id
    GROUP BY av.id
) avt ON avt.attribute_definition_id = ad.id
GROUP BY ad.id, an.name;
```

**Specific Optimizations:**
1. The subquery joining `attribute_values` with `attribute_value_members` needs:
   ```sql
   CREATE INDEX idx_value_members_lookup 
   ON attribute_value_members(value_id, member_id);
   ```

2. For the JSON aggregation performance:
   ```sql
   CREATE INDEX idx_attribute_values_definition_active 
   ON attribute_values(attribute_definition_id, active, id) 
   INCLUDE (value, members);
   ```

### 2. Subject Mapping Queries with Condition Sets

The `subjectMappingSelect` function has:
- Complex JSON_BUILD_OBJECT operations
- Multiple GROUP BY clauses
- JSONB condition field access

**Optimization Needed:**
```sql
-- For the subject condition lookup
CREATE INDEX idx_subject_condition_lookup 
ON subject_condition_set(id) 
INCLUDE (condition);

-- For the subject mapping joins
CREATE INDEX idx_subject_mappings_joins
ON subject_mappings(attribute_value_id, subject_condition_set_id);
```

### 3. FQN (Fully Qualified Name) Lookups

When `withOneValueByFqn` is used, queries include:
```sql
INNER JOIN attribute_fqns AS inner_fqns ON av.id = inner_fqns.value_id
WHERE inner_fqns.fqn = 'namespace/attribute/value'
```

**Critical Index:**
```sql
-- This is the most important index for FQN lookups
CREATE UNIQUE INDEX idx_fqn_lookup_unique 
ON attribute_fqns(fqn) 
INCLUDE (namespace_id, attribute_id, value_id);
```

### 4. Active Record Filtering Pattern

Almost every query includes `WHERE active = true`:

**Partial Index Strategy:**
```sql
-- Create partial indexes for all active record queries
CREATE INDEX idx_attribute_definitions_active_partial 
ON attribute_definitions(namespace_id, id) 
WHERE active = true;

CREATE INDEX idx_attribute_values_active_partial
ON attribute_values(attribute_definition_id, id)
WHERE active = true;
```

## Query Rewriting Recommendations

### 1. Avoid Nested Subqueries in JOINs

Instead of:
```sql
LEFT JOIN (SELECT ... GROUP BY ...) subquery ON ...
```

Consider using CTEs:
```sql
WITH value_members_agg AS (
    SELECT value_id, JSON_AGG(...) as members
    FROM attribute_value_members
    GROUP BY value_id
)
SELECT ... FROM attribute_definitions
LEFT JOIN value_members_agg ON ...
```

### 2. Use FILTER Clause for Conditional Aggregation

Current pattern:
```sql
COALESCE(JSON_AGG(...) FILTER (WHERE vmv.id IS NOT NULL), '[]')
```

This is good! The FILTER clause is more efficient than using CASE statements.

### 3. Consider Materialized Views for Complex Aggregations

For frequently accessed complex queries, create materialized views:

```sql
CREATE MATERIALIZED VIEW mv_attribute_with_values AS
SELECT 
    ad.id,
    ad.namespace_id,
    ad.name,
    ad.active,
    JSON_AGG(
        JSON_BUILD_OBJECT(
            'id', av.id,
            'value', av.value,
            'active', av.active
        )
    ) AS values
FROM attribute_definitions ad
LEFT JOIN attribute_values av ON av.attribute_definition_id = ad.id
WHERE ad.active = true
GROUP BY ad.id;

CREATE UNIQUE INDEX ON mv_attribute_with_values(id);
CREATE INDEX ON mv_attribute_with_values(namespace_id);

-- Refresh periodically or on data changes
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_attribute_with_values;
```

## Application-Level Optimizations

### 1. Implement Query Result Caching

For frequently accessed, relatively static data:
```go
// Cache attribute definitions with values for 5 minutes
type AttributeCache struct {
    data map[string]*policy.Attribute
    ttl  time.Duration
}
```

### 2. Use Prepared Statements

Modify the query builders to use prepared statements:
```go
stmt, err := db.Prepare(ctx, "get_attr_by_fqn", query)
// Reuse the prepared statement
```

### 3. Batch Similar Queries

Instead of multiple single-FQN lookups, batch them:
```sql
WHERE inner_fqns.fqn = ANY($1::text[])
```

## Monitoring Queries

Add this to your application to log slow queries:
```go
// In your database initialization
db.AddQueryHook(pgxslog.NewQueryLogger(logger, &pgxslog.QueryLoggerOptions{
    LogSlowQueries: true,
    SlowQueryThreshold: 100 * time.Millisecond,
}))
```

## Priority Order for Implementation

1. **Immediate (Highest Impact)**:
   - Add foreign key indexes
   - Add FQN lookup index
   - Add partial indexes for active records

2. **Short-term**:
   - Implement covering indexes
   - Add JSONB GIN indexes
   - Optimize GROUP BY with proper indexes

3. **Medium-term**:
   - Consider materialized views
   - Implement application-level caching
   - Query rewriting for complex JOINs

4. **Long-term**:
   - Partition large tables by namespace
   - Archive inactive records
   - Implement read replicas for scaling

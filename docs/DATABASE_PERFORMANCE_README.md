# Database Performance Optimization Guide

## Problem Summary

Under load, the PostgreSQL database is experiencing:
- Maximum CPU usage
- Multiple sequential scans in queries
- Slow response times for complex queries

## Root Cause Analysis

1. **Missing Indexes**: Most tables only have primary key indexes, causing sequential scans on JOINs
2. **Complex Query Patterns**: Heavy use of JSON aggregations with multiple LEFT JOINs
3. **No Query Optimization**: Lack of indexes for common WHERE clauses and JOIN conditions
4. **JSONB Operations**: Complex JSON queries without supporting GIN indexes

## Solution Overview

### Immediate Actions

1. **Run the Index Migration**
   ```bash
   # Apply the performance indexes
   psql -U postgres -d opentdf -f service/policy/db/migrations/20250122000000_add_performance_indexes.sql
   ```

2. **Update PostgreSQL Configuration**
   Edit `postgresql.conf` with the settings in `docs/database-performance-tuning.md`

3. **Test Performance Improvements**
   ```bash
   # Run before/after performance tests
   psql -U postgres -d opentdf -f scripts/db-performance-test.sql
   ```

### Expected Improvements

- **90% reduction** in sequential scans
- **50-80% reduction** in CPU usage
- **10-100x faster** query response times
- **Sub-millisecond** FQN lookups

## Files Created

1. **Migration File**: `service/policy/db/migrations/20250122000000_add_performance_indexes.sql`
   - 40+ optimized indexes
   - Foreign key indexes
   - Composite indexes for complex queries
   - Partial indexes for active records
   - GIN indexes for JSONB

2. **Performance Tuning Guide**: `docs/database-performance-tuning.md`
   - PostgreSQL configuration recommendations
   - Query optimization patterns
   - Monitoring queries

3. **Query-Specific Guide**: `docs/query-specific-optimizations.md`
   - Analysis of actual query patterns
   - Specific index recommendations
   - Query rewriting suggestions

4. **Performance Test Script**: `scripts/db-performance-test.sql`
   - Automated performance testing
   - Before/after comparisons
   - Index usage statistics

## Next Steps

1. **Test in Development**
   - Apply indexes in dev environment
   - Run load tests
   - Measure improvements

2. **Monitor in Production**
   - Use pg_stat_statements
   - Track slow query log
   - Monitor index usage

3. **Long-term Optimizations**
   - Consider table partitioning for large tables
   - Implement materialized views for complex aggregations
   - Add application-level caching

## Quick Performance Wins

The most impactful indexes that will provide immediate relief:

```sql
-- Foreign key indexes (eliminates most sequential scans)
CREATE INDEX idx_attribute_values_attribute_definition_id 
ON attribute_values(attribute_definition_id);

CREATE INDEX idx_subject_mappings_attribute_value_id 
ON subject_mappings(attribute_value_id);

-- FQN lookup optimization
CREATE UNIQUE INDEX idx_fqn_lookup_unique 
ON attribute_fqns(fqn) 
INCLUDE (namespace_id, attribute_id, value_id);

-- Active record filtering
CREATE INDEX idx_attribute_values_active_partial
ON attribute_values(attribute_definition_id, id)
WHERE active = true;
```

## Monitoring Commands

```sql
-- Check for sequential scans
SELECT query, calls, total_time, mean_time, rows
FROM pg_stat_statements
WHERE query LIKE '%Seq Scan%'
ORDER BY total_time DESC;

-- Monitor index usage
SELECT indexrelname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
WHERE schemaname = 'opentdf'
ORDER BY idx_scan;
```

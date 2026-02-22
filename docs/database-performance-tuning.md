# Database Performance Tuning Guide for OpenTDF Platform

## Overview

This guide addresses PostgreSQL performance issues under high load, specifically targeting sequential scan elimination and CPU usage optimization.

## Performance Issues Identified

1. **Sequential Scans**: Multiple queries performing full table scans due to missing indexes
2. **High CPU Usage**: Inefficient query plans causing excessive CPU consumption
3. **JOIN Performance**: Foreign key relationships without supporting indexes
4. **JSONB Operations**: Complex JSON queries without GIN indexes

## Optimization Strategy

### 1. Index Creation (Immediate Impact)

Run the migration file `20250122000000_add_performance_indexes.sql` to add:

- **Foreign Key Indexes**: Eliminates sequential scans on JOINs
- **Active Status Indexes**: Partial indexes for filtering active records
- **JSONB GIN Indexes**: Optimizes complex condition queries
- **Composite Indexes**: Supports common query patterns
- **Covering Indexes**: Reduces table lookups for frequently accessed columns

### 2. Query Plan Analysis

Before and after adding indexes, analyze slow queries:

```sql
-- Enable query timing
\timing on

-- Analyze a specific query
EXPLAIN (ANALYZE, BUFFERS) 
SELECT ... your query here ...;

-- Check index usage
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
WHERE schemaname = 'opentdf'
ORDER BY idx_scan;
```

### 3. PostgreSQL Configuration Tuning

Add these settings to your PostgreSQL configuration:

```ini
# Memory Settings (adjust based on available RAM)
shared_buffers = 25% of RAM          # e.g., 4GB for 16GB system
effective_cache_size = 75% of RAM    # e.g., 12GB for 16GB system
work_mem = 256MB                     # For complex sorts/aggregations
maintenance_work_mem = 512MB         # For index creation

# Query Planner
random_page_cost = 1.1              # For SSD storage (default is 4.0)
effective_io_concurrency = 200      # For SSD storage
default_statistics_target = 100     # More accurate statistics

# Connection Pooling
max_connections = 200               # Adjust based on connection pooler

# Parallel Query Execution
max_parallel_workers_per_gather = 4
max_parallel_workers = 8
parallel_setup_cost = 500
parallel_tuple_cost = 0.05

# Write Performance
checkpoint_completion_target = 0.9
wal_buffers = 16MB
```

### 4. Application-Level Optimizations

#### Connection Pooling
Configure your Go application's database connection pool:

```go
db.SetMaxOpenConns(25)              // Limit concurrent connections
db.SetMaxIdleConns(5)               // Keep some connections ready
db.SetConnMaxLifetime(5 * time.Minute)
```

#### Query Optimization Patterns

1. **Use Prepared Statements**: Reduces parsing overhead
2. **Batch Operations**: Combine multiple inserts/updates
3. **Pagination**: Use LIMIT/OFFSET or cursor-based pagination
4. **Selective Columns**: Only SELECT needed columns

### 5. Monitoring and Maintenance

#### Enable pg_stat_statements
```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

#### Monitor Slow Queries
```sql
-- Top 10 slowest queries
SELECT 
    query,
    mean_exec_time,
    calls,
    total_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

#### Regular Maintenance
```sql
-- Update table statistics
ANALYZE;

-- Check for bloat
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    n_live_tup,
    n_dead_tup,
    round(n_dead_tup * 100.0 / (n_live_tup + n_dead_tup), 2) as dead_percentage
FROM pg_stat_user_tables
WHERE n_live_tup > 0
ORDER BY n_dead_tup DESC;

-- Reindex if needed (during maintenance window)
REINDEX TABLE tablename CONCURRENTLY;
```

## Expected Performance Improvements

After implementing these optimizations:

1. **Elimination of Sequential Scans**: Foreign key indexes will convert sequential scans to index scans
2. **50-90% CPU Reduction**: Efficient query plans will significantly reduce CPU usage
3. **10-100x Faster JOINs**: Indexed foreign keys dramatically improve JOIN performance
4. **Sub-millisecond Lookups**: Composite indexes enable fast record retrieval

## Testing the Optimizations

1. **Load Testing**: Use your existing load test suite to measure improvements
2. **Query Timing**: Compare EXPLAIN ANALYZE results before/after
3. **CPU Monitoring**: Track database CPU usage during peak load
4. **Response Times**: Measure API endpoint latencies

## Rollback Plan

If needed, indexes can be dropped without data loss:

```sql
-- Generate DROP statements
SELECT 'DROP INDEX ' || indexname || ';'
FROM pg_indexes
WHERE indexname LIKE 'idx_%'
AND schemaname = 'opentdf';
```

## Next Steps

1. Apply the migration in a test environment first
2. Run load tests to validate improvements
3. Monitor pg_stat_user_indexes to ensure indexes are being used
4. Fine-tune PostgreSQL configuration based on your hardware
5. Consider partitioning large tables if they continue to grow

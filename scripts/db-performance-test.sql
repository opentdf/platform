-- Database Performance Testing Script for OpenTDF
-- Run this before and after applying indexes to measure improvements

-- Enable timing
\timing on

-- Set up EXPLAIN output format
SET work_mem = '256MB';
SET random_page_cost = 1.1;  -- For SSD

-- Create a temporary table to store results
CREATE TEMP TABLE IF NOT EXISTS performance_results (
    test_name TEXT,
    execution_time INTERVAL,
    query_plan TEXT,
    run_timestamp TIMESTAMP DEFAULT NOW()
);

-- Test 1: Complex Attribute Query with Multiple JOINs
\echo 'Test 1: Complex Attribute Query with Values and Members'
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT
    ad.id,
    ad.name,
    ad.rule,
    an.name as namespace_name,
    JSON_AGG(JSON_BUILD_OBJECT(
        'id', avt.id,
        'value', avt.value,
        'members', avt.members,
        'active', avt.active
    )) AS values
FROM attribute_definitions ad
LEFT JOIN attribute_namespaces an ON an.id = ad.namespace_id
LEFT JOIN (
    SELECT av.id, av.value, av.active,
           COALESCE(JSON_AGG(JSON_BUILD_OBJECT(
               'id', vmv.id,
               'value', vmv.value,
               'active', vmv.active,
               'members', vmv.members || ARRAY[]::UUID[]
           )) FILTER (WHERE vmv.id IS NOT NULL), '[]') AS members,
           av.attribute_definition_id
    FROM attribute_values av
    LEFT JOIN attribute_value_members vm ON av.id = vm.value_id
    LEFT JOIN attribute_values vmv ON vm.member_id = vmv.id
    WHERE av.active = true
    GROUP BY av.id
) avt ON avt.attribute_definition_id = ad.id
WHERE ad.active = true
GROUP BY ad.id, an.name;

-- Test 2: Subject Mapping Query with Condition Sets
\echo 'Test 2: Subject Mapping with JSON Aggregations'
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT
    sm.id,
    sm.actions,
    JSON_BUILD_OBJECT(
        'id', scs.id,
        'subject_sets', scs.condition
    ) AS subject_condition_set,
    JSON_BUILD_OBJECT(
        'id', av.id,
        'value', av.value,
        'active', av.active
    ) AS attribute_value
FROM subject_mappings sm
LEFT JOIN attribute_values av ON sm.attribute_value_id = av.id
LEFT JOIN subject_condition_set scs ON scs.id = sm.subject_condition_set_id
WHERE av.active = true;

-- Test 3: FQN Lookup Performance
\echo 'Test 3: FQN Lookup Query'
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT
    af.fqn,
    af.namespace,
    af.attribute,
    af.value,
    av.id as value_id,
    av.value as value_data,
    ad.id as attribute_id,
    ad.name as attribute_name
FROM attribute_fqns af
JOIN attribute_values av ON af.value_id = av.id
JOIN attribute_definitions ad ON af.attribute_id = ad.id
WHERE af.fqn IN (
    'https://namespace1.com/attr/classification/value1',
    'https://namespace2.com/attr/department/value2',
    'https://namespace3.com/attr/project/value3'
);

-- Test 4: Active Record Filtering
\echo 'Test 4: Active Record Filtering Performance'
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT COUNT(*) as total_active,
       COUNT(DISTINCT namespace_id) as active_namespaces
FROM attribute_definitions
WHERE active = true;

-- Test 5: Complex JOIN with GROUP BY
\echo 'Test 5: Complex JOIN with GROUP BY'
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT
    ns.name as namespace,
    COUNT(DISTINCT ad.id) as attribute_count,
    COUNT(DISTINCT av.id) as value_count,
    COUNT(DISTINCT sm.id) as mapping_count
FROM attribute_namespaces ns
LEFT JOIN attribute_definitions ad ON ad.namespace_id = ns.id AND ad.active = true
LEFT JOIN attribute_values av ON av.attribute_definition_id = ad.id AND av.active = true
LEFT JOIN subject_mappings sm ON sm.attribute_value_id = av.id
WHERE ns.active = true
GROUP BY ns.id, ns.name
ORDER BY value_count DESC;

-- Test 6: JSONB Condition Query
\echo 'Test 6: JSONB Subject Condition Query'
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT
    scs.id,
    scs.condition,
    COUNT(sm.id) as mapping_count
FROM subject_condition_set scs
JOIN subject_mappings sm ON sm.subject_condition_set_id = scs.id
WHERE scs.condition @> '[{"conditionGroups":[{"conditions":[{"subjectExternalSelectorValue":".email"}]}]}]'::jsonb
GROUP BY scs.id;

-- Summary Statistics
\echo 'Database Statistics Summary'
SELECT
    schemaname,
    tablename,
    n_live_tup as live_rows,
    n_dead_tup as dead_rows,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables
WHERE schemaname = 'opentdf'
ORDER BY n_live_tup DESC;

-- Index Usage Statistics
\echo 'Index Usage Statistics'
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes
WHERE schemaname = 'opentdf'
ORDER BY idx_scan DESC;

-- Table Sizes
\echo 'Table Sizes'
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) as index_size
FROM pg_tables
WHERE schemaname = 'opentdf'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

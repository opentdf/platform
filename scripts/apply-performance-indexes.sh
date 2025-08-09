#!/bin/bash

# Script to safely apply performance indexes to OpenTDF database
# Usage: ./apply-performance-indexes.sh [database_name] [host] [port] [username]

set -euo pipefail

# Default values
DB_NAME="${1:-opentdf}"
DB_HOST="${2:-localhost}"
DB_PORT="${3:-5432}"
DB_USER="${4:-postgres}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Files
MIGRATION_FILE="service/policy/db/migrations/20250122000000_add_performance_indexes.sql"
PERFORMANCE_TEST="scripts/db-performance-test.sql"
BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"

echo -e "${GREEN}OpenTDF Database Performance Optimization${NC}"
echo "=================================================="
echo "Database: $DB_NAME"
echo "Host: $DB_HOST:$DB_PORT"
echo "User: $DB_USER"
echo ""

# Check if required files exist
if [ ! -f "$MIGRATION_FILE" ]; then
    echo -e "${RED}Error: Migration file not found at $MIGRATION_FILE${NC}"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to run SQL and capture output
run_sql() {
    local sql_file=$1
    local output_file=$2
    echo -e "${YELLOW}Running: $sql_file${NC}"
    PGPASSWORD="${PGPASSWORD:-}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$sql_file" > "$output_file" 2>&1 || {
        echo -e "${RED}Error executing $sql_file. Check $output_file for details.${NC}"
        return 1
    }
    echo -e "${GREEN}Completed successfully${NC}"
}

# Step 1: Run performance test before optimization
echo -e "\n${YELLOW}Step 1: Running baseline performance test...${NC}"
if [ -f "$PERFORMANCE_TEST" ]; then
    run_sql "$PERFORMANCE_TEST" "$BACKUP_DIR/performance_baseline.log" || true
    echo "Baseline results saved to: $BACKUP_DIR/performance_baseline.log"
else
    echo "Performance test script not found, skipping baseline test"
fi

# Step 2: Backup current index definitions
echo -e "\n${YELLOW}Step 2: Backing up current indexes...${NC}"
PGPASSWORD="${PGPASSWORD:-}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF > "$BACKUP_DIR/current_indexes.sql"
-- Backup of current indexes
SELECT
    'CREATE INDEX ' || indexname || ' ON ' || schemaname || '.' || tablename ||
    ' USING ' || CASE WHEN indisprimary THEN 'btree' ELSE am END ||
    ' (' || indexdef || ');' as create_statement
FROM pg_indexes i
JOIN pg_class c ON c.relname = i.indexname
JOIN pg_index idx ON idx.indexrelid = c.oid
JOIN pg_am a ON a.oid = c.relam
WHERE schemaname = 'opentdf'
AND NOT indisprimary
ORDER BY tablename, indexname;
EOF
echo "Index backup saved to: $BACKUP_DIR/current_indexes.sql"

# Step 3: Check current database statistics
echo -e "\n${YELLOW}Step 3: Checking database statistics...${NC}"
PGPASSWORD="${PGPASSWORD:-}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF > "$BACKUP_DIR/db_stats_before.log"
-- Table sizes and row counts
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    n_live_tup as row_count
FROM pg_stat_user_tables
WHERE schemaname = 'opentdf'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Current slow queries (if pg_stat_statements is available)
SELECT
    calls,
    total_exec_time::bigint as total_ms,
    mean_exec_time::bigint as mean_ms,
    query
FROM pg_stat_statements
WHERE query NOT LIKE '%pg_stat_statements%'
ORDER BY mean_exec_time DESC
LIMIT 20;
EOF

# Step 4: Apply the migration
echo -e "\n${YELLOW}Step 4: Applying performance indexes...${NC}"
echo "This may take several minutes depending on table sizes..."

# Start timing
START_TIME=$(date +%s)

# Apply migration with progress monitoring
PGPASSWORD="${PGPASSWORD:-}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 \
    --echo-queries \
    -f "$MIGRATION_FILE" > "$BACKUP_DIR/migration_output.log" 2>&1 || {
    echo -e "${RED}Error applying migration! Check $BACKUP_DIR/migration_output.log for details.${NC}"
    echo -e "${YELLOW}To rollback, you can drop the newly created indexes using:${NC}"
    echo "psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c \"SELECT 'DROP INDEX IF EXISTS ' || indexname || ';' FROM pg_indexes WHERE indexname LIKE 'idx_%' AND schemaname = 'opentdf';\""
    exit 1
}

# End timing
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo -e "${GREEN}Migration completed successfully in $DURATION seconds!${NC}"

# Step 5: Verify indexes were created
echo -e "\n${YELLOW}Step 5: Verifying new indexes...${NC}"
NEW_INDEX_COUNT=$(PGPASSWORD="${PGPASSWORD:-}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM pg_indexes WHERE indexname LIKE 'idx_%' AND schemaname = 'opentdf';")
echo "Created $NEW_INDEX_COUNT new indexes"

# Step 6: Run performance test after optimization
if [ -f "$PERFORMANCE_TEST" ]; then
    echo -e "\n${YELLOW}Step 6: Running post-optimization performance test...${NC}"
    run_sql "$PERFORMANCE_TEST" "$BACKUP_DIR/performance_after.log" || true
    echo "Post-optimization results saved to: $BACKUP_DIR/performance_after.log"

    # Simple comparison
    echo -e "\n${GREEN}Performance Comparison:${NC}"
    echo "Baseline: $BACKUP_DIR/performance_baseline.log"
    echo "After optimization: $BACKUP_DIR/performance_after.log"
fi

# Step 7: Generate rollback script
echo -e "\n${YELLOW}Step 7: Generating rollback script...${NC}"
cat > "$BACKUP_DIR/rollback_indexes.sql" <<EOF
-- Rollback script for performance indexes
-- Generated on $(date)

-- Drop all indexes created by the migration
EOF

PGPASSWORD="${PGPASSWORD:-}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t <<EOF >> "$BACKUP_DIR/rollback_indexes.sql"
SELECT 'DROP INDEX IF EXISTS ' || schemaname || '.' || indexname || ';'
FROM pg_indexes
WHERE indexname LIKE 'idx_%'
AND schemaname = 'opentdf'
AND indexname IN (
    'idx_attribute_definitions_namespace_id',
    'idx_attribute_definitions_namespace_id_active',
    'idx_attribute_values_attribute_definition_id',
    'idx_attribute_values_attribute_definition_id_active',
    'idx_attribute_value_members_value_id',
    'idx_attribute_value_members_member_id',
    'idx_resource_mappings_attribute_value_id',
    'idx_resource_mappings_attribute_value_id_active',
    'idx_subject_mappings_attribute_value_id',
    'idx_subject_mappings_condition_set_id',
    'idx_subject_mappings_attribute_value_id_active',
    'idx_key_access_grants_namespace_id',
    'idx_key_access_grants_attribute_value_id',
    'idx_attribute_fqn_composite',
    'idx_attribute_namespaces_active',
    'idx_attribute_definitions_active',
    'idx_attribute_values_active',
    'idx_resource_mappings_active',
    'idx_subject_mappings_active',
    'idx_subject_condition_set_condition_gin',
    'idx_attributes_namespace_lookup',
    'idx_values_definition_lookup',
    'idx_fqn_resolution',
    'idx_attribute_values_groupby',
    'idx_subject_mappings_aggregation',
    'idx_attribute_definitions_covering',
    'idx_attribute_values_covering',
    'idx_resource_mappings_created_at',
    'idx_subject_mappings_created_at',
    'idx_resource_mappings_updated_at',
    'idx_subject_mappings_updated_at',
    'idx_key_access_grants_composite'
);
EOF

echo "Rollback script saved to: $BACKUP_DIR/rollback_indexes.sql"

# Summary
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Performance Optimization Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Backup directory: $BACKUP_DIR"
echo "Migration log: $BACKUP_DIR/migration_output.log"
echo "Rollback script: $BACKUP_DIR/rollback_indexes.sql"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Monitor database performance and CPU usage"
echo "2. Check slow query logs for improvements"
echo "3. Run your application load tests"
echo "4. If issues occur, use the rollback script"
echo ""
echo -e "${GREEN}To check index usage:${NC}"
echo "psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c \"SELECT indexrelname, idx_scan FROM pg_stat_user_indexes WHERE schemaname = 'opentdf' ORDER BY idx_scan DESC;\""

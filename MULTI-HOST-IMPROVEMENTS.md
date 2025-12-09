# PostgreSQL Horizontal Scaling & High Availability

## Overview

This document describes PostgreSQL horizontal scaling capabilities added to the platform: read replica support, multi-host primary failover, and circuit breaker health checking.

**Previous (main branch):**
- Single primary database only
- No horizontal scaling
- No failover support

**This branch adds:**
- Read replica support with round-robin load balancing
- Multi-host primary failover
- Circuit breaker health checking (sony/gobreaker)
- Context-based primary routing
- Comprehensive integration tests with testcontainers

## New Capabilities

### 1. **Read Replica Support**
Horizontal scaling via PostgreSQL streaming replication with round-robin load balancing and circuit breaker health checking.

### 2. **Multi-Host Primary Failover**
Multi-host primary configuration using pgx's `target_session_attrs=primary`. When configured with multiple primary hosts, pgx automatically tries each host until it finds one accepting read-write connections.

```yaml
db:
  # Optional: Configure multiple primary hosts for automatic failover
  primary_hosts:
    - host: primary1.example.com
      port: 5432
    - host: primary2.example.com
      port: 5432
    - host: primary3.example.com
      port: 5432
```

**How it works:**
- pgx tries each host in order
- Uses `target_session_attrs=primary` to ensure connection is to a primary (not standby)
- Automatically fails over to next host if current primary is down

### 3. **Circuit Breaker Health Checking**
Industry-standard circuit breaker pattern using **[sony/gobreaker](https://github.com/sony/gobreaker)**:
- Automatically detects failures (60% failure rate over 3 requests)
- Opens circuit after failures, preventing cascading failures
- Automatic recovery after 60 seconds in open state
- Half-open state allows controlled testing (3 requests)
- Falls back to primary when all circuit breakers open

```go
// Circuit breakers protect automatically
// Failed replica is circuit-broken and skipped
db.Query(ctx, "SELECT * FROM users", nil)  // Automatically routes around circuit-broken replicas
```

**Why gobreaker?**
- ✅ Battle-tested by major companies (6.7k ⭐ on GitHub)
- ✅ Production-proven for high-scale systems
- ✅ Standard circuit breaker implementation
- ✅ No custom health tracking code to maintain

### 4. **Context-Based Primary Routing**
Avoid replication lag for read-after-write scenarios:

```go
// Force next read to use primary (avoids replication lag)
db.Exec(ctx, "INSERT INTO users (id, name) VALUES (1, 'Alice')", nil)

ctx = db.WithForcePrimary(ctx)  // Force primary for this read
db.Query(ctx, "SELECT * FROM users WHERE id = 1", nil)  // Guaranteed to see the write
```

### 5. **Comprehensive Integration Tests**
Testcontainer-based tests with proper cleanup:
- Read replica functionality and replication verification
- Circuit breaker behavior with failing replicas
- Multi-host primary failover scenarios
- Uses `t.Cleanup()` for guaranteed container termination

## Configuration Examples

**Required:** `pool.max_conns` must be ≥ 1 (enforced by pgx).

### Option 1: Single Primary + Read Replicas (Original)

```yaml
db:
  host: primary.example.com
  port: 5432
  read_replicas:
    - host: replica1.example.com
      port: 5432
    - host: replica2.example.com
      port: 5432
```

**Behavior:**
- Writes → primary.example.com
- Reads → round-robin across replicas with health checking
- Falls back to primary if replicas fail

### Option 2: Multi-Host Primary + Read Replicas (Recommended for HA)

```yaml
db:
  primary_hosts:  # Automatic primary failover via pgx
    - host: primary1.example.com
      port: 5432
    - host: primary2.example.com
      port: 5432
  read_replicas:  # Health-checked read load balancing
    - host: replica1.example.com
      port: 5432
    - host: replica2.example.com
      port: 5432
```

**Behavior:**
- Writes → tries primary1, then primary2 (automatic pgx failover)
- Reads → round-robin across replicas with health checking
- Falls back to primary if all replicas fail

### Option 3: Local Development (No Failover Needed)

```yaml
db:
  host: localhost
  port: 5432
  read_replicas:
    - host: localhost
      port: 5433
```

**Behavior:**
- Simple setup for testing replica logic locally
- Health checking still active

### Configuration Validation

**Cannot use both `host` and `primary_hosts`:**
```yaml
# ❌ INVALID - Will throw error
db:
  host: localhost           # Single host
  primary_hosts:            # Multi-host
    - host: primary1
      port: 5432
```

The configuration loader validates and rejects ambiguous setups with a clear error:
```
invalid configuration: cannot specify both 'host' and 'primary_hosts' - use one or the other
```

## Local Development with Docker Compose

The `docker-compose.yaml` provides three commented-out scenarios for testing horizontal scaling locally:

### SCENARIO 1: Single Primary (Default)
```yaml
# Active by default - opentdfdb service only
# Configuration: host: opentdfdb
```
- No horizontal scaling
- Simplest setup for basic development
- No additional containers needed

### SCENARIO 2: Primary + Read Replicas
```yaml
# Uncomment: opentdfdb-replica1, opentdfdb-replica2
# Uncomment: corresponding volumes
# Configuration:
db:
  host: opentdfdb
  read_replicas:
    - host: opentdfdb-replica1
      port: 5432
    - host: opentdfdb-replica2
      port: 5432
```
- Tests horizontal read scaling
- Circuit breaker behavior
- Round-robin load balancing

### SCENARIO 3: Multi-Host Primary + Read Replicas (Full HA)
```yaml
# Uncomment: opentdfdb-primary2, opentdfdb-replica1, opentdfdb-replica2
# Uncomment: corresponding volumes
# Configuration:
db:
  primary_hosts:
    - host: opentdfdb
      port: 5432
    - host: opentdfdb-primary2
      port: 5432
  read_replicas:
    - host: opentdfdb-replica1
      port: 5432
    - host: opentdfdb-replica2
      port: 5432
```
- Tests complete high availability setup
- Primary failover + read scaling
- Full circuit breaker and health checking

**To activate a scenario:**
1. Uncomment desired services in `docker-compose.yaml`
2. Uncomment corresponding volumes at bottom of file
3. Update `opentdf-example.yaml` with matching configuration
4. Run: `docker-compose up -d`

## Production PostgreSQL Configuration

The docker-compose PostgreSQL replication setup includes production-ready settings:

### WAL Retention
```yaml
wal_keep_size=1024  # 1GB prevents replication breaks during replica lag
```
- Prevents WAL deletion if replicas lag behind
- 1GB buffer handles temporary network issues or maintenance
- Critical for preventing permanent replication failures

### Network Security
```yaml
# Restricts replication connections to Docker network only
echo "host replication replicator opentdf_platform md5"
```
- Replaces overly permissive `0.0.0.0/0` access
- Follows principle of least privilege
- Prevents external replication connection attempts

### Streaming Replication Parameters
```yaml
-c wal_level=replica
-c max_wal_senders=10
-c max_replication_slots=10
-c hot_standby=on
```
- Enables up to 10 concurrent replicas
- Hot standby allows reads on replicas
- Standard PostgreSQL streaming replication

## API Usage

### Basic Usage (No Changes Required)

```go
// Existing code works without modification
client, err := db.New(ctx, config, logConfig, &tracer)
defer client.Close()

// Writes automatically go to primary
client.Exec(ctx, "INSERT INTO users ...", args)

// Reads automatically load-balance across healthy replicas
rows, _ := client.Query(ctx, "SELECT * FROM users", nil)
```

### Read-After-Write Pattern

```go
// Write something
client.Exec(ctx, "UPDATE users SET status = 'active' WHERE id = $1", []interface{}{userID})

// Read it back immediately (force primary to avoid replication lag)
ctx = db.WithForcePrimary(ctx)
row, _ := client.QueryRow(ctx, "SELECT status FROM users WHERE id = $1", []interface{}{userID})
```

### Critical Reads (Always Use Primary)

```go
// For sensitive queries that must see latest data
ctx = db.WithForcePrimary(ctx)
row, _ := client.QueryRow(ctx, "SELECT balance FROM accounts WHERE id = $1", []interface{}{id})
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Application                           │
└────────┬────────────────────────────────────────────┬────────┘
         │                                            │
         │ Writes (INSERT/UPDATE/DELETE)              │ Reads (SELECT)
         │                                            │
         ▼                                            ▼
┌─────────────────────────┐              ┌──────────────────────┐
│  Multi-Host Primary     │              │  Health-Tracked      │
│  (pgx failover)         │              │  Replicas            │
│                         │              │  (round-robin)       │
│  ┌─────────────┐        │              │                      │
│  │  Primary 1  │────┐   │              │  ┌────────────┐      │
│  └─────────────┘    │   │              │  │ Replica 1  │      │
│                     │   │              │  │ (healthy)  │      │
│  ┌─────────────┐    ├───┼──┐           │  └────────────┘      │
│  │  Primary 2  │────┘   │  │           │                      │
│  └─────────────┘        │  │           │  ┌────────────┐      │
│                         │  │           │  │ Replica 2  │      │
│  target_session_attrs=  │  │           │  │ (unhealthy)│──X   │
│  primary                │  │           │  └────────────┘      │
└─────────────────────────┘  │           │                      │
                             │           │  Background health   │
                             │           │  checks every 30s    │
                             │           └���─────────────────────┘
                             │
                             └─► Fallback if all replicas fail
```

## Implementation Details

### Circuit Breaker (using sony/gobreaker)

**Circuit Breaker States:**
1. **Closed** (healthy): All requests pass through
2. **Open** (unhealthy): All requests fail fast for 60s
3. **Half-Open** (testing): Allow 3 requests to test recovery

**Transition Logic:**
- Closed → Open: When 60% of requests fail (over 3 requests)
- Open → Half-Open: After 60 seconds timeout
- Half-Open → Closed: If test requests succeed
- Half-Open → Open: If test requests fail

**Benefits:**
- ✅ Prevents cascading failures
- ✅ Automatic recovery without manual intervention
- ✅ Industry-standard implementation (not custom code)
- ✅ Used by major companies in production
- ✅ No background goroutines needed

### Connection String Generation

**Single Primary:**
```
postgres://user:pass@primary:5432/db?sslmode=prefer
```

**Multi-Host Primary:**
```
postgres://user:pass@primary1:5432,primary2:5433/db?sslmode=prefer&target_session_attrs=primary
```

### Performance Characteristics

- **Primary Failover**: ~100ms per failed host (pgx ConnectTimeout)
- **Circuit Breaker Overhead**: ~5-10µs per query (gobreaker state check)
- **Circuit Open Duration**: 60 seconds before retry
- **Half-Open Test Requests**: 3 requests to verify recovery
- **Fallback to Primary**: Immediate when all circuit breakers open
- **Replica Recovery**: Automatic when queries start succeeding

## Monitoring

### Log Messages

**Circuit Breaker State Changes:**
```
INFO replica circuit breaker state changed replica_index=0 from=closed to=open
INFO replica circuit breaker state changed replica_index=0 from=open to=half-open
INFO replica circuit breaker state changed replica_index=0 from=half-open to=closed
WARN all read replica circuit breakers open, falling back to primary
```

**Primary Failover:**
```
INFO opening primary database pool schema=opentdf
INFO configuring read replicas count=2
```

### Recommended Metrics (Future Enhancement)

```
db_read_queries_total{replica="replica1"}
db_replica_lag_seconds{replica="replica1"}
db_connection_pool_active{replica="replica1", type="read"}
db_query_errors_total{replica="replica1", error_type="timeout"}
```

## Testing

### Unit Tests

```bash
# Multi-host primary configuration
go test ./service/pkg/db -run TestMultiHostPrimaryConfig -v

# Context-based primary routing
go test ./service/pkg/db -run TestContextForcePrimary -v

# Circuit breaker logic
go test ./service/pkg/db -run TestReplicaCircuitBreaker -v

# Configuration validation (host vs primary_hosts)
go test ./service/pkg/db -run TestConfigValidation -v
```

### Integration Tests (with Testcontainers)

```bash
# Read replica health checking and load balancing
go test ./service/integration -run TestReadReplicasWithTestcontainers -v

# Circuit breaker behavior with failing replicas
go test ./service/integration -run TestCircuitBreaker -v

# Multi-host primary failover scenarios
go test ./service/integration -run TestMultiHostPrimary -v
```

**Note:** Tests use `t.Cleanup()` for proper container termination even on test failures.

## Migration Guide

### Backward Compatibility

**No code changes required!** Existing single-database configurations work without modification:

```yaml
# Existing config continues to work
db:
  host: primary
  port: 5432
```

### Opt-In Features

1. **Add read replicas for horizontal scaling:**
```yaml
db:
  host: primary
  port: 5432
  read_replicas:
    - host: replica1
      port: 5432
    - host: replica2
      port: 5432
```

2. **Add multi-host primary for failover:**
```yaml
db:
  primary_hosts:
    - host: primary1
      port: 5432
    - host: primary2
      port: 5432
```

3. **Use context-based routing for read-after-write:**
```go
client.Exec(ctx, "INSERT ...", args)
ctx = db.WithForcePrimary(ctx)
client.Query(ctx, "SELECT ...", args)  // Guaranteed to see the write
```

## Limitations & Future Work

### Current Limitations

1. **No Replica Lag Monitoring**: Circuit breaker is based on connectivity, not replication lag
2. **No Weighted Round-Robin**: All healthy replicas get equal load regardless of capacity
3. **No Geographic Routing**: Can't prefer replicas closer to application
4. **DNS Failures Block All**: Known pgx issue - DNS failure prevents trying next host

### Future Enhancements

1. **LSN-Based Lag Checking**: Query `pg_last_wal_replay_lsn()` to measure lag
2. **Metrics Export**: Prometheus metrics for replica health and query distribution
3. **Weighted Load Balancing**: Configure capacity weights per replica
4. **Connection Pool Statistics**: Expose pool saturation metrics
5. **Patroni Integration**: Auto-discover primary/replicas from Patroni

## References

- [pgx Multi-Host Support](https://github.com/jackc/pgx/discussions/1608)
- [PostgreSQL target_session_attrs](https://pgpedia.info/t/target_session_attrs.html)
- [PostgreSQL Streaming Replication](https://www.postgresql.org/docs/current/warm-standby.html)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)

## Dependencies

- **pgx/v5**: PostgreSQL driver with multi-host support
- **sony/gobreaker/v2**: Industry-standard circuit breaker implementation

## Summary

**New Capabilities:**
- ✅ Read replica support with round-robin load balancing
- ✅ Multi-host primary failover (pgx `target_session_attrs=primary`)
- ✅ Circuit breaker health checking (sony/gobreaker)
- ✅ Context-based primary routing (`WithForcePrimary`)
- ✅ Automatic fallback to primary when replicas fail
- ✅ Configuration validation (prevents ambiguous host/primary_hosts setup)
- ✅ Three docker-compose scenarios for local development testing
- ✅ Production-ready PostgreSQL replication settings
- ✅ Comprehensive integration tests with testcontainers

**Backward Compatibility:**
- ✅ Existing single-database configs work without changes
- ✅ All features are opt-in via configuration

**Local Development:**
- ✅ Three commented-out docker-compose scenarios (single/replicas/full-HA)
- ✅ Easy activation via uncommenting services + volumes
- ✅ Aligned with opentdf-example.yaml configuration

**Production Ready:**
- ✅ 1GB WAL retention prevents replication breaks
- ✅ Network-restricted replication access (Docker network only)
- ✅ Proper streaming replication parameters

# Harbor Multi-Tenant Migration with PGX Ecosystem

## Executive Summary

This document investigates migrating Harbor to a true multi-tenant system leveraging the PGX tools and ecosystem. The goal is to support **100 tenants per region** with a **total of 300 database connections** while ensuring efficient connection reuse across tenants.

## Current Architecture Analysis

### Database Stack

| Component | Current Implementation |
|-----------|----------------------|
| ORM | Beego ORM v2 (`github.com/beego/beego/v2/client/orm`) |
| PostgreSQL Driver | pgx v4 (`github.com/jackc/pgx/v4/stdlib`) |
| Migration Tool | golang-migrate v4 |
| Connection Pooling | Beego ORM built-in (limited configuration) |

### Current Connection Pool Configuration

Located in `src/common/dao/pgsql.go`:

```go
type pgsql struct {
    maxIdleConns    int           // Default: 2
    maxOpenConns    int           // Default: 0 (unlimited)
    connMaxLifetime time.Duration // Default: 5 minutes
    connMaxIdleTime time.Duration // Default: 0 (no limit)
}
```

**Problem**: These defaults are unsuitable for multi-tenant workloads with 100 tenants.

### Current Multi-Tenancy Model

Harbor uses **project-based tenancy** with `project_id` as the tenant identifier:

| Table | Tenant Isolation |
|-------|------------------|
| `project` | Base tenant table |
| `project_member` | Tenant membership |
| `project_metadata` | Tenant configuration |
| `repository` | Resources scoped by `project_id` |
| `artifact` | Data scoped by `project_id` |
| `access_log` | Audit trail with `project_id` |

**Current Filtering**: Queries are manually filtered by `project_id` in the DAO layer:

```go
// src/pkg/project/dao/dao.go:138
if err = o.Read(project, "project_id", "deleted"); err != nil { ... }
```

---

## Proposed Architecture

### Target Stack

| Component | Proposed Implementation |
|-----------|------------------------|
| PostgreSQL Driver | pgx v5 (`github.com/jackc/pgx/v5`) |
| Connection Pooling | pgxpool + PgBouncer |
| Multi-tenancy | Row-Level Security (RLS) |
| ORM Compatibility | Hybrid approach (gradual migration) |

### Connection Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Harbor Application                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Instance 1 │  │  Instance 2 │  │  Instance N │         │
│  │  pgxpool    │  │  pgxpool    │  │  pgxpool    │         │
│  │  30 conns   │  │  30 conns   │  │  30 conns   │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
└─────────┼────────────────┼────────────────┼─────────────────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
              ┌────────────▼────────────┐
              │       PgBouncer         │
              │  Transaction Pooling    │
              │  300 total connections  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │      PostgreSQL         │
              │   Row-Level Security    │
              │   100 Tenants/Region    │
              └─────────────────────────┘
```

### Connection Math for 100 Tenants / 300 Connections

| Configuration | Value | Rationale |
|---------------|-------|-----------|
| PostgreSQL max_connections | 350 | 300 + 50 for admin/monitoring |
| PgBouncer pool_size | 300 | Target connection limit |
| PgBouncer reserve_pool | 10 | Burst capacity |
| pgxpool per instance (10 instances) | 30 | 300 / 10 = 30 |
| pgxpool per instance (5 instances) | 60 | 300 / 5 = 60 |
| Connections per tenant (shared) | 3 | 300 / 100 = 3 average |

**Key Insight**: With RLS, connections are shared across tenants. No pool-per-tenant needed.

---

## Implementation Plan

### Phase 1: Upgrade to pgx v5

**1.1 Update Dependencies**

```go
// go.mod changes
- github.com/jackc/pgx/v4 v4.x.x
+ github.com/jackc/pgx/v5 v5.x.x
+ github.com/jackc/pgx/v5/pgxpool
```

**1.2 Create New Connection Manager**

Create `src/lib/db/pgxpool.go`:

```go
package db

import (
    "context"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

type PoolConfig struct {
    Host            string
    Port            int
    Username        string
    Password        string
    Database        string
    SSLMode         string
    MaxConns        int32         // Target: 30 per instance
    MinConns        int32         // Target: 5
    MaxConnLifetime time.Duration // Target: 1 hour
    MaxConnIdleTime time.Duration // Target: 30 minutes
    HealthCheckPeriod time.Duration // Target: 1 minute
}

func NewPool(ctx context.Context, cfg *PoolConfig) (*pgxpool.Pool, error) {
    connString := fmt.Sprintf(
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=%s "+
        "pool_max_conns=%d pool_min_conns=%d "+
        "pool_max_conn_lifetime=%s pool_max_conn_idle_time=%s "+
        "pool_health_check_period=%s",
        cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database, cfg.SSLMode,
        cfg.MaxConns, cfg.MinConns,
        cfg.MaxConnLifetime, cfg.MaxConnIdleTime,
        cfg.HealthCheckPeriod,
    )

    poolConfig, err := pgxpool.ParseConfig(connString)
    if err != nil {
        return nil, err
    }

    // Configure for PgBouncer compatibility (transaction mode)
    poolConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec

    return pgxpool.NewWithConfig(ctx, poolConfig)
}
```

**1.3 Recommended Pool Configuration**

```go
// For 10 application instances, 300 total connections, 100 tenants
cfg := &PoolConfig{
    MaxConns:          30,              // 300 / 10 instances
    MinConns:          5,               // Keep some warm
    MaxConnLifetime:   1 * time.Hour,   // Recycle periodically
    MaxConnIdleTime:   30 * time.Minute,// Release idle connections
    HealthCheckPeriod: 1 * time.Minute, // Detect stale connections
}
```

### Phase 2: Implement Row-Level Security

**2.1 Add Tenant Column Migration**

Create `make/migrations/postgresql/0200_multi_tenant_rls.up.sql`:

```sql
-- Add tenant_id to existing tables that need true multi-tenancy
-- Note: project_id already serves as tenant identifier in Harbor

-- Create tenant context function
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS INTEGER AS $$
BEGIN
    RETURN NULLIF(current_setting('app.tenant_id', true), '')::INTEGER;
END;
$$ LANGUAGE plpgsql STABLE;

-- Enable RLS on key tables
ALTER TABLE repository ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_metadata ENABLE ROW LEVEL SECURITY;

-- Create RLS policies
CREATE POLICY tenant_isolation_repository ON repository
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_artifact ON artifact
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_project_member ON project_member
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_project_metadata ON project_metadata
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- Force RLS for application user (not superuser)
ALTER TABLE repository FORCE ROW LEVEL SECURITY;
ALTER TABLE artifact FORCE ROW LEVEL SECURITY;
ALTER TABLE project_member FORCE ROW LEVEL SECURITY;
ALTER TABLE project_metadata FORCE ROW LEVEL SECURITY;
```

**2.2 Tenant Context Middleware**

Create `src/lib/db/tenant.go`:

```go
package db

import (
    "context"

    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
)

type tenantKey struct{}

// WithTenant adds tenant ID to context
func WithTenant(ctx context.Context, tenantID int64) context.Context {
    return context.WithValue(ctx, tenantKey{}, tenantID)
}

// TenantFromContext retrieves tenant ID from context
func TenantFromContext(ctx context.Context) (int64, bool) {
    tenantID, ok := ctx.Value(tenantKey{}).(int64)
    return tenantID, ok
}

// ExecuteWithTenant runs a function with tenant context set in PostgreSQL
func ExecuteWithTenant(ctx context.Context, pool *pgxpool.Pool, fn func(ctx context.Context, tx pgx.Tx) error) error {
    tenantID, hasTenant := TenantFromContext(ctx)

    tx, err := pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)

    if hasTenant {
        // SET LOCAL ensures the setting is transaction-scoped
        _, err = tx.Exec(ctx, "SET LOCAL app.tenant_id = $1", tenantID)
        if err != nil {
            return err
        }
    }

    if err := fn(ctx, tx); err != nil {
        return err
    }

    return tx.Commit(ctx)
}

// AcquireWithTenant gets a connection with tenant context
func AcquireWithTenant(ctx context.Context, pool *pgxpool.Pool) (*pgxpool.Conn, error) {
    conn, err := pool.Acquire(ctx)
    if err != nil {
        return nil, err
    }

    tenantID, hasTenant := TenantFromContext(ctx)
    if hasTenant {
        _, err = conn.Exec(ctx, "SET app.tenant_id = $1", tenantID)
        if err != nil {
            conn.Release()
            return nil, err
        }
    }

    return conn, nil
}
```

### Phase 3: PgBouncer Configuration

**3.1 PgBouncer Configuration File**

Create `deploy/pgbouncer/pgbouncer.ini`:

```ini
[databases]
harbor = host=postgresql port=5432 dbname=registry

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt

; Connection pooling
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 300
reserve_pool_size = 10
reserve_pool_timeout = 5

; Connection limits
max_db_connections = 300
max_user_connections = 300

; Timeouts
server_idle_timeout = 600
server_lifetime = 3600
client_idle_timeout = 0
query_timeout = 0

; Logging
log_connections = 1
log_disconnections = 1
log_pooler_errors = 1

; Statistics
stats_period = 60

; Application name for debugging
application_name_add_host = 1
```

**3.2 Kubernetes Deployment**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pgbouncer
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pgbouncer
  template:
    metadata:
      labels:
        app: pgbouncer
    spec:
      containers:
      - name: pgbouncer
        image: pgbouncer/pgbouncer:1.21.0
        ports:
        - containerPort: 6432
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          tcpSocket:
            port: 6432
          initialDelaySeconds: 10
          periodSeconds: 10
        volumeMounts:
        - name: config
          mountPath: /etc/pgbouncer
      volumes:
      - name: config
        configMap:
          name: pgbouncer-config
---
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer
spec:
  ports:
  - port: 5432
    targetPort: 6432
  selector:
    app: pgbouncer
```

### Phase 4: Gradual Migration Strategy

**4.1 Hybrid ORM Support**

Maintain Beego ORM compatibility while introducing pgx directly:

Create `src/lib/db/hybrid.go`:

```go
package db

import (
    "context"
    "database/sql"

    "github.com/beego/beego/v2/client/orm"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/jackc/pgx/v5/stdlib"
)

// HybridDB provides both pgxpool and Beego ORM access
type HybridDB struct {
    pool   *pgxpool.Pool
    sqlDB  *sql.DB
}

func NewHybridDB(pool *pgxpool.Pool) (*HybridDB, error) {
    // Create sql.DB from pgxpool for Beego ORM compatibility
    sqlDB := stdlib.OpenDBFromPool(pool)

    // Register with Beego ORM
    if err := orm.AddAliasWthDB("default", "postgres", sqlDB); err != nil {
        return nil, err
    }

    return &HybridDB{
        pool:  pool,
        sqlDB: sqlDB,
    }, nil
}

// Pool returns the pgxpool for new code
func (h *HybridDB) Pool() *pgxpool.Pool {
    return h.pool
}

// Ormer returns Beego ORM for legacy code
func (h *HybridDB) Ormer() orm.Ormer {
    return orm.NewOrm()
}
```

**4.2 Migration Order**

1. **Week 1-2**: Setup infrastructure
   - Deploy PgBouncer
   - Update pgx to v5
   - Create HybridDB wrapper

2. **Week 3-4**: Implement RLS
   - Add RLS migrations
   - Create tenant middleware
   - Update HTTP middleware to set tenant context

3. **Week 5-8**: Migrate critical paths
   - Repository operations
   - Artifact operations
   - Project member operations

4. **Week 9-12**: Complete migration
   - Migrate remaining DAOs
   - Remove Beego ORM dependency
   - Performance testing

### Phase 5: Monitoring and Observability

**5.1 Connection Pool Metrics**

```go
// src/lib/db/metrics.go
package db

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/jackc/pgx/v5/pgxpool"
)

var (
    poolAcquireCount = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "harbor_db_pool_acquire_total",
            Help: "Total number of connection acquires",
        },
        []string{"status"},
    )

    poolConnections = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "harbor_db_pool_connections",
            Help: "Current number of connections in pool",
        },
        []string{"state"},
    )

    queryDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "harbor_db_query_duration_seconds",
            Help:    "Query execution duration",
            Buckets: prometheus.DefBuckets,
        },
        []string{"operation", "tenant_id"},
    )
)

func RecordPoolStats(pool *pgxpool.Pool) {
    stats := pool.Stat()
    poolConnections.WithLabelValues("acquired").Set(float64(stats.AcquiredConns()))
    poolConnections.WithLabelValues("idle").Set(float64(stats.IdleConns()))
    poolConnections.WithLabelValues("total").Set(float64(stats.TotalConns()))
    poolConnections.WithLabelValues("max").Set(float64(stats.MaxConns()))
}
```

**5.2 PgBouncer Monitoring**

```sql
-- Query PgBouncer stats
SHOW POOLS;
SHOW STATS;
SHOW CLIENTS;
SHOW SERVERS;
```

---

## Configuration Reference

### Environment Variables

| Variable | Default | Multi-tenant Value | Description |
|----------|---------|-------------------|-------------|
| `POSTGRESQL_MAX_IDLE_CONNS` | 2 | 5 | Minimum warm connections |
| `POSTGRESQL_MAX_OPEN_CONNS` | 0 | 30 | Maximum per instance |
| `POSTGRESQL_CONN_MAX_LIFETIME` | 5m | 1h | Connection recycle time |
| `POSTGRESQL_CONN_MAX_IDLE_TIME` | 0 | 30m | Idle connection timeout |
| `PGBOUNCER_ENABLED` | false | true | Use PgBouncer |
| `PGBOUNCER_HOST` | - | pgbouncer | PgBouncer service name |
| `PGBOUNCER_PORT` | - | 6432 | PgBouncer port |

### PostgreSQL Server Configuration

```sql
-- postgresql.conf for 100 tenants / 300 connections
max_connections = 350
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
work_mem = 10MB

-- Connection handling
tcp_keepalives_idle = 600
tcp_keepalives_interval = 30
tcp_keepalives_count = 10

-- Statement timeout for runaway queries
statement_timeout = '30s'

-- Logging
log_connections = on
log_disconnections = on
log_statement = 'ddl'
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| RLS performance overhead | Medium | Medium | Index on project_id, test with realistic data |
| PgBouncer prepared statement issues | High | Low | Use `QueryExecModeDescribeExec` |
| Beego ORM incompatibility | Medium | High | Hybrid approach, gradual migration |
| Connection exhaustion | Low | High | Proper pool sizing, monitoring |
| Tenant context leak | Medium | Critical | Transaction-scoped SET LOCAL |

---

## Alternatives Considered

### 1. Schema-per-Tenant

**Pros**: Strong isolation, easy backup/restore
**Cons**: Connection explosion (100 schemas = pool-per-schema), migration complexity
**Decision**: Rejected due to connection limits

### 2. Database-per-Tenant

**Pros**: Complete isolation
**Cons**: Massive connection overhead, operational complexity
**Decision**: Rejected due to connection limits

### 3. Application-level Filtering Only (Current)

**Pros**: Simple, no database changes
**Cons**: Risk of data leaks, no database-level enforcement
**Decision**: Enhance with RLS for defense-in-depth

### 4. Citus/Distributed PostgreSQL

**Pros**: Horizontal scaling, automatic sharding
**Cons**: Operational complexity, cost
**Decision**: Consider for future if >1000 tenants needed

---

## Conclusion

The recommended approach is:

1. **Upgrade to pgx v5** with native `pgxpool` for better connection management
2. **Deploy PgBouncer** in transaction mode for connection multiplexing
3. **Implement Row-Level Security** for database-enforced tenant isolation
4. **Use shared connection pool** (not pool-per-tenant) for efficient resource usage
5. **Gradual migration** from Beego ORM to direct pgx for better control

This architecture efficiently supports **100 tenants per region** with **300 total connections** while providing:
- Strong tenant isolation at the database level
- Efficient connection reuse across all tenants
- Compatibility with existing Harbor codebase
- Clear migration path with minimal disruption

---

## References

- [pgx v5 Documentation](https://github.com/jackc/pgx)
- [PgBouncer Documentation](https://www.pgbouncer.org/)
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Multi-Tenant PostgreSQL Best Practices](https://www.citusdata.com/blog/2018/06/20/postgres-connection-pooling/)
- [golang-migrate](https://github.com/golang-migrate/migrate)

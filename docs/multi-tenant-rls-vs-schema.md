# RLS vs Schema-per-Tenant: Code Change Analysis

## Tables Requiring Tenant Isolation

Based on schema analysis, these tables have `project_id` and need tenant isolation:

| Table | project_id Column | Current Filtering | Raw SQL Usage |
|-------|-------------------|-------------------|---------------|
| `repository` | ✅ | ORM query | Minimal |
| `artifact` | ✅ | ORM query | Some complex joins |
| `project_member` | ✅ | Raw SQL | Heavy |
| `project_metadata` | ✅ | ORM query | Minimal |
| `audit_log` | ✅ | ORM query | Minimal |
| `audit_log_ext` | ✅ | ORM query | Minimal |
| `robot` | ✅ | Raw SQL | DELETE |
| `blob` (via project_blob) | ✅ | Raw SQL | Complex joins |
| `notification_policy` | ✅ | ORM query | Minimal |
| `cve_allowlist` | ✅ | ORM query | Minimal |
| `immutable_tag_rule` | ✅ | ORM query | Minimal |
| `harbor_label` | ✅ (optional) | ORM query | Minimal |

---

## Approach 1: Row-Level Security (RLS)

### How It Works

```sql
-- Set tenant context per transaction
SET LOCAL app.tenant_id = 123;

-- All queries automatically filtered
SELECT * FROM repository;  -- Only returns tenant 123's repos
```

### Database Migration

```sql
-- 0200_rls_multi_tenant.up.sql

-- Tenant context function
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS INTEGER AS $$
BEGIN
    RETURN NULLIF(current_setting('app.tenant_id', true), '')::INTEGER;
END;
$$ LANGUAGE plpgsql STABLE;

-- Enable RLS on tenant-scoped tables
ALTER TABLE repository ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE robot ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_blob ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE immutable_tag_rule ENABLE ROW LEVEL SECURITY;

-- Create policies (example for repository)
CREATE POLICY tenant_isolation ON repository
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- Force RLS for app user
ALTER TABLE repository FORCE ROW LEVEL SECURITY;
```

### Go Code Changes

**1. Tenant Middleware (NEW FILE)**

```go
// src/lib/orm/tenant.go
package orm

import "context"

type tenantKey struct{}

func WithTenantID(ctx context.Context, projectID int64) context.Context {
    return context.WithValue(ctx, tenantKey{}, projectID)
}

func TenantIDFromContext(ctx context.Context) (int64, bool) {
    id, ok := ctx.Value(tenantKey{}).(int64)
    return id, ok
}
```

**2. Transaction Wrapper (MODIFY src/lib/orm/orm.go)**

```go
// Add to existing WithTransaction function
func WithTransaction(ctx context.Context, f func(ctx context.Context) error) error {
    ormer, err := FromContext(ctx)
    if err != nil {
        return err
    }

    tx, err := ormer.Begin()
    if err != nil {
        return err
    }

    // NEW: Set tenant context if present
    if tenantID, ok := TenantIDFromContext(ctx); ok {
        _, err = tx.Raw("SET LOCAL app.tenant_id = ?", tenantID).Exec()
        if err != nil {
            tx.Rollback()
            return err
        }
    }

    // ... rest of transaction logic
}
```

**3. DAO Changes: NONE Required**

Existing DAOs continue to work unchanged:

```go
// src/pkg/repository/dao/dao.go - NO CHANGES
func (d *dao) List(ctx context.Context, query *q.Query) ([]*model.RepoRecord, error) {
    repositories := []*model.RepoRecord{}
    qs, err := orm.QuerySetter(ctx, &model.RepoRecord{}, query)
    // RLS automatically filters by project_id
    if _, err = qs.All(&repositories); err != nil {
        return nil, err
    }
    return repositories, nil
}
```

**4. Raw SQL: Minimal Changes**

```go
// Before (src/pkg/member/dao/dao.go:120)
sql := "SELECT COUNT(1) FROM project_member WHERE project_id = ?"

// After - RLS handles filtering, but explicit is fine
sql := "SELECT COUNT(1) FROM project_member WHERE project_id = ?"
// Works the same - RLS is additive protection
```

### Files to Modify for RLS

| File | Change Type | Effort |
|------|-------------|--------|
| `src/lib/orm/tenant.go` | NEW | Low |
| `src/lib/orm/orm.go` | Modify transaction | Low |
| `src/server/middleware/tenant.go` | NEW - extract tenant from request | Medium |
| `make/migrations/postgresql/0200_*.sql` | NEW - RLS policies | Medium |
| DAOs | **NONE** | None |

**Total: ~5 files, low-medium effort**

---

## Approach 2: Schema-per-Tenant

### How It Works

```sql
-- Each tenant has own schema
CREATE SCHEMA tenant_123;
CREATE TABLE tenant_123.repository (...);

-- Set search_path per connection
SET search_path TO tenant_123, public;

-- Queries use tenant's tables
SELECT * FROM repository;  -- Uses tenant_123.repository
```

### Database Migration

```sql
-- For EACH new tenant:
CREATE SCHEMA tenant_${TENANT_ID};

-- Copy all table definitions to new schema
CREATE TABLE tenant_${TENANT_ID}.repository (LIKE public.repository INCLUDING ALL);
CREATE TABLE tenant_${TENANT_ID}.artifact (LIKE public.artifact INCLUDING ALL);
-- ... 15+ more tables

-- Copy all indexes, constraints, triggers
-- This is complex and error-prone
```

### Go Code Changes

**1. Schema Manager (NEW FILE)**

```go
// src/lib/orm/schema.go
package orm

import (
    "context"
    "fmt"
)

func SetTenantSchema(ctx context.Context, tenantID int64) error {
    ormer, err := FromContext(ctx)
    if err != nil {
        return err
    }

    schema := fmt.Sprintf("tenant_%d", tenantID)
    _, err = ormer.Raw("SET search_path TO ?, public", schema).Exec()
    return err
}

func ResetSchema(ctx context.Context) error {
    ormer, err := FromContext(ctx)
    if err != nil {
        return err
    }
    _, err = ormer.Raw("SET search_path TO public").Exec()
    return err
}
```

**2. Connection Acquire/Release Hooks**

```go
// Must set schema on every connection acquire
// Must reset schema on every connection release
// Problem: Beego ORM doesn't expose these hooks easily
```

**3. Model Changes - REMOVE project_id**

```go
// src/pkg/repository/model/model.go - MUST MODIFY
type RepoRecord struct {
    RepositoryID int64     `orm:"pk;auto;column(repository_id)"`
    Name         string    `orm:"column(name)"`
    // ProjectID    int64  // REMOVED - schema provides isolation
    Description  string    `orm:"column(description)"`
    // ...
}
```

**4. DAO Changes - REMOVE project_id filtering**

```go
// src/pkg/repository/dao/dao.go - MUST MODIFY
func (d *dao) List(ctx context.Context, query *q.Query) ([]*model.RepoRecord, error) {
    // Must ensure search_path is set before query
    if err := orm.SetTenantSchema(ctx, tenantID); err != nil {
        return nil, err
    }
    defer orm.ResetSchema(ctx)

    // Query no longer needs project_id filter
    // But how do we get tenantID here? Context propagation needed
}
```

**5. All Raw SQL - MUST MODIFY**

```go
// src/pkg/member/dao/dao.go - MUST MODIFY ALL RAW SQL

// Before
sql := "SELECT COUNT(1) FROM project_member WHERE project_id = ?"

// After - remove project_id, but table is now in tenant schema
sql := "SELECT COUNT(1) FROM project_member"
// Must ensure search_path is set before this runs
```

**6. Cross-Tenant Queries - BROKEN**

```go
// Admin queries across tenants become complex
// Before (single schema):
sql := "SELECT COUNT(*) FROM repository"  // All repos

// After (schema per tenant):
sql := `
    SELECT SUM(cnt) FROM (
        SELECT COUNT(*) as cnt FROM tenant_1.repository
        UNION ALL
        SELECT COUNT(*) as cnt FROM tenant_2.repository
        -- ... repeat for all 100 tenants
    ) t
`
// Or: Dynamic SQL iterating over all schemas
```

### Files to Modify for Schema-per-Tenant

| File | Change Type | Effort |
|------|-------------|--------|
| `src/lib/orm/schema.go` | NEW | Medium |
| `src/lib/orm/orm.go` | Major changes for schema handling | High |
| `src/pkg/repository/model/model.go` | Remove project_id | Medium |
| `src/pkg/artifact/model/model.go` | Remove project_id | Medium |
| `src/pkg/*/dao/dao.go` (15+ files) | Remove project_id filters | High |
| `src/pkg/member/dao/dao.go` | Rewrite all raw SQL | High |
| `src/pkg/blob/dao/dao.go` | Rewrite complex joins | High |
| `src/server/middleware/*.go` | Schema switching | High |
| Migration tooling | Per-schema migrations | Very High |

**Total: 30+ files, very high effort**

### Schema-per-Tenant: Connection Pool Problem

From pgx discussions, the critical issue:

```go
// Prepared statements are schema-specific
conn.Prepare("get_repos", "SELECT * FROM repository")

// Tenant A uses schema tenant_1
SET search_path TO tenant_1;
conn.Query("get_repos")  // Works

// Tenant B acquires same connection, uses schema tenant_2
SET search_path TO tenant_2;
conn.Query("get_repos")  // FAILS or returns wrong data!
// Prepared statement was compiled for tenant_1.repository
```

**Solutions (all have downsides):**

1. **Disable prepared statements** - Lose performance benefit
2. **Pool per tenant** - 100 tenants = 100 pools = connection explosion
3. **Re-prepare on schema change** - Complex, error-prone
4. **Always use explicit schema** - `SELECT * FROM tenant_1.repository` defeats the purpose

---

## Comparison Summary

| Aspect | RLS | Schema-per-Tenant |
|--------|-----|-------------------|
| **Code changes** | ~5 files | 30+ files |
| **DAO changes** | None | All DAOs |
| **Raw SQL changes** | None | All raw SQL |
| **Model changes** | None | Remove project_id |
| **Prepared statements** | Work across tenants | Break on schema switch |
| **Connection reuse** | Full reuse | Limited/complex |
| **Cross-tenant queries** | Simple | Very complex |
| **Migrations** | Single schema | Per-tenant schemas |
| **New tenant setup** | INSERT row | CREATE SCHEMA + tables |
| **Backup/restore** | Standard | Per-schema complexity |
| **pgxpool compatibility** | Native | Requires workarounds |

---

## Connection Pool Behavior

### RLS with pgxpool

```go
// Connection acquired from pool
conn := pool.Acquire(ctx)

// Tenant A's request
tx1, _ := conn.Begin(ctx)
tx1.Exec(ctx, "SET LOCAL app.tenant_id = $1", 1)
tx1.Query(ctx, "SELECT * FROM repository")  // Filtered to tenant 1
tx1.Commit(ctx)
// SET LOCAL automatically resets after transaction

// Same connection, Tenant B's request
tx2, _ := conn.Begin(ctx)
tx2.Exec(ctx, "SET LOCAL app.tenant_id = $1", 2)
tx2.Query(ctx, "SELECT * FROM repository")  // Filtered to tenant 2
tx2.Commit(ctx)

conn.Release()  // Connection clean, reusable by any tenant
```

### Schema-per-Tenant with pgxpool

```go
// Connection acquired from pool
conn := pool.Acquire(ctx)

// Tenant A's request
conn.Exec(ctx, "SET search_path TO tenant_1, public")
conn.Query(ctx, "SELECT * FROM repository")  // tenant_1.repository
// search_path persists on connection!

// Same connection, Tenant B's request
// PROBLEM: search_path still tenant_1 unless explicitly changed
conn.Exec(ctx, "SET search_path TO tenant_2, public")  // Must do this
// Any prepared statements from tenant_1 are now invalid

conn.Release()
// Connection has tenant_2 search_path - next acquire may be tenant_3
// Must reset or track which tenant connection is configured for
```

---

## Recommendation

**Use RLS** for Harbor multi-tenancy because:

1. **Minimal code changes** - DAOs unchanged, ORM queries unchanged
2. **Full connection reuse** - `SET LOCAL` is transaction-scoped, auto-resets
3. **Prepared statements work** - Same schema, same query plans
4. **Existing project_id** - Already used for filtering, RLS adds enforcement
5. **Simple operations** - Backup, migrate, add tenant = standard operations
6. **Defense in depth** - RLS enforces at DB level even if app has bugs

Schema-per-tenant would require:
- Rewriting 30+ files
- Removing project_id from all models
- Complex connection pool management
- Breaking prepared statement caching
- Complex cross-tenant admin queries
- Per-schema migration tooling

**The effort difference is roughly 10x, with RLS being simpler and more compatible with pgxpool.**

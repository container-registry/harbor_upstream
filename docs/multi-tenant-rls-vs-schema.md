# RLS vs Schema-per-Tenant: Code Change Analysis

## Multi-Tenancy Model

```
┌─────────────────────────────────────────────────────────┐
│  Shared Harbor Instance                                  │
│                                                          │
│  ┌─────────────────────┐  ┌─────────────────────┐       │
│  │ Tenant A (Acme)     │  │ Tenant B (Globex)   │       │
│  │ tenant_id = 1       │  │ tenant_id = 2       │       │
│  │                     │  │                     │       │
│  │  ┌───────┐ ┌──────┐ │  │  ┌───────┐         │       │
│  │  │Proj 1 │ │Proj 2│ │  │  │Proj 3 │         │       │
│  │  └───────┘ └──────┘ │  │  └───────┘         │       │
│  └─────────────────────┘  └─────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

**Key insight**: `project_id` is NOT the tenant. A tenant can have multiple projects.

---

## Schema Changes Required

### New Tenant Table

```sql
CREATE TABLE tenant (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    slug VARCHAR(63) NOT NULL UNIQUE,  -- for subdomain routing
    status VARCHAR(20) DEFAULT 'active',
    metadata JSONB DEFAULT '{}'
);
```

### Tables Requiring tenant_id Column

| Category | Tables | Notes |
|----------|--------|-------|
| **Core** | `harbor_user`, `user_group`, `project` | Top-level tenant resources |
| **Project children** | `project_member`, `project_metadata`, `repository` | Denormalized for RLS performance |
| **Artifacts** | `artifact`, `blob`, `project_blob`, `tag` | Container image data |
| **Security** | `robot`, `cve_allowlist`, `scan_report` | Access and vulnerability |
| **Audit** | `audit_log`, `access_log` | Logging |
| **Policies** | `notification_policy`, `replication_policy`, `retention_policy`, `immutable_tag_rule` | Configuration |
| **Jobs** | `admin_job`, `execution`, `task`, `job_log`, `schedule` | Background processing |
| **Other** | `registry`, `quota`, `harbor_label` | Various features |

### System Tables (NO tenant_id)

| Table | Reason |
|-------|--------|
| `access` | System constants |
| `role` | System constants |
| `properties` | Global configuration |
| `schema_migrations` | Migration tracking |
| `oidc_user` | Identity federation (cross-tenant) |

---

## Approach 1: RLS with tenant_id (Recommended)

### How It Works

```sql
-- Set tenant context per transaction
BEGIN;
SET LOCAL app.tenant_id = 123;

-- All queries automatically filtered by RLS policy
SELECT * FROM project;       -- Only tenant 123's projects
SELECT * FROM repository;    -- Only tenant 123's repos
COMMIT;
-- SET LOCAL automatically resets
```

### Migration Required

```sql
-- Add tenant_id to ALL tenant-scoped tables
ALTER TABLE project ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
ALTER TABLE repository ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
-- ... (20+ tables)

-- Create RLS policies
CREATE POLICY tenant_isolation ON project
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);
```

### Go Code Changes

**1. New Tenant Model**

```go
// src/pkg/tenant/model/model.go (NEW)
type Tenant struct {
    ID        int64     `orm:"pk;auto;column(id)"`
    Name      string    `orm:"column(name)"`
    Slug      string    `orm:"column(slug)"`
    Status    string    `orm:"column(status)"`
    CreatedAt time.Time `orm:"column(creation_time)"`
}
```

**2. Update ALL Models with tenant_id**

```go
// src/pkg/project/models/project.go (MODIFY)
type Project struct {
    ProjectID   int64  `orm:"pk;auto;column(project_id)"`
    TenantID    int64  `orm:"column(tenant_id)"`  // ADD THIS
    OwnerID     int    `orm:"column(owner_id)"`
    Name        string `orm:"column(name)"`
    // ...
}

// src/pkg/repository/model/model.go (MODIFY)
type RepoRecord struct {
    RepositoryID int64  `orm:"pk;auto;column(repository_id)"`
    TenantID     int64  `orm:"column(tenant_id)"`  // ADD THIS
    Name         string `orm:"column(name)"`
    ProjectID    int64  `orm:"column(project_id)"`
    // ...
}

// ... repeat for 20+ models
```

**3. Tenant Context Middleware**

```go
// src/server/middleware/tenant.go (NEW)
func TenantMiddleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract tenant from subdomain, header, or JWT
            tenantID := extractTenantID(r)

            ctx := context.WithValue(r.Context(), TenantKey, tenantID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func extractTenantID(r *http.Request) int64 {
    // Option 1: Subdomain (acme.harbor.example.com)
    host := r.Host
    if strings.Contains(host, ".") {
        slug := strings.Split(host, ".")[0]
        tenant, _ := tenantDAO.GetBySlug(slug)
        return tenant.ID
    }

    // Option 2: Header (X-Tenant-ID: 123)
    if id := r.Header.Get("X-Tenant-ID"); id != "" {
        return parseID(id)
    }

    // Option 3: JWT claim
    if claims := jwt.FromContext(r.Context()); claims != nil {
        return claims.TenantID
    }

    return 0
}
```

**4. Transaction Wrapper (MODIFY)**

```go
// src/lib/orm/orm.go (MODIFY)
func WithTransaction(ctx context.Context, f func(ctx context.Context) error) error {
    o, err := FromContext(ctx)
    if err != nil {
        return err
    }

    tx, err := o.Begin()
    if err != nil {
        return err
    }

    // Set tenant context for RLS
    if tenantID := TenantFromContext(ctx); tenantID > 0 {
        if _, err := tx.Raw("SET LOCAL app.tenant_id = ?", tenantID).Exec(); err != nil {
            tx.Rollback()
            return err
        }
    }

    // ... rest of transaction
}
```

**5. DAO Changes - Add tenant_id to Creates**

```go
// src/pkg/project/dao/dao.go (MODIFY)
func (d *dao) Create(ctx context.Context, project *models.Project) (int64, error) {
    // Must set tenant_id on create
    if project.TenantID == 0 {
        project.TenantID = TenantFromContext(ctx)
    }

    o, err := orm.FromContext(ctx)
    if err != nil {
        return 0, err
    }
    return o.Insert(project)
}

// Queries don't need changes - RLS handles filtering
func (d *dao) List(ctx context.Context, query *q.Query) ([]*models.Project, error) {
    // RLS automatically filters by tenant_id
    // No code change needed here!
}
```

### Files to Modify for RLS

| Category | Files | Change |
|----------|-------|--------|
| **New** | `src/pkg/tenant/model/model.go` | Tenant model |
| **New** | `src/pkg/tenant/dao/dao.go` | Tenant DAO |
| **New** | `src/server/middleware/tenant.go` | Extract tenant from request |
| **Modify** | `src/lib/orm/orm.go` | Set tenant in transactions |
| **Modify** | `src/pkg/*/model/*.go` (20+ files) | Add TenantID field |
| **Modify** | `src/pkg/*/dao/*.go` (20+ files) | Set TenantID on create |
| **Migration** | `0190_multi_tenant.up.sql` | Add columns, RLS policies |

**Queries (SELECT) - NO changes needed** (RLS handles filtering)

---

## Approach 2: Schema-per-Tenant

### How It Works

```sql
-- Each tenant has own schema
CREATE SCHEMA tenant_123;
CREATE TABLE tenant_123.project (...);

-- Set search_path per connection
SET search_path TO tenant_123, public;
SELECT * FROM project;  -- Uses tenant_123.project
```

### Problems

| Issue | Impact |
|-------|--------|
| **Prepared statement cache** | Statements compiled for one schema don't work for another |
| **Connection reuse** | Must track which schema each connection is configured for |
| **100 tenants = 100 schemas** | Schema proliferation |
| **Migrations** | Must run on every schema |
| **Cross-tenant queries** | Admin queries need dynamic SQL |

### From pgx Discussion #2384

> "Prepared statements don't automatically recompile across tenant schema changes... RLS might be superior to schema-per-tenant for connection reuse efficiency."

---

## Comparison Summary

| Aspect | RLS (tenant_id) | Schema-per-Tenant |
|--------|-----------------|-------------------|
| **New column** | Yes (tenant_id on all tables) | No |
| **Model changes** | Add TenantID field (20+ files) | No model changes |
| **DAO create changes** | Set TenantID (20+ files) | Set search_path |
| **DAO query changes** | **NONE** (RLS filters) | Schema context needed |
| **Prepared statements** | Shared across tenants | Per-schema (no reuse) |
| **Connection pool** | Standard pgxpool | Complex schema tracking |
| **New tenant setup** | INSERT INTO tenant | CREATE SCHEMA + all tables |
| **Migrations** | Single schema | Per-tenant schema |
| **Cross-tenant admin** | `SET LOCAL app.tenant_id = NULL` | Dynamic SQL |

---

## Tenant Selection at Query Time

### HTTP Request Flow

```
Request: GET https://acme.harbor.example.com/api/v2/projects
         X-Tenant-ID: 123 (optional header)
         Authorization: Bearer <jwt with tenant_id claim>

┌─────────────────────────────────────────────────────────────┐
│  1. TenantMiddleware extracts tenant_id                     │
│     - From subdomain: acme → lookup tenant by slug          │
│     - From header: X-Tenant-ID                              │
│     - From JWT: tenant_id claim                             │
│                                                             │
│  2. Add to context: ctx = WithTenant(ctx, 123)              │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  3. DAO operation                                           │
│     tx.Begin()                                              │
│     tx.Exec("SET LOCAL app.tenant_id = 123")                │
│                                                             │
│  4. Query executes with RLS                                 │
│     SELECT * FROM project                                   │
│     -- RLS policy: WHERE tenant_id = 123                    │
│                                                             │
│  5. Commit releases connection (SET LOCAL auto-resets)      │
└─────────────────────────────────────────────────────────────┘
```

### Code Example

```go
// Handler
func (h *ProjectHandler) List(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    // tenant_id already in context from middleware

    projects, err := h.projectCtl.List(ctx, query)
    // Returns only this tenant's projects
}

// Controller - no tenant logic needed
func (c *controller) List(ctx context.Context, query *q.Query) ([]*models.Project, error) {
    return c.projectMgr.List(ctx, query)
}

// Manager - no tenant logic needed
func (m *manager) List(ctx context.Context, query *q.Query) ([]*models.Project, error) {
    return m.dao.List(ctx, query)
}

// DAO - no tenant logic needed (RLS handles it)
func (d *dao) List(ctx context.Context, query *q.Query) ([]*models.Project, error) {
    qs, _ := orm.QuerySetter(ctx, &models.Project{}, query)
    var projects []*models.Project
    _, err := qs.All(&projects)  // RLS filters automatically
    return projects, err
}
```

---

## Recommendation

**Use RLS with tenant_id column** because:

1. **Queries unchanged** - RLS is transparent to existing query logic
2. **Connection reuse** - `SET LOCAL` is transaction-scoped, auto-resets
3. **Prepared statements shared** - Same schema, same query plans
4. **Simple operations** - Standard backup, migration, admin
5. **Defense in depth** - Database enforces isolation even if app has bugs

### Effort Estimate

| Task | Files | Complexity |
|------|-------|------------|
| Add tenant_id to models | ~25 | Low (mechanical) |
| Add tenant_id to creates | ~25 | Low (mechanical) |
| Tenant middleware | 1 | Medium |
| Transaction wrapper | 1 | Low |
| Migration SQL | 1 | Medium |
| **Total** | ~53 files | **Medium overall** |

Most changes are mechanical "add TenantID field" - the query logic stays the same.

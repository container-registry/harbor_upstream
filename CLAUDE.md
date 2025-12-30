# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Harbor is a CNCF graduated open-source container registry that stores, signs, and scans container images and Helm charts. This is a fork ("Harbor Next") with continuous delivery, multi-architecture support, and Docker Distribution V3.

## Technology Stack

### Backend
- **Go 1.24.6+** - Main backend language
- **Beego v2** - Web framework with MVC pattern
- **PostgreSQL** - Metadata storage
- **Redis/Valkey** - Caching and job queue
- **go-swagger** - API code generation from OpenAPI spec
- **Casbin** - RBAC authorization
- **golang-migrate** - Database migrations

### Frontend
- **Angular 16** - SPA framework
- **Clarity Design System** - UI components
- **TypeScript** - Type-safe JavaScript

## Essential Commands

### Build & Development

**IMPORTANT**: DO NOT use `make` commands except for migrations. Use direct commands instead.

**Build:**
```bash
cd src && go build ./...                    # Build all Go code
cd src/core && go build                     # Build core service
cd src/jobservice && go build               # Build job service
cd src/registryctl && go build              # Build registry controller
```

**Linting (CRITICAL):**
```bash
cd src && golangci-lint run                 # ALWAYS use this directly, NOT task wrappers
cd src && golangci-lint run ./...           # Lint all packages
```

**Testing:**
```bash
cd src && go test ./...                     # Run all Go tests
cd src && go test -v -race ./pkg/...        # Test specific package with race detection
cd src/portal && npm run test               # Run frontend tests
cd src/portal && npm run lint               # Lint frontend code
```

**Database:**
- Migrations are in `make/migrations/postgresql/`
- Format: `XXXX_version_description.up.sql`
- Use golang-migrate for running migrations

**Frontend Development:**
```bash
cd src/portal && npm install                # Install dependencies
cd src/portal && npm start                  # Start dev server (https://localhost:4200)
cd src/portal && npm run build              # Build for production
cd src/portal && npm run release            # Production build
```

## Architecture

Harbor consists of multiple services:

### Harbor Core (src/core/main.go)
- Central API server and orchestrator
- REST API at `/api/v2.0/*` (auto-generated from OpenAPI spec)
- Docker Registry V2 API proxy at `/v2/*`
- Authentication (DB, LDAP, OIDC, UAA)
- RBAC authorization via Casbin
- Serves Portal static files in production
- Port: 8080

### JobService (src/jobservice/main.go)
- Asynchronous job execution using forked gocraft/work
- Redis-backed job queue
- Job types: GC, replication, scanning, retention, preheat, audit purge
- Port: 8888

### RegistryCtl (src/registryctl/main.go)
- Low-level storage operations
- Direct blob/manifest deletion bypassing Registry API
- Wraps docker/distribution storage.Vacuum
- Port: 8080 (internal)

### Portal (src/portal/)
- Angular 16 + Clarity Design System
- Development: port 4200
- Production: served by Core at port 8080

### Docker Registry
- Implementation: distribution/distribution
- Docker Registry V2 API specification
- Storage backends: filesystem, S3, GCS, Azure, Swift, OSS
- Port: 5000

## Code Organization

### Layered Architecture
```
API Layer         → src/server/v2.0/handler/     (auto-generated)
Controller Layer  → src/controller/              (business logic)
Package Layer     → src/pkg/                     (DAO/data access)
Library Layer     → src/lib/                     (ORM, cache, logging)
```

### Key Directories
- `src/controller/` - Business logic (artifact, project, scan, replication)
- `src/pkg/` - Data access layer with DAO interfaces
- `src/server/` - API server, routing, middleware
- `src/lib/orm/` - Database abstraction layer
- `src/lib/cache/` - Multi-backend caching
- `src/common/` - Shared utilities
- `src/testing/` - Mock implementations

## Critical Development Guidelines

### API Changes
1. ALWAYS update `api/v2.0/swagger.yaml` first
2. Run `make gen_apis` to regenerate server code
3. Implement handlers in `src/server/v2.0/handler/`
4. Never manually edit auto-generated files in `src/server/v2.0/restapi/`

### Database Migrations
- New migrations go in `make/migrations/postgresql/`
- Use sequential numbering: `XXXX_version_description.up.sql`
- Test migrations with fresh database before committing

### Code Quality
- **Linting**: Use `cd src && golangci-lint run` directly (NOT make/task wrappers)
- **Enabled linters**: bodyclose, errcheck, goheader, govet, ineffassign, misspell, revive, staticcheck, whitespace
- **Formatters**: gofmt (no simplify), goimports with local prefix `github.com/goharbor/harbor`
- **Testing**: Use testify/mock for controller/manager tests
- **Mock Generation**: Configure in `src/.mockery.yaml`, run `make gen_mocks`

### Commit Requirements
- MUST include `Signed-off-by` line (use `git commit -s`)
- Follow conventional commit messages (concise, 1-2 sentences)
- Reference related issues in commit message
- DCO (Developer Certificate of Origin) check enforced

### Code Style
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Limit line width to 120 characters
- Use `controller/manager/dao` programming model
- Stateless design, fail loudly, sanitize inputs

## Service Communication

### Inter-Service Protocols
- Core ↔ Registry: HTTP (Docker V2 API), Basic/Token auth
- Core ↔ JobService: HTTP, `CORE_SECRET` auth
- Core ↔ RegistryCtl: HTTP, `JOBSERVICE_SECRET` auth
- Core/JobService ↔ PostgreSQL: TCP, password auth
- Core/JobService ↔ Redis: TCP, optional password

### Data Storage
- **PostgreSQL**: Users, projects, artifacts, repositories, jobs, policies, quotas, audit logs
- **Redis/Valkey**: Job queue, cache, sessions, idempotency keys

## Testing Strategy

### Go Tests
```bash
cd src && go test ./...                     # All tests
cd src && go test -race ./pkg/...           # Race detection
cd src && go test -v ./controller/artifact/ # Specific package
```

### Frontend Tests
```bash
cd src/portal && npm run test               # Karma/Jasmine tests
cd src/portal && npm run test:headless      # CI mode
cd src/portal && npm run lint               # ESLint + Stylelint
```

### Integration Tests
- Robot Framework tests in `tests/robot-cases/`
- API tests: `tests/ci/api_run.sh`

## Important Notes

- This is "Harbor Next" - a fork with continuous delivery and modern features
- Go module path: `github.com/goharbor/harbor/src`
- Current version: v2.15.0
- NEVER edit more than one module at a time
- Prefer direct commands (go, golangci-lint) over wrappers
- DO NOT over-engineer, over-optimize, or over-document
- Maintain code consistency with existing patterns
- Follow DRY, YAGNI, KISS, SOLID principles

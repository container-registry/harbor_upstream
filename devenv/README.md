# Harbor Development Environment

This directory contains all configuration files needed to run Harbor locally for development.

## Philosophy

**Simplicity First**: All dev settings are hardcoded for `localhost`. No environment variables needed - everything works out of the box with `task dev:up`.

## Directory Structure

```
devenv/
├── air.core.toml              # Air hot-reload config for Core service
├── air.jobservice.toml        # Air hot-reload config for Jobservice
├── core.config.conf           # Core (Beego) application config
├── jobservice.config.yml      # Jobservice configuration (hardcoded localhost)
├── registryctl.config.yml     # Registryctl configuration
├── registry.config.yml        # Docker Registry config (hardcoded localhost)
├── registry.passwd            # Registry HTTP basic auth credentials
├── docker-compose.yml         # Docker Compose for infrastructure services
└── README.md                  # This file
```

## Quick Start

```bash
# Start full dev environment
task dev:up

# Or start services individually
task dev:infra:up        # Infrastructure only (PostgreSQL, Redis, Registry)
task dev:backend:core    # Core API with hot reload
task dev:frontend        # Angular frontend with HMR
```

## Infrastructure Services

The `docker-compose.yml` file provides:

- **PostgreSQL 16** - Database on `localhost:5432`
- **Valkey** (Redis) - Cache/queue on `localhost:6379`
- **Distribution** (Registry) - Registry on `localhost:50000`

## Configuration Files

### Air Configs

- **air.core.toml** - Watches `src/` and rebuilds Core in ~3 seconds
- **air.jobservice.toml** - Watches `src/` and rebuilds Jobservice

### Service Configs

All configs use `localhost` for local development:

- **jobservice.config.yml** - Redis at `redis://localhost:6379/2`
- **registry.config.yml** - Redis at `localhost:6379`, storage in Docker volume

**Note:** All credentials are hardcoded for local dev (e.g., password `root123`). This is intentional and safe for development - these configs are checked into git for a ready-to-go setup.

## Development Workflow

1. **Infrastructure First**: `task dev:infra:up` starts all dependencies
2. **Native Services**: Services run natively with hot reload for fast iteration
3. **No Rebuilds**: Changes to Go files trigger automatic rebuild (~3s)
4. **Frontend HMR**: Angular changes reflect in < 1 second

## Notes

- All settings are optimized for **local development only**
- Passwords are hardcoded (e.g., `root123`) - fine for dev, never for production
- Registry uses HTTP basic auth (see `registry.passwd`)
- Logs go to stdout for easy debugging

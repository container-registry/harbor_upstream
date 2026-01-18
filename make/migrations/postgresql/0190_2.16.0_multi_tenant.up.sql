/*
 * Multi-Tenant Schema Migration
 *
 * Adds tenant_id to all tenant-scoped tables.
 * Tenant = organization/customer that can have multiple projects.
 *
 * Table categorization:
 * - SYSTEM tables (no tenant_id): access, role, properties, schema_migrations
 * - TENANT tables (need tenant_id): everything else
 */

-- =============================================================================
-- TENANT TABLE
-- =============================================================================

CREATE TABLE tenant (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(63) NOT NULL,  -- URL-safe identifier (subdomain)
    status VARCHAR(20) DEFAULT 'active' NOT NULL,  -- active, suspended, deleted
    metadata JSONB DEFAULT '{}',
    creation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name),
    UNIQUE (slug)
);

CREATE TRIGGER tenant_update_time_at_modtime
    BEFORE UPDATE ON tenant
    FOR EACH ROW EXECUTE PROCEDURE update_update_time_at_column();

-- Default tenant for migration (existing data)
INSERT INTO tenant (id, name, slug, status) VALUES (1, 'default', 'default', 'active');

-- =============================================================================
-- ADD tenant_id TO ALL TENANT-SCOPED TABLES
-- =============================================================================

-- Users belong to tenants
ALTER TABLE harbor_user ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE harbor_user SET tenant_id = 1;
ALTER TABLE harbor_user ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_harbor_user_tenant_id ON harbor_user(tenant_id);

-- User groups belong to tenants
ALTER TABLE user_group ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE user_group SET tenant_id = 1;
ALTER TABLE user_group ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_user_group_tenant_id ON user_group(tenant_id);

-- Projects belong to tenants
ALTER TABLE project ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE project SET tenant_id = 1;
ALTER TABLE project ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_project_tenant_id ON project(tenant_id);
-- Project name unique per tenant, not globally
ALTER TABLE project DROP CONSTRAINT project_name_key;
ALTER TABLE project ADD CONSTRAINT unique_project_name_per_tenant UNIQUE (tenant_id, name);

-- Repository (denormalized for faster RLS)
ALTER TABLE repository ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE repository r SET tenant_id = (SELECT p.tenant_id FROM project p WHERE p.project_id = r.project_id);
ALTER TABLE repository ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_repository_tenant_id ON repository(tenant_id);

-- Access log
ALTER TABLE access_log ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE access_log al SET tenant_id = COALESCE(
    (SELECT p.tenant_id FROM project p WHERE p.project_id = al.project_id),
    1
);
ALTER TABLE access_log ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_access_log_tenant_id ON access_log(tenant_id);

-- Replication policy
ALTER TABLE replication_policy ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE replication_policy SET tenant_id = 1;
ALTER TABLE replication_policy ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_replication_policy_tenant_id ON replication_policy(tenant_id);

-- Replication target
ALTER TABLE replication_target ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE replication_target SET tenant_id = 1;
ALTER TABLE replication_target ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_replication_target_tenant_id ON replication_target(tenant_id);

-- Harbor labels
ALTER TABLE harbor_label ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE harbor_label SET tenant_id = 1;
ALTER TABLE harbor_label ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_harbor_label_tenant_id ON harbor_label(tenant_id);

-- Admin jobs
ALTER TABLE admin_job ADD COLUMN tenant_id BIGINT REFERENCES tenant(id);
UPDATE admin_job SET tenant_id = 1;
ALTER TABLE admin_job ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_admin_job_tenant_id ON admin_job(tenant_id);

-- =============================================================================
-- TABLES FROM LATER MIGRATIONS (check if exist before altering)
-- =============================================================================

DO $$
BEGIN
    -- Artifact table (added in later migration)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'artifact') THEN
        ALTER TABLE artifact ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE artifact a SET tenant_id = (SELECT p.tenant_id FROM project p WHERE p.project_id = a.project_id) WHERE tenant_id IS NULL;
        ALTER TABLE artifact ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_artifact_tenant_id ON artifact(tenant_id);
    END IF;

    -- Audit log table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_log') THEN
        ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE audit_log al SET tenant_id = COALESCE(
            (SELECT p.tenant_id FROM project p WHERE p.project_id = al.project_id),
            1
        ) WHERE tenant_id IS NULL;
        ALTER TABLE audit_log ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit_log(tenant_id);
    END IF;

    -- Robot table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'robot') THEN
        ALTER TABLE robot ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE robot SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE robot ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_robot_tenant_id ON robot(tenant_id);
    END IF;

    -- Notification policy
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'notification_policy') THEN
        ALTER TABLE notification_policy ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE notification_policy SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE notification_policy ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_notification_policy_tenant_id ON notification_policy(tenant_id);
    END IF;

    -- CVE allowlist
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cve_allowlist') THEN
        ALTER TABLE cve_allowlist ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE cve_allowlist SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE cve_allowlist ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_cve_allowlist_tenant_id ON cve_allowlist(tenant_id);
    END IF;

    -- Immutable tag rule
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'immutable_tag_rule') THEN
        ALTER TABLE immutable_tag_rule ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE immutable_tag_rule SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE immutable_tag_rule ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_immutable_tag_rule_tenant_id ON immutable_tag_rule(tenant_id);
    END IF;

    -- Blob table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'blob') THEN
        ALTER TABLE blob ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE blob SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE blob ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_blob_tenant_id ON blob(tenant_id);
    END IF;

    -- Project blob junction table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'project_blob') THEN
        ALTER TABLE project_blob ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE project_blob pb SET tenant_id = (SELECT p.tenant_id FROM project p WHERE p.project_id = pb.project_id) WHERE tenant_id IS NULL;
        ALTER TABLE project_blob ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_project_blob_tenant_id ON project_blob(tenant_id);
    END IF;

    -- Scan report table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'scan_report') THEN
        ALTER TABLE scan_report ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE scan_report SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE scan_report ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_scan_report_tenant_id ON scan_report(tenant_id);
    END IF;

    -- Quota table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'quota') THEN
        ALTER TABLE quota ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE quota SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE quota ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_quota_tenant_id ON quota(tenant_id);
    END IF;

    -- Registry table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'registry') THEN
        ALTER TABLE registry ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE registry SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE registry ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_registry_tenant_id ON registry(tenant_id);
    END IF;

    -- Retention policy
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'retention_policy') THEN
        ALTER TABLE retention_policy ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE retention_policy SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE retention_policy ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_retention_policy_tenant_id ON retention_policy(tenant_id);
    END IF;

    -- Schedule table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'schedule') THEN
        ALTER TABLE schedule ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE schedule SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE schedule ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_schedule_tenant_id ON schedule(tenant_id);
    END IF;

    -- Job log table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'job_log') THEN
        ALTER TABLE job_log ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE job_log SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE job_log ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_job_log_tenant_id ON job_log(tenant_id);
    END IF;

    -- Execution table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'execution') THEN
        ALTER TABLE execution ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE execution SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE execution ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_execution_tenant_id ON execution(tenant_id);
    END IF;

    -- Task table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'task') THEN
        ALTER TABLE task ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
        UPDATE task SET tenant_id = 1 WHERE tenant_id IS NULL;
        ALTER TABLE task ALTER COLUMN tenant_id SET NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_task_tenant_id ON task(tenant_id);
    END IF;
END $$;

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================

-- Function to get current tenant from session
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS BIGINT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.tenant_id', true), '')::BIGINT;
END;
$$ LANGUAGE plpgsql STABLE;

-- Enable RLS and create policies for all tenant-scoped tables
DO $$
DECLARE
    tenant_tables TEXT[] := ARRAY[
        'harbor_user', 'user_group', 'project', 'project_member', 'project_metadata',
        'repository', 'access_log', 'replication_policy', 'replication_target',
        'harbor_label', 'harbor_resource_label', 'admin_job',
        'artifact', 'audit_log', 'robot', 'notification_policy', 'cve_allowlist',
        'immutable_tag_rule', 'blob', 'project_blob', 'scan_report', 'quota',
        'registry', 'retention_policy', 'schedule', 'job_log', 'execution', 'task'
    ];
    t TEXT;
BEGIN
    FOREACH t IN ARRAY tenant_tables
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = t) THEN
            -- Check if table has tenant_id column
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = t AND column_name = 'tenant_id'
            ) THEN
                EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
                EXECUTE format('
                    CREATE POLICY tenant_isolation_%I ON %I
                    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
                    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
                ', t, t);
            END IF;
        END IF;
    END LOOP;
END $$;

-- Special handling for tables that reference tenant through project_id only
-- (project_member, project_metadata don't need tenant_id if we join through project)
-- But for performance, we add tenant_id to avoid joins in RLS policies

ALTER TABLE project_member ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
UPDATE project_member pm SET tenant_id = (SELECT p.tenant_id FROM project p WHERE p.project_id = pm.project_id) WHERE tenant_id IS NULL;
ALTER TABLE project_member ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_project_member_tenant_id ON project_member(tenant_id);
ALTER TABLE project_member ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_project_member ON project_member
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE project_metadata ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenant(id);
UPDATE project_metadata pm SET tenant_id = (SELECT p.tenant_id FROM project p WHERE p.project_id = pm.project_id) WHERE tenant_id IS NULL;
ALTER TABLE project_metadata ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_project_metadata_tenant_id ON project_metadata(tenant_id);
ALTER TABLE project_metadata ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_project_metadata ON project_metadata
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE tenant IS 'Multi-tenant organizations - each tenant can have multiple projects';
COMMENT ON COLUMN tenant.slug IS 'URL-safe identifier used for subdomains (e.g., acme.harbor.example.com)';
COMMENT ON FUNCTION current_tenant_id() IS 'Returns current tenant from session variable app.tenant_id, NULL if not set';

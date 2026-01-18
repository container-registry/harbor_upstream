/*
 * Rollback Multi-Tenant Schema Migration
 * WARNING: This will remove tenant isolation. All data becomes accessible.
 */

-- =============================================================================
-- DROP RLS POLICIES
-- =============================================================================

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
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_%I ON %I', t, t);
            EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
        END IF;
    END LOOP;
END $$;

-- =============================================================================
-- DROP TENANT FUNCTION
-- =============================================================================

DROP FUNCTION IF EXISTS current_tenant_id();

-- =============================================================================
-- DROP tenant_id COLUMNS
-- Note: This loses tenant association data!
-- =============================================================================

-- Core tables
ALTER TABLE harbor_user DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE user_group DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE project DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE project_member DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE project_metadata DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE repository DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE access_log DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE replication_policy DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE replication_target DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE harbor_label DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE admin_job DROP COLUMN IF EXISTS tenant_id;

-- Tables from later migrations (may not exist)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'artifact') THEN
        ALTER TABLE artifact DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_log') THEN
        ALTER TABLE audit_log DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'robot') THEN
        ALTER TABLE robot DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'notification_policy') THEN
        ALTER TABLE notification_policy DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cve_allowlist') THEN
        ALTER TABLE cve_allowlist DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'immutable_tag_rule') THEN
        ALTER TABLE immutable_tag_rule DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'blob') THEN
        ALTER TABLE blob DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'project_blob') THEN
        ALTER TABLE project_blob DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'scan_report') THEN
        ALTER TABLE scan_report DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'quota') THEN
        ALTER TABLE quota DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'registry') THEN
        ALTER TABLE registry DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'retention_policy') THEN
        ALTER TABLE retention_policy DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'schedule') THEN
        ALTER TABLE schedule DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'job_log') THEN
        ALTER TABLE job_log DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'execution') THEN
        ALTER TABLE execution DROP COLUMN IF EXISTS tenant_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'task') THEN
        ALTER TABLE task DROP COLUMN IF EXISTS tenant_id;
    END IF;
END $$;

-- =============================================================================
-- RESTORE PROJECT NAME UNIQUENESS
-- =============================================================================

ALTER TABLE project DROP CONSTRAINT IF EXISTS unique_project_name_per_tenant;
ALTER TABLE project ADD CONSTRAINT project_name_key UNIQUE (name);

-- =============================================================================
-- DROP TENANT TABLE
-- =============================================================================

DROP TABLE IF EXISTS tenant;

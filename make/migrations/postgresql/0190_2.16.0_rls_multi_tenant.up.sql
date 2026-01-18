/*
 * Multi-tenant Row-Level Security (RLS) Migration
 *
 * This migration enables RLS on tenant-scoped tables using existing project_id columns.
 * No schema changes required - tables already have project_id.
 */

-- Function to get current tenant from session variable
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS BIGINT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.tenant_id', true), '')::BIGINT;
END;
$$ LANGUAGE plpgsql STABLE;

-- Enable RLS on tenant-scoped tables
-- Note: Existing data and queries continue to work unchanged

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
ALTER TABLE tag ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_accessory ENABLE ROW LEVEL SECURITY;

-- Create tenant isolation policies
-- Policy allows access when:
--   1. tenant_id matches current session tenant, OR
--   2. No tenant is set (admin/system operations)

CREATE POLICY tenant_isolation_repository ON repository
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_artifact ON artifact
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_project_member ON project_member
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_project_metadata ON project_metadata
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_audit_log ON audit_log
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_robot ON robot
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_project_blob ON project_blob
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_notification_policy ON notification_policy
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_cve_allowlist ON cve_allowlist
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY tenant_isolation_immutable_tag_rule ON immutable_tag_rule
    USING (project_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- Tag and accessory need to join through artifact/repository for project_id
-- Using subquery-based policies

CREATE POLICY tenant_isolation_tag ON tag
    USING (
        current_tenant_id() IS NULL
        OR EXISTS (
            SELECT 1 FROM artifact a
            WHERE a.id = tag.artifact_id
            AND a.project_id = current_tenant_id()
        )
    );

CREATE POLICY tenant_isolation_artifact_accessory ON artifact_accessory
    USING (
        current_tenant_id() IS NULL
        OR EXISTS (
            SELECT 1 FROM artifact a
            WHERE a.id = artifact_accessory.artifact_id
            AND a.project_id = current_tenant_id()
        )
    );

-- FORCE RLS ensures policies apply even to table owner
-- Only enable if using non-superuser application role
-- ALTER TABLE repository FORCE ROW LEVEL SECURITY;

-- Add index to improve RLS policy performance (if not exists)
CREATE INDEX IF NOT EXISTS idx_repository_project_id ON repository(project_id);
CREATE INDEX IF NOT EXISTS idx_artifact_project_id ON artifact(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_project_id ON audit_log(project_id);
CREATE INDEX IF NOT EXISTS idx_robot_project_id ON robot(project_id);

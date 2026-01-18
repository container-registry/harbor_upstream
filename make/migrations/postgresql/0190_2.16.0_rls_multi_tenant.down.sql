/*
 * Rollback Multi-tenant Row-Level Security (RLS)
 */

-- Drop policies
DROP POLICY IF EXISTS tenant_isolation_repository ON repository;
DROP POLICY IF EXISTS tenant_isolation_artifact ON artifact;
DROP POLICY IF EXISTS tenant_isolation_project_member ON project_member;
DROP POLICY IF EXISTS tenant_isolation_project_metadata ON project_metadata;
DROP POLICY IF EXISTS tenant_isolation_audit_log ON audit_log;
DROP POLICY IF EXISTS tenant_isolation_robot ON robot;
DROP POLICY IF EXISTS tenant_isolation_project_blob ON project_blob;
DROP POLICY IF EXISTS tenant_isolation_notification_policy ON notification_policy;
DROP POLICY IF EXISTS tenant_isolation_cve_allowlist ON cve_allowlist;
DROP POLICY IF EXISTS tenant_isolation_immutable_tag_rule ON immutable_tag_rule;
DROP POLICY IF EXISTS tenant_isolation_tag ON tag;
DROP POLICY IF EXISTS tenant_isolation_artifact_accessory ON artifact_accessory;

-- Disable RLS on tables
ALTER TABLE repository DISABLE ROW LEVEL SECURITY;
ALTER TABLE artifact DISABLE ROW LEVEL SECURITY;
ALTER TABLE project_member DISABLE ROW LEVEL SECURITY;
ALTER TABLE project_metadata DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY;
ALTER TABLE robot DISABLE ROW LEVEL SECURITY;
ALTER TABLE project_blob DISABLE ROW LEVEL SECURITY;
ALTER TABLE notification_policy DISABLE ROW LEVEL SECURITY;
ALTER TABLE cve_allowlist DISABLE ROW LEVEL SECURITY;
ALTER TABLE immutable_tag_rule DISABLE ROW LEVEL SECURITY;
ALTER TABLE tag DISABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_accessory DISABLE ROW LEVEL SECURITY;

-- Drop tenant function
DROP FUNCTION IF EXISTS current_tenant_id();

-- Note: Indexes are kept as they benefit queries regardless of RLS

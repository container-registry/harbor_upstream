-- Description:
--
-- Human-readable name of the identity provider
-- Optional description
-- OIDC issuer URL (unique per provider)
-- URL to the OIDC discovery document (.well-known/openid-configuration)
-- URL to fetch signing keys (JWKS)
-- JWKS for offline validation
-- Scope of trust; -1 = system-level, otherwise project-level
CREATE TABLE IF NOT EXISTS identity_providers (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    issuer TEXT NOT NULL UNIQUE,
    openid_config_url TEXT,
    jwks_uri TEXT,
    jwks_keys JSONB,
    project_id INT NOT NULL,
    creation_time TIMESTAMP DEFAULT NOW(),
    update_time TIMESTAMP DEFAULT NOW()
);

-- Description: join table for identity providers and robots
CREATE TABLE IF NOT EXISTS robot_identity_providers (
    identity_provider_id INT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    robot_id INT NOT NULL REFERENCES robot(id) ON DELETE CASCADE,
    creation_time TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (identity_provider_id, robot_id)
);

-- Description:
--
-- claim_rules stores required JWT claim/value pairs for authentication
-- scoped to either an identity provider or a specific robot.
CREATE TABLE IF NOT EXISTS claim_rules (
    id SERIAL PRIMARY KEY,
    identity_provider_id INT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    robot_id INT REFERENCES robot(id) ON DELETE CASCADE,
    claim_path TEXT NOT NULL,
    value TEXT,
    creation_time TIMESTAMP DEFAULT NOW()
);

-- Unique constraint: ensure no duplicate claim rules per scope
ALTER TABLE claim_rules
    ADD CONSTRAINT IF NOT EXISTS claim_rules_unique
    UNIQUE (identity_provider_id, robot_id, claim_path, value);

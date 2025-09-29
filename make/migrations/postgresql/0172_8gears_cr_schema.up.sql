-- Table: identity_providers
-- Stores federated identity providers

CREATE TABLE IF NOT EXISTS identity_providers (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    issuer TEXT NOT NULL UNIQUE,
    openid_config_url TEXT,
    offline_validation BOOLEAN NOT NULL DEFAULT FALSE,
    supported_algorithms TEXT,
    claims_supported TEXT,
    jwks_uri TEXT,
    jwks_keys JSONB,
    project_id INT NOT NULL,
    creation_time TIMESTAMP DEFAULT NOW(),
    update_time TIMESTAMP DEFAULT NOW()
);

-- Table: robot_identity_providers
-- Join table linking robots and identity providers

CREATE TABLE IF NOT EXISTS robot_identity_providers (
    identity_provider_id INT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    robot_id INT NOT NULL REFERENCES robot(id) ON DELETE CASCADE,
    creation_time TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (identity_provider_id, robot_id)
);

-- Table: claim_rules
-- Stores JWT claim/value pairs for authentication
-- Scoped to identity provider or specific robot

CREATE TABLE IF NOT EXISTS claim_rules (
    id SERIAL PRIMARY KEY,
    identity_provider_id INT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    robot_id INT REFERENCES robot(id) ON DELETE CASCADE,
    claim_path TEXT NOT NULL,
    value TEXT,
    creation_time TIMESTAMP DEFAULT NOW()
);

-- Unique constraint for claim_rules
-- Use a conditional check to avoid errors if the constraint exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_name='claim_rules'
          AND constraint_type='UNIQUE'
          AND constraint_name='claim_rules_unique'
    ) THEN
        ALTER TABLE claim_rules
            ADD CONSTRAINT claim_rules_unique
            UNIQUE (identity_provider_id, robot_id, claim_path, value);
    END IF;
END$$;

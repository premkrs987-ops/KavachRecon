CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";

CREATE TYPE scan_mode_enum AS ENUM ('PASSIVE_ONLY', 'CONTROLLED_ACTIVE');
CREATE TYPE module_status_enum AS ENUM ('NOT_STARTED', 'QUEUED', 'RUNNING', 'COMPLETED', 'COMPLETED_NO_RESULTS', 'FAILED', 'SKIPPED', 'NOT_APPLICABLE');
CREATE TYPE scan_status_enum AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'PARTIALLY_FAILED', 'FAILED', 'CANCELLED');
CREATE TYPE asset_type_enum AS ENUM ('DOMAIN', 'SUBDOMAIN', 'IP_ADDRESS', 'NETWORK_RANGE', 'HOST', 'SERVICE', 'WEB_SERVICE', 'ENDPOINT', 'JAVASCRIPT_RESOURCE');
CREATE TYPE finding_classification_enum AS ENUM ('OBSERVED', 'VERIFIED', 'INFERRED', 'HEURISTIC', 'RECOMMENDED_FOR_MANUAL_REVIEW', 'CONFIRMED_FINDING');
CREATE TYPE severity_enum AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    primary_domain VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    pattern VARCHAR(255) NOT NULL,
    scope_type VARCHAR(50) NOT NULL,
    is_excluded BOOLEAN NOT NULL DEFAULT FALSE,
    authorization_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_mode scan_mode_enum NOT NULL DEFAULT 'PASSIVE_ONLY',
    status scan_status_enum NOT NULL DEFAULT 'PENDING',
    active_confirmation_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_modules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module_name VARCHAR(100) NOT NULL,
    status module_status_enum NOT NULL DEFAULT 'NOT_STARTED',
    items_discovered INT NOT NULL DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_scan_module UNIQUE (scan_id, module_name)
);

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    type asset_type_enum NOT NULL,
    canonical_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    first_seen_scan_id UUID REFERENCES scans(id),
    last_seen_scan_id UUID REFERENCES scans(id),
    confidence_score FLOAT NOT NULL DEFAULT 1.0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_target_asset_value UNIQUE (target_id, type, normalized_value)
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    classification finding_classification_enum NOT NULL DEFAULT 'OBSERVED',
    severity severity_enum NOT NULL DEFAULT 'INFO',
    deterministic_risk_score FLOAT NOT NULL DEFAULT 0.0,
    evidence TEXT NOT NULL,
    remediation_guidance TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

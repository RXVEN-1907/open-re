-- open-re Database Initialization Script
-- This script runs automatically when the PostgreSQL container starts for the first time
-- It creates the necessary schema, extensions, and initial data for the open-re platform

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gin";
CREATE EXTENSION IF NOT EXISTS "btree_gist";

-- Create custom types
DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE finding_category AS ENUM (
        'injection', 'broken_auth', 'sensitive_data', 'xxe', 'broken_access',
        'security_misconfig', 'xss', 'insecure_deserialization', 'vulnerable_components',
        'insufficient_logging', 'ssrf', 'csrf', 'idor', 'open_redirect',
        'path_traversal', 'command_injection', 'ldap_injection', 'template_injection',
        'jwt_issues', 'oauth_issues', 'websocket_issues', 'graphql_issues',
        'rate_limiting', 'cors', 'csp', 'cookie_security', 'info_disclosure',
        'tech_fingerprint', 'tls_issues', 'http_methods', 'ssl_config',
        'other'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE job_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled', 'retrying');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE job_type AS ENUM (
        'scan', 'analysis', 'ai_analysis', 'report_generation',
        'plugin_execution', 'verification', 'correlation', 'prioritization',
        'investigation', 'workflow', 'maintenance'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE project_role AS ENUM ('owner', 'admin', 'member', 'viewer');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    avatar_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    is_superuser BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMPTZ,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    permissions JSONB DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    is_public BOOLEAN DEFAULT FALSE,
    settings JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id);
CREATE INDEX IF NOT EXISTS idx_projects_public ON projects(is_public);

-- Project members table
CREATE TABLE IF NOT EXISTS project_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role project_role DEFAULT 'viewer',
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(project_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_project_members_project ON project_members(project_id);
CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);

-- Files table
CREATE TABLE IF NOT EXISTS files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    uploaded_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    filename VARCHAR(500) NOT NULL,
    original_filename VARCHAR(500),
    content_type VARCHAR(100),
    size_bytes BIGINT NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL,
    storage_bucket VARCHAR(100) NOT NULL,
    storage_key VARCHAR(500) NOT NULL,
    binary_format VARCHAR(20),
    architecture VARCHAR(20),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_files_project ON files(project_id);
CREATE INDEX IF NOT EXISTS idx_files_checksum ON files(checksum_sha256);
CREATE INDEX IF NOT EXISTS idx_files_format ON files(binary_format);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    target_type VARCHAR(50) DEFAULT 'web',
    profile VARCHAR(20) DEFAULT 'standard',
    status scan_status DEFAULT 'pending',
    checks_requested JSONB DEFAULT '[]'::jsonb,
    checks_completed JSONB DEFAULT '[]'::jsonb,
    findings_count INTEGER DEFAULT 0,
    severity_counts JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}'::jsonb,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    error_message TEXT,
    config JSONB DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity finding_severity NOT NULL,
    category finding_category NOT NULL,
    confidence VARCHAR(20) DEFAULT 'medium',
    location TEXT,
    evidence JSONB DEFAULT '{}'::jsonb,
    remediation TEXT,
    remediation_effort VARCHAR(20),
    remediation_priority VARCHAR(20),
    references JSONB DEFAULT '[]'::jsonb,
    cwe_ids JSONB DEFAULT '[]'::jsonb,
    capec_ids JSONB DEFAULT '[]'::jsonb,
    owasp_ids JSONB DEFAULT '[]'::jsonb,
    mitre_ids JSONB DEFAULT '[]'::jsonb,
    cvss_score DECIMAL(3,1),
    risk_score DECIMAL(5,2),
    exploitability VARCHAR(20),
    is_verified BOOLEAN DEFAULT FALSE,
    verified_by UUID REFERENCES users(id) ON DELETE SET NULL,
    verified_at TIMESTAMPTZ,
    false_positive BOOLEAN DEFAULT FALSE,
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(is_verified);
CREATE INDEX IF NOT EXISTS idx_findings_false_positive ON findings(false_positive);

-- Finding relationships table
CREATE TABLE IF NOT EXISTS finding_relationships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    target_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    relationship_type VARCHAR(50) NOT NULL,
    confidence VARCHAR(20) DEFAULT 'medium',
    evidence JSONB DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(source_finding_id, target_finding_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_finding_rels_source ON finding_relationships(source_finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_rels_target ON finding_relationships(target_finding_id);

-- Attack paths table
CREATE TABLE IF NOT EXISTS attack_paths (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    entry_point_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    target_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    steps JSONB DEFAULT '[]'::jsonb,
    risk_score DECIMAL(5,2),
    likelihood VARCHAR(20),
    impact VARCHAR(20),
    is_validated BOOLEAN DEFAULT FALSE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_project ON attack_paths(project_id);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    format VARCHAR(20) NOT NULL,
    template VARCHAR(100),
    status VARCHAR(20) DEFAULT 'generating',
    file_path TEXT,
    file_size_bytes BIGINT,
    generated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_project ON reports(project_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan ON reports(scan_id);

-- Jobs table
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    job_type job_type NOT NULL,
    status job_status DEFAULT 'pending',
    priority VARCHAR(20) DEFAULT 'default',
    payload JSONB DEFAULT '{}'::jsonb,
    result JSONB,
    error_message TEXT,
    progress INTEGER DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    worker_id VARCHAR(100),
    parent_job_id UUID REFERENCES jobs(id) ON DELETE SET NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jobs_project ON jobs(project_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(priority);
CREATE INDEX IF NOT EXISTS idx_jobs_scheduled ON jobs(scheduled_at);
CREATE INDEX IF NOT EXISTS idx_jobs_worker ON jobs(worker_id);

-- Workflows table
CREATE TABLE IF NOT EXISTS workflows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    definition JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'draft',
    version INTEGER DEFAULT 1,
    is_template BOOLEAN DEFAULT FALSE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflows_project ON workflows(project_id);
CREATE INDEX IF NOT EXISTS idx_workflows_template ON workflows(is_template);

-- Workflow executions table
CREATE TABLE IF NOT EXISTS workflow_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'pending',
    current_stage VARCHAR(100),
    input JSONB DEFAULT '{}'::jsonb,
    output JSONB,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wf_executions_workflow ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_wf_executions_project ON workflow_executions(project_id);
CREATE INDEX IF NOT EXISTS idx_wf_executions_status ON workflow_executions(status);

-- Plugins table
CREATE TABLE IF NOT EXISTS plugins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    version VARCHAR(50) NOT NULL,
    author VARCHAR(255),
    repository_url TEXT,
    documentation_url TEXT,
    license VARCHAR(100),
    plugin_type VARCHAR(50) DEFAULT 'security',
    capabilities JSONB DEFAULT '[]'::jsonb,
    config_schema JSONB DEFAULT '{}'::jsonb,
    wasm_module_path TEXT,
    is_builtin BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT TRUE,
    checksum_sha256 VARCHAR(64),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plugins_enabled ON plugins(is_enabled);
CREATE INDEX IF NOT EXISTS idx_plugins_type ON plugins(plugin_type);

-- Plugin configurations table
CREATE TABLE IF NOT EXISTS plugin_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    plugin_id UUID NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    config JSONB DEFAULT '{}'::jsonb,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(plugin_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_plugin_configs_plugin ON plugin_configs(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_configs_project ON plugin_configs(project_id);

-- AI conversations table
CREATE TABLE IF NOT EXISTS ai_conversations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(500),
    model VARCHAR(100),
    provider VARCHAR(50),
    system_prompt TEXT,
    context JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_convs_project ON ai_conversations(project_id);
CREATE INDEX IF NOT EXISTS idx_ai_convs_user ON ai_conversations(user_id);

-- AI messages table
CREATE TABLE IF NOT EXISTS ai_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conversation_id UUID NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    tokens_used INTEGER,
    model VARCHAR(100),
    provider VARCHAR(50),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_messages_conv ON ai_messages(conversation_id);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

-- System settings table
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default system settings
INSERT INTO system_settings (key, value, description, is_public) VALUES
    ('platform.name', '"open-re"', 'Platform display name', TRUE),
    ('platform.version', '"0.1.0"', 'Platform version', TRUE),
    ('scanner.default_profile', '"standard"', 'Default scan profile', TRUE),
    ('scanner.max_concurrent', '10', 'Maximum concurrent scans', FALSE),
    ('ai.default_provider', '"ollama"', 'Default AI provider', FALSE),
    ('ai.default_model', '"codellama:13b"', 'Default AI model', FALSE),
    ('plugins.auto_update', 'false', 'Auto-update plugins', FALSE),
    ('queue.default_workers', '4', 'Default worker count', FALSE),
    ('retention.scan_days', '90', 'Scan retention in days', FALSE),
    ('retention.audit_days', '365', 'Audit log retention in days', FALSE)
ON CONFLICT (key) DO NOTHING;

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at triggers to all tables with updated_at column
DO $$
DECLARE
    tbl record;
BEGIN
    FOR tbl IN
        SELECT table_name
        FROM information_schema.columns
        WHERE column_name = 'updated_at'
        AND table_schema = 'public'
        AND table_name NOT IN ('system_settings')
    LOOP
        EXECUTE format('
            DROP TRIGGER IF EXISTS update_%I_updated_at ON %I;
            CREATE TRIGGER update_%I_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', tbl.table_name, tbl.table_name, tbl.table_name, tbl.table_name);
    END LOOP;
END $$;

-- Grant permissions to openre user (created by POSTGRES_USER env var)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO openre;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO openre;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO openre;

-- Default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO openre;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO openre;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO openre;

-- Create a default admin user (password: admin123 - CHANGE IN PRODUCTION!)
-- This is only for development; production should use proper registration
INSERT INTO users (email, username, password_hash, full_name, is_active, is_superuser, email_verified)
VALUES (
    'admin@openre.local',
    'admin',
    crypt('admin123', gen_salt('bf')),
    'System Administrator',
    TRUE,
    TRUE,
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- Create default project for admin
INSERT INTO projects (name, description, owner_id, is_public, settings)
SELECT
    'Default Project',
    'Default project for development',
    id,
    FALSE,
    '{}'::jsonb
FROM users WHERE username = 'admin'
ON CONFLICT DO NOTHING;

-- Add admin as project owner
INSERT INTO project_members (project_id, user_id, role)
SELECT p.id, u.id, 'owner'
FROM projects p, users u
WHERE p.name = 'Default Project' AND u.username = 'admin'
ON CONFLICT DO NOTHING;

-- Insert built-in security plugins
INSERT INTO plugins (name, display_name, description, version, author, plugin_type, capabilities, is_builtin, is_enabled, config_schema)
VALUES
    ('sqli-detector', 'SQL Injection Detector', 'Detects SQL injection vulnerabilities in web applications', '1.0.0', 'open-re', 'security', '["injection", "sqli"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('xss-scanner', 'XSS Scanner', 'Cross-site scripting vulnerability detector', '1.0.0', 'open-re', 'security', '["xss", "injection"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('path-traversal', 'Path Traversal Detector', 'Detects directory traversal and file inclusion vulnerabilities', '1.0.0', 'open-re', 'security', '["path_traversal", "file_inclusion"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('auth-analyzer', 'Authentication Analyzer', 'Analyzes authentication mechanisms for weaknesses', '1.0.0', 'open-re', 'security', '["broken_auth", "session", "jwt"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('csp-analyzer', 'CSP Analyzer', 'Content Security Policy analysis and misconfiguration detection', '1.0.0', 'open-re', 'security', '["csp", "security_misconfig"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('cors-checker', 'CORS Checker', 'Cross-Origin Resource Sharing misconfiguration detector', '1.0.0', 'open-re', 'security', '["cors", "security_misconfig"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('rate-limiter', 'Rate Limiting Detector', 'Detects missing or weak rate limiting', '1.0.0', 'open-re', 'security', '["rate_limiting", "dos"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('graphql-introspection', 'GraphQL Introspection', 'Detects exposed GraphQL introspection endpoints', '1.0.0', 'open-re', 'security', '["graphql", "info_disclosure"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('rest-discovery', 'REST API Discovery', 'Discovers and maps REST API endpoints', '1.0.0', 'open-re', 'security', '["recon", "api_discovery"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('ssrf-detector', 'SSRF Detector', 'Server-Side Request Forgery vulnerability detector', '1.0.0', 'open-re', 'security', '["ssrf", "injection"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('xxe-scanner', 'XXE Scanner', 'XML External Entity injection detector', '1.0.0', 'open-re', 'security', '["xxe", "injection"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('command-injection', 'Command Injection Detector', 'OS command injection vulnerability detector', '1.0.0', 'open-re', 'security', '["command_injection", "injection"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('ldap-injection', 'LDAP Injection Detector', 'LDAP injection vulnerability detector', '1.0.0', 'open-re', 'security', '["ldap_injection", "injection"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('template-injection', 'Template Injection Detector', 'Server-side template injection (SSTI) detector', '1.0.0', 'open-re', 'security', '["template_injection", "injection"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('deserialization', 'Insecure Deserialization Detector', 'Detects insecure deserialization vulnerabilities', '1.0.0', 'open-re', 'security', '["insecure_deserialization", "rce"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('jwt-analyzer', 'JWT Analyzer', 'JSON Web Token security analysis', '1.0.0', 'open-re', 'security', '["jwt_issues", "broken_auth"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('oauth-analyzer', 'OAuth Analyzer', 'OAuth/OIDC configuration security analysis', '1.0.0', 'open-re', 'security', '["oauth_issues", "broken_auth"]'::jsonb, TRUE, TRUE, '{}'::jsonb),
    ('websocket-analyzer', 'WebSocket Analyzer', 'WebSocket security analysis', '1.0.0', 'open-re', 'security', '["websocket_issues", "recon"]'::jsonb, TRUE, TRUE, '{}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Create full-text search index for findings
CREATE INDEX IF NOT EXISTS idx_findings_fulltext ON findings USING GIN (
    to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(description, '') || ' ' || COALESCE(remediation, ''))
);

-- Create full-text search index for projects
CREATE INDEX IF NOT EXISTS idx_projects_fulltext ON projects USING GIN (
    to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, ''))
);

-- Create partial index for active scans
CREATE INDEX IF NOT EXISTS idx_scans_active ON scans(project_id, created_at) WHERE status IN ('pending', 'running');

-- Create partial index for open findings
CREATE INDEX IF NOT EXISTS idx_findings_open ON findings(project_id, severity, created_at) WHERE false_positive = FALSE AND is_verified = FALSE;

-- Statistics view for dashboards
CREATE OR REPLACE VIEW project_stats AS
SELECT
    p.id AS project_id,
    p.name AS project_name,
    COUNT(DISTINCT s.id) AS total_scans,
    COUNT(DISTINCT s.id) FILTER (WHERE s.status = 'completed') AS completed_scans,
    COUNT(DISTINCT f.id) AS total_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'critical') AS critical_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'high') AS high_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'medium') AS medium_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'low') AS low_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'info') AS info_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.is_verified = TRUE) AS verified_findings,
    COUNT(DISTINCT f.id) FILTER (WHERE f.false_positive = TRUE) AS false_positive_findings,
    MAX(s.completed_at) AS last_scan_at
FROM projects p
LEFT JOIN scans s ON s.project_id = p.id
LEFT JOIN findings f ON f.scan_id = s.id
GROUP BY p.id, p.name;

-- Grant access to views
GRANT SELECT ON project_stats TO openre;

-- Completion message
DO $$
BEGIN
    RAISE NOTICE 'open-re database initialization completed successfully!';
    RAISE NOTICE 'Default admin user: admin@openre.local / admin123 (CHANGE IN PRODUCTION)';
    RAISE NOTICE '18 built-in security plugins registered';
    RAISE NOTICE 'All tables, indexes, and views created';
END $$;
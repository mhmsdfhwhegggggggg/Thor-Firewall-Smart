-- جدول الوكلاء (مفهرس للبحث السريع حسب IP والحالة)
CREATE TABLE agents (
    agent_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(100) NOT NULL,
    thor_version VARCHAR(50) NOT NULL,
    ip_address INET NOT NULL,
    metadata JSONB DEFAULT '{}',
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DEGRADED, OFFLINE
    cpu_usage DOUBLE PRECISION,
    memory_mb BIGINT
);
CREATE INDEX idx_agents_last_heartbeat ON agents(last_heartbeat);
CREATE INDEX idx_agents_ip ON agents(ip_address);

-- جدول السياسات (مع دعم الإصدارات والتراجع Rollback)
CREATE TABLE policies (
    id BIGSERIAL PRIMARY KEY,
    version BIGINT NOT NULL UNIQUE,
    policy_type VARCHAR(50) NOT NULL,
    rule_id VARCHAR(128) NOT NULL,
    content TEXT NOT NULL,
    enforcement_mode VARCHAR(20) DEFAULT 'ENFORCE', -- ENFORCE, SHADOW
    created_by VARCHAR(64) DEFAULT 'SYSTEM',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);
CREATE INDEX idx_policies_version ON policies(version DESC);
CREATE INDEX idx_policies_active ON policies(is_active) WHERE is_active = TRUE;

-- جدول الحوادث (مقسم زمنياً في الإنتاج، هنا مبسط)
CREATE TABLE incidents (
    incident_id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) REFERENCES agents(agent_id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    matched_rules TEXT[],
    actions_taken TEXT[],
    context JSONB DEFAULT '{}',
    reported_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_incidents_agent ON incidents(agent_id);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_time ON incidents(reported_at DESC);

-- سجلات التدقيق غير القابلة للتغيير (Immutable Audit Logs)
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_id VARCHAR(64) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(128),
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_logs_time ON audit_logs(created_at DESC);

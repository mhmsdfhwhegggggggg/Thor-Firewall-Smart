-- ═══════════════════════════════════════════════════════════════════════════
-- Thor Firewall Smart — Initial Production Schema
-- Phase 1: Persistent state (alerts, campaigns, UEBA, audit, token blacklist)
-- ═══════════════════════════════════════════════════════════════════════════

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fast text search on alert messages

-- ─── Enum types ───────────────────────────────────────────────────────────────
CREATE TYPE threat_level  AS ENUM ('unknown','low','medium','high','critical');
CREATE TYPE alert_status  AS ENUM ('open','acknowledged','resolved','false_positive');
CREATE TYPE campaign_status AS ENUM ('active','resolved','investigating');
CREATE TYPE rule_type     AS ENUM ('sigma','yara','ioc','ids','ml','zero_day','fim','sequence');
CREATE TYPE ioc_type      AS ENUM ('ip_address','domain','file_hash','url');

-- ─── 1. Alerts ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_name       TEXT        NOT NULL,
    rule_type       rule_type   NOT NULL,
    threat_level    threat_level NOT NULL DEFAULT 'medium',
    status          alert_status NOT NULL DEFAULT 'open',

    -- Event context
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    pid             INTEGER,
    process_name    TEXT,
    username        TEXT,
    hostname        TEXT,

    -- Detection payload
    message         TEXT        NOT NULL,
    raw_event       JSONB,
    mitre_tactic    TEXT,
    mitre_technique TEXT,

    -- ML scoring
    ml_score        FLOAT,
    false_positive_feedback BOOLEAN,
    analyst_notes   TEXT,
    acknowledged_by TEXT,

    -- Campaign linkage
    campaign_id     UUID,

    -- Timestamps
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,

    -- Audit
    agent_hostname  TEXT        NOT NULL DEFAULT '',
    agent_version   TEXT        NOT NULL DEFAULT '0.0.0'
);

CREATE INDEX idx_alerts_detected_at     ON alerts (detected_at DESC);
CREATE INDEX idx_alerts_threat_level    ON alerts (threat_level);
CREATE INDEX idx_alerts_status          ON alerts (status);
CREATE INDEX idx_alerts_src_ip          ON alerts (src_ip);
CREATE INDEX idx_alerts_campaign_id     ON alerts (campaign_id);
CREATE INDEX idx_alerts_rule_type       ON alerts (rule_type);
CREATE INDEX idx_alerts_message_trgm    ON alerts USING GIN (message gin_trgm_ops);

-- ─── 2. Attack Campaigns ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS campaigns (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    status          campaign_status NOT NULL DEFAULT 'active',
    max_threat_level threat_level   NOT NULL DEFAULT 'medium',
    kill_chain_stage TEXT,
    alert_count     INTEGER         NOT NULL DEFAULT 0,

    -- Scope
    involved_ips    TEXT[]          NOT NULL DEFAULT '{}',
    involved_pids   INTEGER[]       NOT NULL DEFAULT '{}',
    mitre_techniques TEXT[]         NOT NULL DEFAULT '{}',
    rule_names      TEXT[]          NOT NULL DEFAULT '{}',

    -- ML-generated narrative
    threat_narrative TEXT,
    recommended_actions TEXT[],
    dwell_time_hours FLOAT,

    -- Timestamps
    first_seen      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,

    -- Linkage
    assigned_analyst TEXT,
    case_ticket     TEXT
);

CREATE INDEX idx_campaigns_status       ON campaigns (status);
CREATE INDEX idx_campaigns_last_seen    ON campaigns (last_seen DESC);
CREATE INDEX idx_campaigns_threat_level ON campaigns (max_threat_level);

-- ─── 3. UEBA Entity Profiles ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS entity_profiles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type     TEXT            NOT NULL, -- user, process, host, service
    entity_id       TEXT            NOT NULL, -- username, pid-cmd, hostname

    -- EMA baselines (serialized feature stats)
    baseline_json   JSONB           NOT NULL DEFAULT '{}',
    peer_group      TEXT,
    risk_score      FLOAT           NOT NULL DEFAULT 0.0,
    anomaly_count   INTEGER         NOT NULL DEFAULT 0,

    first_seen      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    UNIQUE (entity_type, entity_id)
);

CREATE INDEX idx_entity_profiles_risk   ON entity_profiles (risk_score DESC);
CREATE INDEX idx_entity_profiles_lookup ON entity_profiles (entity_type, entity_id);

-- ─── 4. Audit Log (HMAC tamper-evident chain) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL       PRIMARY KEY,
    event_time      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    action          TEXT            NOT NULL,
    actor           TEXT            NOT NULL,
    target          TEXT,
    details         JSONB,
    source_ip       INET,
    result          TEXT            NOT NULL DEFAULT 'success', -- success | failure
    chain_hash      TEXT            NOT NULL, -- HMAC of previous row
    agent_hostname  TEXT            NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_log_time         ON audit_log (event_time DESC);
CREATE INDEX idx_audit_log_actor        ON audit_log (actor);
CREATE INDEX idx_audit_log_action       ON audit_log (action);

-- ─── 5. JWT Token Blacklist (revoked tokens) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS token_blacklist (
    jti             TEXT            PRIMARY KEY, -- JWT ID
    revoked_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL,    -- Auto-purge when past expiry
    revoked_by      TEXT,
    reason          TEXT            -- logout | admin_revoke | password_change
);

CREATE INDEX idx_token_blacklist_expires ON token_blacklist (expires_at);

-- ─── 6. IOC Database (persistent cache) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_entries (
    id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    value           TEXT            NOT NULL,
    ioc_type        ioc_type        NOT NULL,
    threat_level    TEXT            NOT NULL DEFAULT 'HIGH',
    source          TEXT            NOT NULL,
    tags            TEXT[]          NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    hit_count       INTEGER         NOT NULL DEFAULT 0,
    UNIQUE (value, ioc_type)
);

CREATE INDEX idx_ioc_value              ON ioc_entries (value);
CREATE INDEX idx_ioc_type               ON ioc_entries (ioc_type);
CREATE INDEX idx_ioc_source             ON ioc_entries (source);

-- ─── 7. ML Feedback (for continuous learning) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_feedback (
    id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id        UUID            NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    is_true_positive BOOLEAN        NOT NULL,
    analyst         TEXT            NOT NULL,
    feedback_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    features_json   JSONB,          -- Stored feature vector for retraining
    model_version   TEXT,
    notes           TEXT
);

CREATE INDEX idx_ml_feedback_alert      ON ml_feedback (alert_id);
CREATE INDEX idx_ml_feedback_time       ON ml_feedback (feedback_at DESC);
CREATE INDEX idx_ml_feedback_analyst    ON ml_feedback (analyst);

-- ─── 8. FIM Baseline (file integrity) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fim_baseline (
    id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    path            TEXT            NOT NULL UNIQUE,
    hash_blake3     TEXT            NOT NULL,
    hash_sha256     TEXT,
    size_bytes      BIGINT,
    permissions     TEXT,
    owner           TEXT,
    group_owner     TEXT,
    last_modified   TIMESTAMPTZ,
    baseline_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    verified_clean  BOOLEAN         NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_fim_path               ON fim_baseline (path);
CREATE INDEX idx_fim_updated            ON fim_baseline (updated_at DESC);

-- ─── 9. System Metrics Snapshots ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapped_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    agent_hostname  TEXT            NOT NULL,
    packets_processed BIGINT,
    packets_dropped   BIGINT,
    active_flows      INTEGER,
    total_alerts      BIGINT,
    ioc_count         INTEGER,
    ws_clients        INTEGER,
    cpu_usage_pct     FLOAT,
    mem_usage_mb      FLOAT
);

CREATE INDEX idx_metrics_time           ON metrics_snapshots (snapped_at DESC);
CREATE INDEX idx_metrics_agent          ON metrics_snapshots (agent_hostname, snapped_at DESC);

-- ─── Retention policy helper (run via pg_cron or external cron) ──────────────
-- DELETE FROM alerts WHERE detected_at < NOW() - INTERVAL '90 days' AND status = 'resolved';
-- DELETE FROM token_blacklist WHERE expires_at < NOW();
-- DELETE FROM metrics_snapshots WHERE snapped_at < NOW() - INTERVAL '30 days';

-- ─── Views ────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_alert_summary AS
SELECT
    DATE_TRUNC('hour', detected_at) AS hour,
    threat_level,
    rule_type,
    COUNT(*)                        AS count
FROM alerts
GROUP BY 1, 2, 3;

CREATE OR REPLACE VIEW v_top_attackers AS
SELECT
    src_ip,
    COUNT(*)            AS alert_count,
    MAX(threat_level::TEXT) AS max_severity,
    MAX(detected_at)    AS last_seen,
    ARRAY_AGG(DISTINCT rule_name) AS rules_triggered
FROM alerts
WHERE src_ip IS NOT NULL
  AND detected_at > NOW() - INTERVAL '24 hours'
GROUP BY src_ip
ORDER BY alert_count DESC
LIMIT 100;

CREATE OR REPLACE VIEW v_active_campaigns AS
SELECT
    c.*,
    COUNT(a.id) AS total_alerts
FROM campaigns c
LEFT JOIN alerts a ON a.campaign_id = c.id
WHERE c.status = 'active'
GROUP BY c.id
ORDER BY c.last_seen DESC;

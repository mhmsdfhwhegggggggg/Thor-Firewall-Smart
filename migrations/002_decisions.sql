-- ═══════════════════════════════════════════════════════════════════════════════
-- Thor Firewall Smart — Migration 002: SOC Decisions + Federated Learning
-- ═══════════════════════════════════════════════════════════════════════════════
-- Adds:
--   - soc_decisions: Human-in-the-loop SOC approval/rejection records
--   - fl_model_versions: Federated learning model version tracking
--   - fl_gradient_deltas: Gradient updates from agents (before aggregation)
--   - pending_decisions: View for SOC analyst dashboard
-- ═══════════════════════════════════════════════════════════════════════════════

-- ─── Enum: decision outcome ───────────────────────────────────────────────────
CREATE TYPE decision_outcome AS ENUM ('pending', 'approved', 'rejected', 'expired', 'auto_approved');
CREATE TYPE agent_type AS ENUM ('net', 'web', 'srv', 'soc', 'agent');
CREATE TYPE model_status AS ENUM ('training', 'pending_review', 'approved', 'deployed', 'deprecated');

-- ─── 1. SOC Decisions ─────────────────────────────────────────────────────────
-- Records every autonomous decision made by agents and human SOC interventions.
CREATE TABLE IF NOT EXISTS soc_decisions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id        UUID NOT NULL REFERENCES alerts(id) ON DELETE SET NULL,

    -- Who made the decision
    agent_type      agent_type  NOT NULL,
    agent_hostname  TEXT,

    -- What was decided
    action          TEXT        NOT NULL,  -- e.g. "block_ip", "quarantine_file", "isolate_namespace"
    target          TEXT        NOT NULL,  -- e.g. "192.168.1.100", "/tmp/malware.exe"
    outcome         decision_outcome NOT NULL DEFAULT 'pending',

    -- ML context
    ml_confidence   REAL,
    ml_model_version TEXT,
    xai_explanation JSONB,  -- Top-3 feature contributions from ONNX XAI

    -- Human review
    reviewed_by     TEXT,   -- SOC analyst username (NULL = autonomous)
    reviewed_at     TIMESTAMPTZ,
    review_notes    TEXT,

    -- Audit trail
    auto_threshold  REAL,   -- SOC auto-block threshold at decision time
    escalation_reason TEXT, -- Why it was escalated to human review

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ DEFAULT NOW() + INTERVAL '4 hours',  -- Pending decisions expire

    -- Foreign keys
    CONSTRAINT fk_alert FOREIGN KEY (event_id) REFERENCES alerts(id)
);

-- Indexes
CREATE INDEX idx_soc_decisions_event_id  ON soc_decisions(event_id);
CREATE INDEX idx_soc_decisions_outcome   ON soc_decisions(outcome) WHERE outcome = 'pending';
CREATE INDEX idx_soc_decisions_created   ON soc_decisions(created_at DESC);
CREATE INDEX idx_soc_decisions_agent     ON soc_decisions(agent_type, agent_hostname);

-- Row-Level Security
ALTER TABLE soc_decisions ENABLE ROW LEVEL SECURITY;
CREATE POLICY soc_decisions_analyst ON soc_decisions
    FOR ALL TO thor_analyst USING (true);
CREATE POLICY soc_decisions_readonly ON soc_decisions
    FOR SELECT TO thor_readonly USING (true);

-- ─── 2. Federated Learning Model Versions ────────────────────────────────────
CREATE TABLE IF NOT EXISTS fl_model_versions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name      TEXT NOT NULL,   -- e.g. "thor_master_brain_v3_2026"
    version_tag     TEXT NOT NULL,   -- e.g. "v3.2.1"
    status          model_status NOT NULL DEFAULT 'pending_review',

    -- Model metadata
    architecture    TEXT,            -- e.g. "IsolationForest+LSTM"
    training_rounds INTEGER DEFAULT 0,
    participating_agents INTEGER DEFAULT 0,
    jsd_drift_score REAL,           -- Jensen-Shannon divergence metric

    -- Storage
    model_hash      TEXT NOT NULL,   -- SHA-256 of model file
    model_size_bytes BIGINT,
    storage_path    TEXT,            -- s3:// or local path

    -- Performance metrics
    precision_score REAL,
    recall_score    REAL,
    f1_score        REAL,
    auc_roc         REAL,
    false_positive_rate REAL,

    -- Review
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    deployed_at     TIMESTAMPTZ,
    deprecated_at   TIMESTAMPTZ,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fl_models_status  ON fl_model_versions(status);
CREATE INDEX idx_fl_models_name    ON fl_model_versions(model_name, created_at DESC);
CREATE UNIQUE INDEX idx_fl_models_unique ON fl_model_versions(model_name, version_tag);

-- ─── 3. Federated Learning Gradient Deltas ───────────────────────────────────
-- Stores gradient updates from each agent before FedAvg aggregation
CREATE TABLE IF NOT EXISTS fl_gradient_deltas (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_version_id UUID NOT NULL REFERENCES fl_model_versions(id),

    agent_id        TEXT NOT NULL,
    agent_hostname  TEXT,
    agent_type      agent_type,
    round_number    INTEGER NOT NULL,

    -- Gradient data (compressed)
    gradient_hash   TEXT NOT NULL,      -- SHA-256 of gradient delta (integrity check)
    gradient_size_bytes BIGINT,
    gradient_checksum TEXT,

    -- Metadata
    local_samples   INTEGER,            -- Number of local training samples used
    local_loss      REAL,
    local_accuracy  REAL,
    training_duration_ms INTEGER,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fl_gradients_model ON fl_gradient_deltas(model_version_id);
CREATE INDEX idx_fl_gradients_round ON fl_gradient_deltas(round_number);

-- ─── 4. Views ─────────────────────────────────────────────────────────────────

-- SOC analyst: pending decisions requiring human review
CREATE OR REPLACE VIEW pending_decisions AS
SELECT
    sd.id,
    sd.action,
    sd.target,
    sd.agent_type,
    sd.agent_hostname,
    sd.ml_confidence,
    sd.xai_explanation,
    sd.escalation_reason,
    sd.expires_at,
    a.threat_level,
    a.rule_name,
    a.message,
    a.src_ip,
    a.dst_ip,
    a.mitre_tactic,
    sd.created_at
FROM soc_decisions sd
LEFT JOIN alerts a ON a.id = sd.event_id
WHERE sd.outcome = 'pending'
  AND sd.expires_at > NOW()
ORDER BY sd.ml_confidence DESC, sd.created_at ASC;

-- Aggregated FL round status
CREATE OR REPLACE VIEW fl_aggregation_status AS
SELECT
    model_version_id,
    round_number,
    COUNT(*) as agents_reported,
    AVG(local_loss) as avg_loss,
    AVG(local_accuracy) as avg_accuracy,
    MAX(created_at) as last_update
FROM fl_gradient_deltas
GROUP BY model_version_id, round_number
ORDER BY round_number DESC;

-- ─── 5. Schema version tracking ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_migrations (version, description)
VALUES ('002', 'SOC decisions + Federated Learning model tracking + gradient deltas')
ON CONFLICT (version) DO NOTHING;

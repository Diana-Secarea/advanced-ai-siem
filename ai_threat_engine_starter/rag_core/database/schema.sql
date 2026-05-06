-- =============================================================
-- Wazuh AI Threat Engine — PostgreSQL Schema
-- =============================================================

-- ------------------------------------------------------------------
-- 1. THREAT INTELLIGENCE  (raw records from all ingestion sources)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel (
    id          SERIAL PRIMARY KEY,
    source_id   VARCHAR(512) NOT NULL,        -- e.g. "CVE-2021-44228", "T1566"
    source_type VARCHAR(60)  NOT NULL,        -- 'cisa_kev', 'mitre_attack', 'sigma', ...
    name        VARCHAR(512),
    description TEXT,
    raw_data    JSONB        NOT NULL,         -- full original record
    tags        TEXT[]       DEFAULT '{}',
    ingested_at TIMESTAMPTZ  DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  DEFAULT NOW(),
    CONSTRAINT uq_threat_intel UNIQUE (source_id, source_type)
);

CREATE INDEX IF NOT EXISTS idx_ti_source_type ON threat_intel (source_type);
CREATE INDEX IF NOT EXISTS idx_ti_source_id   ON threat_intel (source_id);
CREATE INDEX IF NOT EXISTS idx_ti_tags        ON threat_intel USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_ti_raw         ON threat_intel USING GIN (raw_data);
CREATE INDEX IF NOT EXISTS idx_ti_ingested    ON threat_intel (ingested_at);

-- ------------------------------------------------------------------
-- 2. WAZUH ALERTS  (every alert processed by the system)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wazuh_alerts (
    id               SERIAL PRIMARY KEY,
    alert_id         VARCHAR(255),
    rule_id          INTEGER,
    rule_level       SMALLINT,
    rule_description VARCHAR(512),
    agent_id         VARCHAR(50),
    agent_name       VARCHAR(255),
    src_ip           INET,
    alert_timestamp  TIMESTAMPTZ,
    full_log         TEXT,
    raw_alert        JSONB        NOT NULL,
    anomaly_score    FLOAT,
    is_anomaly       BOOLEAN      DEFAULT FALSE,
    ingested_at      TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON wazuh_alerts (alert_timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id    ON wazuh_alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_level      ON wazuh_alerts (rule_level);
CREATE INDEX IF NOT EXISTS idx_alerts_agent      ON wazuh_alerts (agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_is_anomaly ON wazuh_alerts (is_anomaly);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON wazuh_alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_raw        ON wazuh_alerts USING GIN (raw_alert);

-- ------------------------------------------------------------------
-- 3. ALERT EPISODES  (processed/grouped alerts with context)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_episodes (
    id           SERIAL PRIMARY KEY,
    episode_id   VARCHAR(255) UNIQUE NOT NULL,
    episode_type VARCHAR(50),                  -- 'authentication', 'process', 'network', 'alert'
    summary      TEXT,
    tags         TEXT[]    DEFAULT '{}',
    entities     JSONB     DEFAULT '{}',
    time_start   TIMESTAMPTZ,
    time_end     TIMESTAMPTZ,
    metadata     JSONB     DEFAULT '{}',
    qdrant_id    VARCHAR(255),                 -- UUID of the point in Qdrant
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ep_type     ON alert_episodes (episode_type);
CREATE INDEX IF NOT EXISTS idx_ep_time     ON alert_episodes (time_start);
CREATE INDEX IF NOT EXISTS idx_ep_tags     ON alert_episodes USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_ep_entities ON alert_episodes USING GIN (entities);

-- ------------------------------------------------------------------
-- 4. INGESTION RUN LOG  (tracks when each source was last refreshed)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ingestion_log (
    id          SERIAL PRIMARY KEY,
    source_type VARCHAR(60) NOT NULL,
    started_at  TIMESTAMPTZ DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    records_upserted INTEGER DEFAULT 0,
    status      VARCHAR(20) DEFAULT 'running',  -- 'running', 'ok', 'error'
    error_msg   TEXT,
    CONSTRAINT uq_ingestion_log UNIQUE (source_type, started_at)
);

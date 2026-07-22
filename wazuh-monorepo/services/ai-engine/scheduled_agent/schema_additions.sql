-- =============================================================
-- Wazuh AI Threat Engine — Schema additions for the CVE ingestion agent
--
-- Idempotent: safe to run on every agent startup (ensure_schema()).
-- Extends the existing rag_core/database/schema.sql.
-- =============================================================

-- ------------------------------------------------------------------
-- 1. ingestion_log  — run-level rollup columns
--    (one row per agent run; the existing table only tracked
--     records_upserted, so we add the decision-bucket counters the
--     thesis promises: evaluated / indexed / queued / dropped)
-- ------------------------------------------------------------------
ALTER TABLE ingestion_log ADD COLUMN IF NOT EXISTS cves_evaluated  INTEGER     DEFAULT 0;
ALTER TABLE ingestion_log ADD COLUMN IF NOT EXISTS cves_indexed    INTEGER     DEFAULT 0;
ALTER TABLE ingestion_log ADD COLUMN IF NOT EXISTS cves_queued     INTEGER     DEFAULT 0;
ALTER TABLE ingestion_log ADD COLUMN IF NOT EXISTS cves_dropped    INTEGER     DEFAULT 0;
ALTER TABLE ingestion_log ADD COLUMN IF NOT EXISTS cves_duplicate  INTEGER     DEFAULT 0;
ALTER TABLE ingestion_log ADD COLUMN IF NOT EXISTS cursor_used     TIMESTAMPTZ;

-- ------------------------------------------------------------------
-- 2. cve_decisions  — CVE-level audit ledger (the backbone)
--    One row per CVE per run. The `decision` column is the bucket:
--      'indexed'   -> final_score >= 7  (also in threat_intel + Qdrant)
--      'queued'    -> 4 <= final_score < 7  (HELD OUT of Qdrant)
--      'dropped'   -> final_score < 4  (audit only, never indexed)
--      'duplicate' -> already known, skipped before scoring
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_decisions (
    id            SERIAL PRIMARY KEY,
    cve_id        VARCHAR(32)  NOT NULL,
    source_type   VARCHAR(60)  NOT NULL,                 -- 'nvd' | 'cisa_kev'
    run_id        INTEGER      REFERENCES ingestion_log(id),
    base_score    SMALLINT,                              -- LLM 0-10 before boost
    boost         SMALLINT     DEFAULT 0,                -- rule + alert-history bonus
    final_score   SMALLINT,                              -- min(base + boost, 10)
    decision      VARCHAR(12)  NOT NULL,                 -- indexed|queued|dropped|duplicate
    reasoning     TEXT,                                  -- LLM relevance explanation
    boost_reason  TEXT,                                  -- why it was boosted (auditable)
    raw_cve       JSONB        NOT NULL,                 -- full source record
    qdrant_id     VARCHAR(255),                          -- set only when indexed
    decided_at    TIMESTAMPTZ  DEFAULT NOW(),
    CONSTRAINT uq_cve_run UNIQUE (cve_id, run_id)
);

CREATE INDEX IF NOT EXISTS idx_cd_decision ON cve_decisions (decision);
CREATE INDEX IF NOT EXISTS idx_cd_cve      ON cve_decisions (cve_id);
CREATE INDEX IF NOT EXISTS idx_cd_score    ON cve_decisions (final_score);
CREATE INDEX IF NOT EXISTS idx_cd_decided  ON cve_decisions (decided_at);
CREATE INDEX IF NOT EXISTS idx_cd_run      ON cve_decisions (run_id);

-- ------------------------------------------------------------------
-- 3. pending_review  — the human review queue (a VIEW, not a table)
--    Mid-score CVEs are quarantined here and WITHHELD from RAG until
--    a human flips their decision to 'indexed'.
-- ------------------------------------------------------------------
CREATE OR REPLACE VIEW pending_review AS
SELECT cve_id,
       source_type,
       final_score,
       reasoning,
       boost_reason,
       raw_cve,
       decided_at
FROM   cve_decisions
WHERE  decision = 'queued'
ORDER BY final_score DESC, decided_at DESC;

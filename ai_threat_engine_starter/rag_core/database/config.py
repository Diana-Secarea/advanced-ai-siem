"""
Database connection configuration.
Values can be overridden with environment variables.
"""
import os

# PostgreSQL
PG_HOST     = os.environ.get("PG_HOST",     "localhost")
PG_PORT     = int(os.environ.get("PG_PORT", "5432"))
PG_DB       = os.environ.get("PG_DB",       "wazuh_ai")
PG_USER     = os.environ.get("PG_USER",     "wazuh")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "wazuh_ai_2024")

PG_DSN = f"host={PG_HOST} port={PG_PORT} dbname={PG_DB} user={PG_USER} password={PG_PASSWORD}"

# Qdrant
QDRANT_HOST = os.environ.get("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", "6333"))

# Collection names
COLLECTION_THREAT_INTEL    = "wazuh_threat_intel"
COLLECTION_ALERT_EPISODES  = "wazuh_alert_episodes"

# Embedding models
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM   = 384
SPARSE_MODEL    = "Qdrant/bm25"  # BM25 keyword sparse vectors via fastembed

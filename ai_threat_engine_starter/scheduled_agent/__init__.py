"""Scheduled CVE ingestion agent for the Wazuh AI Threat Engine.

A scheduled agentic workflow that periodically fetches CVEs from NVD and
CISA-KEV, deduplicates them, boosts relevance with environment evidence
(Wazuh rules + historical alerts), scores each 0-10 with a local LLM, and
records every decision in PostgreSQL. High-scoring CVEs are indexed into
Qdrant; mid-range are quarantined for human review; low-scoring are
audit-logged.

PostgreSQL is the audit/analytics backbone; Qdrant serves only verified
intelligence.
"""

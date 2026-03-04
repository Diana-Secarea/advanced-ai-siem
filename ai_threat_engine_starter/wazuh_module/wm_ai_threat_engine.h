/*
 * Wazuh Module for AI Threat Engine
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AI_THREAT_ENGINE_H
#define WM_AI_THREAT_ENGINE_H

#define WM_AI_THREAT_ENGINE_LOGTAG ARGV0 ":ai-threat-engine"
#define WM_AI_THREAT_ENGINE_DEFAULT_INTERVAL 5

typedef struct wm_ai_threat_engine_state_t {
    time_t last_analysis;
    unsigned long events_processed;
    unsigned long anomalies_detected;
} wm_ai_threat_engine_state_t;

typedef struct wm_ai_threat_engine_t {
    char *tag;
    char *python_path;              // Path to Python interpreter
    char *ai_engine_script;         // Path to AI engine Python script
    char *model_path;                // Path to ML model
    char *vector_db_path;            // Path to vector database for RAG
    int queue_fd;                    // Queue file descriptor
    int enabled;
    int anomaly_threshold;           // Anomaly score threshold (0-100)
    int batch_size;                  // Events to batch before processing
    int api_port;                    // REST API port for LLM service
    wm_ai_threat_engine_state_t state;
    sched_scan_config scan_config;
} wm_ai_threat_engine_t;

extern const wm_context WM_AI_THREAT_ENGINE_CONTEXT;

// Parse XML configuration
int wm_ai_threat_engine_read(xml_node **nodes, wmodule *module, int agent_cfg);

#endif // WM_AI_THREAT_ENGINE_H

/*
 * Wazuh Module for AI Threat Engine
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "wm_ai_threat_engine.h"

// Forward declarations
static void *wm_ai_threat_engine_main(wm_ai_threat_engine_t *config);
static void wm_ai_threat_engine_destroy(wm_ai_threat_engine_t *config);
static cJSON *wm_ai_threat_engine_dump(const wm_ai_threat_engine_t *config);
static void process_event_with_ai(wm_ai_threat_engine_t *config, const char *event_json);
static void generate_ai_alert(wm_ai_threat_engine_t *config, const char *event_json, cJSON *ai_analysis);

// Module context definition
const wm_context WM_AI_THREAT_ENGINE_CONTEXT = {
    .name = "ai-threat-engine",
    .start = (wm_routine)wm_ai_threat_engine_main,
    .destroy = (void(*)(void *))wm_ai_threat_engine_destroy,
    .dump = (cJSON * (*)(const void *))wm_ai_threat_engine_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

// Module main function
void *wm_ai_threat_engine_main(wm_ai_threat_engine_t *config) {
    if (!config->enabled) {
        mtinfo(WM_AI_THREAT_ENGINE_LOGTAG, "AI Threat Engine disabled. Exiting.");
        pthread_exit(0);
    }

    // Connect to queue
    config->queue_fd = StartMQ(DEFAULTQUEUE, READ, INFINITE_OPENQ_ATTEMPTS);
    if (config->queue_fd < 0) {
        mterror(WM_AI_THREAT_ENGINE_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    mtinfo(WM_AI_THREAT_ENGINE_LOGTAG, "AI Threat Engine started");

    // Initialize Python AI engine
    char *init_cmd;
    os_malloc(OS_SIZE_2048, init_cmd);
    snprintf(init_cmd, OS_SIZE_2048, "%s %s --init --model-path %s --vector-db %s",
             config->python_path ? config->python_path : "/usr/bin/python3",
             config->ai_engine_script ? config->ai_engine_script : "/var/ossec/ai_engine/main.py",
             config->model_path ? config->model_path : "/var/ossec/ai_models",
             config->vector_db_path ? config->vector_db_path : "/var/ossec/ai_models/vector_db");
    
    // Execute initialization
    int status = 0;
    char *output = NULL;
    wm_exec(init_cmd, &output, &status, 30, NULL);
    os_free(init_cmd);
    if (output) os_free(output);

    // Main processing loop
    do {
        // Read events from queue
        char *event_json = NULL;
        size_t event_size = 0;
        
        if (ReadMQ(config->queue_fd, event_json, &event_size, 0) == 0) {
            // Process event with AI engine
            process_event_with_ai(config, event_json);
            os_free(event_json);
        }
        
        // Batch processing every N events
        if (config->state.events_processed % config->batch_size == 0) {
            mtdebug1(WM_AI_THREAT_ENGINE_LOGTAG, "Processed %lu events, %lu anomalies detected",
                     config->state.events_processed, config->state.anomalies_detected);
        }
        
    } while (FOREVER());

    return NULL;
}

static void process_event_with_ai(wm_ai_threat_engine_t *config, const char *event_json) {
    if (!event_json || !strlen(event_json)) {
        return;
    }

    // Call Python AI engine
    char *cmd;
    os_malloc(OS_SIZE_8192, cmd);
    snprintf(cmd, OS_SIZE_8192,
             "%s %s --analyze --event '%s' --threshold %d",
             config->python_path ? config->python_path : "/usr/bin/python3",
             config->ai_engine_script ? config->ai_engine_script : "/var/ossec/ai_engine/main.py",
             event_json, config->anomaly_threshold);
    
    int status = 0;
    char *output = NULL;
    wm_exec(cmd, &output, &status, 10, NULL);
    
    if (output) {
        // Parse AI analysis result
        cJSON *result = cJSON_Parse(output);
        if (result) {
            cJSON *anomaly_score = cJSON_GetObjectItem(result, "anomaly_score");
            cJSON *is_anomaly = cJSON_GetObjectItem(result, "is_anomaly");
            
            if (is_anomaly && cJSON_IsTrue(is_anomaly)) {
                if (anomaly_score && anomaly_score->valueint >= config->anomaly_threshold) {
                    // Generate enhanced alert
                    generate_ai_alert(config, event_json, result);
                    config->state.anomalies_detected++;
                }
            }
            
            cJSON_Delete(result);
        }
        os_free(output);
    }
    
    os_free(cmd);
    config->state.events_processed++;
}

static void generate_ai_alert(wm_ai_threat_engine_t *config, 
                               const char *event_json, 
                               cJSON *ai_analysis) {
    // Create enhanced alert with AI insights
    char *alert_msg;
    os_malloc(OS_SIZE_4096, alert_msg);
    
    cJSON *threat_level = cJSON_GetObjectItem(ai_analysis, "threat_level");
    cJSON *confidence = cJSON_GetObjectItem(ai_analysis, "confidence");
    cJSON *pattern = cJSON_GetObjectItem(ai_analysis, "pattern_match");
    
    snprintf(alert_msg, OS_SIZE_4096,
             "AI Threat Detection: %s (Confidence: %d%%, Pattern: %s) - %s",
             threat_level ? cJSON_GetStringValue(threat_level) : "UNKNOWN",
             confidence ? confidence->valueint : 0,
             pattern ? cJSON_GetStringValue(pattern) : "N/A",
             event_json);
    
    // Send to analysisd queue
    wm_sendmsg(100000, config->queue_fd, alert_msg, 
               "ai-threat-engine", LOCALFILE_MQ);
    
    os_free(alert_msg);
}

// Dump configuration
cJSON *wm_ai_threat_engine_dump(const wm_ai_threat_engine_t *config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_ai = cJSON_CreateObject();

    sched_scan_dump(&(config->scan_config), wm_ai);

    if (config->enabled) {
        cJSON_AddStringToObject(wm_ai, "disabled", "no");
    } else {
        cJSON_AddStringToObject(wm_ai, "disabled", "yes");
    }

    if (config->tag) {
        cJSON_AddStringToObject(wm_ai, "tag", config->tag);
    }
    if (config->python_path) {
        cJSON_AddStringToObject(wm_ai, "python_path", config->python_path);
    }
    if (config->ai_engine_script) {
        cJSON_AddStringToObject(wm_ai, "ai_engine_script", config->ai_engine_script);
    }
    if (config->model_path) {
        cJSON_AddStringToObject(wm_ai, "model_path", config->model_path);
    }
    if (config->vector_db_path) {
        cJSON_AddStringToObject(wm_ai, "vector_db_path", config->vector_db_path);
    }

    cJSON_AddNumberToObject(wm_ai, "anomaly_threshold", config->anomaly_threshold);
    cJSON_AddNumberToObject(wm_ai, "batch_size", config->batch_size);
    cJSON_AddNumberToObject(wm_ai, "api_port", config->api_port);

    cJSON_AddItemToObject(root, "ai-threat-engine", wm_ai);
    return root;
}

// Destroy configuration
void wm_ai_threat_engine_destroy(wm_ai_threat_engine_t *config) {
    if (config) {
        free(config->tag);
        free(config->python_path);
        free(config->ai_engine_script);
        free(config->model_path);
        free(config->vector_db_path);
        free(config);
    }
}

// Read XML configuration
int wm_ai_threat_engine_read(xml_node **nodes, wmodule *module, int agent_cfg) {
    wm_ai_threat_engine_t *config;
    wm_ai_threat_engine_t *aux_config;
    xml_node *child;
    int enabled = 1;

    os_calloc(1, sizeof(wm_ai_threat_engine_t), config);
    config->enabled = 1;
    config->anomaly_threshold = 70;
    config->batch_size = 100;
    config->api_port = 8000;
    config->queue_fd = -1;

    // Default paths
    os_strdup("/usr/bin/python3", config->python_path);
    os_strdup("/var/ossec/ai_engine/main.py", config->ai_engine_script);
    os_strdup("/var/ossec/ai_models", config->model_path);
    os_strdup("/var/ossec/ai_models/vector_db", config->vector_db_path);

    if (!nodes) {
        return 0;
    }

    for (child = *nodes; child; child = child->next) {
        if (!child->element) {
            continue;
        } else if (!strcmp(child->element, "enabled")) {
            if (!strcmp(child->content, "yes")) {
                enabled = 1;
            } else {
                enabled = 0;
            }
        } else if (!strcmp(child->element, "tag")) {
            os_strdup(child->content, config->tag);
        } else if (!strcmp(child->element, "python_path")) {
            free(config->python_path);
            os_strdup(child->content, config->python_path);
        } else if (!strcmp(child->element, "ai_engine_script")) {
            free(config->ai_engine_script);
            os_strdup(child->content, config->ai_engine_script);
        } else if (!strcmp(child->element, "model_path")) {
            free(config->model_path);
            os_strdup(child->content, config->model_path);
        } else if (!strcmp(child->element, "vector_db_path")) {
            free(config->vector_db_path);
            os_strdup(child->content, config->vector_db_path);
        } else if (!strcmp(child->element, "anomaly_threshold")) {
            config->anomaly_threshold = atoi(child->content);
            if (config->anomaly_threshold < 0 || config->anomaly_threshold > 100) {
                config->anomaly_threshold = 70;
            }
        } else if (!strcmp(child->element, "batch_size")) {
            config->batch_size = atoi(child->content);
            if (config->batch_size < 1) {
                config->batch_size = 100;
            }
        } else if (!strcmp(child->element, "api_port")) {
            config->api_port = atoi(child->content);
        } else if (!strcmp(child->element, "interval")) {
            if (sched_scan_read(&(config->scan_config), child, WM_AI_THREAT_ENGINE_LOGTAG) < 0) {
                mterror(WM_AI_THREAT_ENGINE_LOGTAG, "Invalid interval value.");
                wm_ai_threat_engine_destroy(config);
                return OS_INVALID;
            }
        } else {
            mterror(WM_AI_THREAT_ENGINE_LOGTAG, "No such tag '%s'", child->element);
        }
    }

    config->enabled = enabled;

    if (config->enabled) {
        aux_config = (wm_ai_threat_engine_t *)module->data;
        if (aux_config) {
            aux_config->next = config;
        } else {
            module->data = config;
        }
    } else {
        wm_ai_threat_engine_destroy(config);
    }

    return 0;
}

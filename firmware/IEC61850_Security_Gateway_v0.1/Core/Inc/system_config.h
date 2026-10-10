#ifndef SYSTEM_CONFIG_H
#define SYSTEM_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SYS_CONFIG_FILE "0:/config/system_config.bin"
#define SYS_CONFIG_LEGACY_FILE "0:/system_config.json"
#define GATEWAY_NAME_MAX_LEN 32

/* GOOSE IDS Settings */
typedef struct
{
    bool timing_check_enabled;     /* Enable/disable timing jitter checks (FAST/SLOW) */
    bool state_check_enabled;      /* Enable/disable stNum/sqNum state anomaly checks */
    bool baseline_check_enabled;   /* Enable/disable SCD parameter matching checks */
    uint32_t min_time_fallback_ms; /* Fallback minTime (ms) if 0 or missing in SCD (1..1000) */
    uint32_t max_time_fallback_ms; /* Fallback maxTime (ms) if 0 or missing in SCD (10..60000) */
    uint32_t ttl_multiplier;       /* Fallback multiplier for maxTime when TTL is 0 (1..10) */
} GooseConfig_t;

/* Sampled Values (SV) IDS Settings */
typedef struct
{
    bool smpcnt_check_enabled;        /* Enable/disable duplicate, gap, rollback checks */
    bool baseline_check_enabled;      /* Enable/disable SCD stream matching checks */
    uint32_t sample_rate_fallback;    /* Fallback sample rate (Hz) if 0 or missing (1000..12800) */
    uint32_t idle_timeout_ms;         /* Idle stream restart threshold (ms) (10..5000) */
    uint32_t wrap_boundary_tolerance; /* Max smpCnt count at wrap boundary (10..1000) */
} SvConfig_t;

/* MMS Protection Settings */
typedef struct
{
    bool inspection_enabled;     /* Enable/disable MMS inspection */
    bool baseline_check_enabled; /* Enable/disable SCD endpoint whitelist checks */
    uint16_t tcp_port;           /* Expected standard MMS TCP port (1..65535) */
} MmsConfig_t;

/* Alerts & Logging Settings */
typedef struct
{
    uint32_t alert_aggregation_window_ms;    /* Burst aggregation window (ms) (50..5000) */
    uint32_t alert_aggregation_max_ms;       /* Max aggregation time before flush (ms) (100..10000) */
    uint32_t normal_traffic_log_interval_ms; /* Throttle interval for normal traffic logs (ms) (10..5000) */
    uint32_t anomaly_print_interval_ms;      /* Console diagnostic print throttle (ms) (100..10000) */
    bool sd_logging_enabled;                 /* Enable/disable writing alerts to SD card file */
} AlertsConfig_t;

/* System Identity Settings */
typedef struct
{
    char gateway_name[GATEWAY_NAME_MAX_LEN]; /* Gateway device identifier string */
} GatewaySystemConfig_t;

/* Master Configuration Structure */
typedef struct
{
    GooseConfig_t goose;
    SvConfig_t sv;
    MmsConfig_t mms;
    AlertsConfig_t alerts;
    GatewaySystemConfig_t system;
} SystemConfig_t;

void SystemConfig_Init(void);
void SystemConfig_Get(SystemConfig_t *dest);
bool SystemConfig_Set(const SystemConfig_t *src);
void SystemConfig_ResetToDefaults(void);
bool SystemConfig_SaveToSD(void);
bool SystemConfig_LoadFromSD(void);
bool SystemConfig_Validate(const SystemConfig_t *cfg);
int SystemConfig_ToJson(const SystemConfig_t *cfg, char *buf, size_t max_len);
bool SystemConfig_FromJson(const char *json, SystemConfig_t *cfg);

#endif /* SYSTEM_CONFIG_H */

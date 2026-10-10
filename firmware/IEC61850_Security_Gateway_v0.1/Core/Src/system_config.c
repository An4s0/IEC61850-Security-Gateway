#include "system_config.h"
#include "system_logger.h"
#include "security.h"
#include "fatfs.h"
#include "ff.h"
#include "cmsis_os.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static SystemConfig_t s_active_config;
static bool s_initialized = false;

static osMutexId s_sys_config_mutex = NULL;
osMutexDef(SysConfigMutex);

static const SystemConfig_t s_default_config = {
    .goose = {
        .timing_check_enabled = true,
        .state_check_enabled = true,
        .baseline_check_enabled = true,
        .min_time_fallback_ms = 4,
        .max_time_fallback_ms = 1000,
        .ttl_multiplier = 2},
    .sv = {.smpcnt_check_enabled = true, .baseline_check_enabled = true, .sample_rate_fallback = 4000, .idle_timeout_ms = 150, .wrap_boundary_tolerance = 100},
    .mms = {.inspection_enabled = true, .baseline_check_enabled = true, .tcp_port = 102},
    .alerts = {.alert_aggregation_window_ms = 350, .alert_aggregation_max_ms = 1000, .normal_traffic_log_interval_ms = 100, .anomaly_print_interval_ms = 1000, .sd_logging_enabled = true},
    .system = {.gateway_name = "IEC61850-Security-Gateway"}};

/**
 * @brief Acquires the system configuration mutex if it exists.
 */
static void lock_config(void)
{
    if (s_sys_config_mutex != NULL)
    {
        osMutexWait(s_sys_config_mutex, osWaitForever);
    }
}

/**
 * @brief Releases the system configuration mutex if it exists.
 */
static void unlock_config(void)
{
    if (s_sys_config_mutex != NULL)
    {
        osMutexRelease(s_sys_config_mutex);
    }
}

/**
 * @brief Validates a configuration structure against parameter bounds.
 * @param cfg Pointer to configuration to validate.
 * @return true if all values within valid ranges, false otherwise.
 */
bool SystemConfig_Validate(const SystemConfig_t *cfg)
{
    if (cfg == NULL)
    {
        return false;
    }

    /* GOOSE validation */
    if (cfg->goose.min_time_fallback_ms < 1 || cfg->goose.min_time_fallback_ms > 1000)
    {
        return false;
    }
    if (cfg->goose.max_time_fallback_ms < 10 || cfg->goose.max_time_fallback_ms > 60000)
    {
        return false;
    }
    if (cfg->goose.min_time_fallback_ms >= cfg->goose.max_time_fallback_ms)
    {
        return false;
    }
    if (cfg->goose.ttl_multiplier < 1 || cfg->goose.ttl_multiplier > 10)
    {
        return false;
    }

    /* SV validation */
    if (cfg->sv.sample_rate_fallback < 1000 || cfg->sv.sample_rate_fallback > 12800)
    {
        return false;
    }
    if (cfg->sv.idle_timeout_ms < 10 || cfg->sv.idle_timeout_ms > 5000)
    {
        return false;
    }
    if (cfg->sv.wrap_boundary_tolerance < 10 || cfg->sv.wrap_boundary_tolerance > 1000)
    {
        return false;
    }

    /* MMS validation */
    if (cfg->mms.tcp_port == 0)
    {
        return false;
    }

    /* Alerts validation */
    if (cfg->alerts.alert_aggregation_window_ms < 50 || cfg->alerts.alert_aggregation_window_ms > 5000)
    {
        return false;
    }
    if (cfg->alerts.alert_aggregation_max_ms < 100 || cfg->alerts.alert_aggregation_max_ms > 10000)
    {
        return false;
    }
    if (cfg->alerts.alert_aggregation_window_ms > cfg->alerts.alert_aggregation_max_ms)
    {
        return false;
    }
    if (cfg->alerts.normal_traffic_log_interval_ms < 10 || cfg->alerts.normal_traffic_log_interval_ms > 5000)
    {
        return false;
    }
    if (cfg->alerts.anomaly_print_interval_ms < 100 || cfg->alerts.anomaly_print_interval_ms > 10000)
    {
        return false;
    }

    /* System validation */
    if (strlen(cfg->system.gateway_name) == 0 || strlen(cfg->system.gateway_name) >= GATEWAY_NAME_MAX_LEN)
    {
        return false;
    }

    return true;
}

/**
 * @brief Initializes the runtime configuration module, mutexes, and loads from SD card.
 */
void SystemConfig_Init(void)
{
    if (s_initialized)
    {
        return;
    }

    if (s_sys_config_mutex == NULL)
    {
        s_sys_config_mutex = osMutexCreate(osMutex(SysConfigMutex));
    }

    s_active_config = s_default_config;
    s_initialized = true;

    if (!SystemConfig_LoadFromSD())
    {
        SysLog_Print(SYSLOG_LEVEL_WARN, "CONFIG", "No configuration found; saving factory defaults to %s",
                     SYS_CONFIG_FILE);
        SystemConfig_SaveToSD();
    }
    else
    {
        SysLog_Print(SYSLOG_LEVEL_INFO, "CONFIG", "Loaded configuration from %s (Gateway: %s)",
                     SYS_CONFIG_FILE, s_active_config.system.gateway_name);
    }
}

/**
 * @brief Thread-safe retrieval of current active configuration.
 * @param dest Pointer to destination structure.
 */
void SystemConfig_Get(SystemConfig_t *dest)
{
    if (dest == NULL)
    {
        return;
    }

    lock_config();
    if (!s_initialized)
    {
        *dest = s_default_config;
    }
    else
    {
        *dest = s_active_config;
    }
    unlock_config();
}

/**
 * @brief Thread-safe update of current active configuration with validation.
 * @param src Pointer to new configuration values.
 * @return true if valid and applied, false if validation failed.
 */
bool SystemConfig_Set(const SystemConfig_t *src)
{
    if (src == NULL)
    {
        return false;
    }

    if (!SystemConfig_Validate(src))
    {
        SysLog_Print(SYSLOG_LEVEL_WARN, "CONFIG", "Validation failed for new configuration");
        return false;
    }

    lock_config();
    s_active_config = *src;
    unlock_config();

    return true;
}

/**
 * @brief Resets configuration to compiled-in factory defaults.
 */
void SystemConfig_ResetToDefaults(void)
{
    lock_config();
    s_active_config = s_default_config;
    unlock_config();
}

/**
 * @brief Serializes configuration to a JSON string.
 * @param cfg Pointer to configuration.
 * @param buf Output string buffer.
 * @param max_len Size of buffer.
 * @return Number of characters written, or -1 on overflow/error.
 */
int SystemConfig_ToJson(const SystemConfig_t *cfg, char *buf, size_t max_len)
{
    if (cfg == NULL || buf == NULL || max_len == 0)
    {
        return -1;
    }

    int ret = snprintf(buf, max_len,
                       "{\n"
                       "  \"goose\": {\n"
                       "    \"timing_check_enabled\": %s,\n"
                       "    \"state_check_enabled\": %s,\n"
                       "    \"baseline_check_enabled\": %s,\n"
                       "    \"min_time_fallback_ms\": %lu,\n"
                       "    \"max_time_fallback_ms\": %lu,\n"
                       "    \"ttl_multiplier\": %lu\n"
                       "  },\n"
                       "  \"sv\": {\n"
                       "    \"smpcnt_check_enabled\": %s,\n"
                       "    \"baseline_check_enabled\": %s,\n"
                       "    \"sample_rate_fallback\": %lu,\n"
                       "    \"idle_timeout_ms\": %lu,\n"
                       "    \"wrap_boundary_tolerance\": %lu\n"
                       "  },\n"
                       "  \"mms\": {\n"
                       "    \"inspection_enabled\": %s,\n"
                       "    \"baseline_check_enabled\": %s,\n"
                       "    \"tcp_port\": %u\n"
                       "  },\n"
                       "  \"alerts\": {\n"
                       "    \"alert_aggregation_window_ms\": %lu,\n"
                       "    \"alert_aggregation_max_ms\": %lu,\n"
                       "    \"normal_traffic_log_interval_ms\": %lu,\n"
                       "    \"anomaly_print_interval_ms\": %lu,\n"
                       "    \"sd_logging_enabled\": %s\n"
                       "  },\n"
                       "  \"system\": {\n"
                       "    \"gateway_name\": \"%s\"\n"
                       "  }\n"
                       "}",
                       cfg->goose.timing_check_enabled ? "true" : "false",
                       cfg->goose.state_check_enabled ? "true" : "false",
                       cfg->goose.baseline_check_enabled ? "true" : "false",
                       (unsigned long)cfg->goose.min_time_fallback_ms,
                       (unsigned long)cfg->goose.max_time_fallback_ms,
                       (unsigned long)cfg->goose.ttl_multiplier,
                       cfg->sv.smpcnt_check_enabled ? "true" : "false",
                       cfg->sv.baseline_check_enabled ? "true" : "false",
                       (unsigned long)cfg->sv.sample_rate_fallback,
                       (unsigned long)cfg->sv.idle_timeout_ms,
                       (unsigned long)cfg->sv.wrap_boundary_tolerance,
                       cfg->mms.inspection_enabled ? "true" : "false",
                       cfg->mms.baseline_check_enabled ? "true" : "false",
                       (unsigned int)cfg->mms.tcp_port,
                       (unsigned long)cfg->alerts.alert_aggregation_window_ms,
                       (unsigned long)cfg->alerts.alert_aggregation_max_ms,
                       (unsigned long)cfg->alerts.normal_traffic_log_interval_ms,
                       (unsigned long)cfg->alerts.anomaly_print_interval_ms,
                       cfg->alerts.sd_logging_enabled ? "true" : "false",
                       cfg->system.gateway_name);

    if (ret < 0 || (size_t)ret >= max_len)
    {
        return -1;
    }

    return ret;
}

/**
 * @brief Finds a JSON key and returns a pointer to its value.
 */
static const char *find_key(const char *json, const char *key)
{
    if (json == NULL || key == NULL)
    {
        return NULL;
    }

    size_t klen = strlen(key);
    const char *p = json;
    while ((p = strstr(p, key)) != NULL)
    {
        if (p > json && *(p - 1) == '"')
        {
            if (*(p + klen) == '"')
            {
                const char *colon = strchr(p + klen + 1, ':');
                if (colon != NULL)
                {
                    return colon + 1;
                }
            }
        }
        p += klen;
    }
    return NULL;
}

/**
 * @brief Parses a Boolean value associated with a JSON key.
 */
static bool parse_bool(const char *json, const char *key, bool *out)
{
    const char *val = find_key(json, key);
    if (val == NULL)
    {
        return false;
    }

    while (*val == ' ' || *val == '\t' || *val == '\r' || *val == '\n')
    {
        val++;
    }

    if (strncmp(val, "true", 4) == 0 || *val == '1')
    {
        *out = true;
        return true;
    }
    if (strncmp(val, "false", 5) == 0 || *val == '0')
    {
        *out = false;
        return true;
    }

    return false;
}

/**
 * @brief Parses an unsigned integer associated with a JSON key.
 */
static bool parse_uint(const char *json, const char *key, uint32_t *out)
{
    const char *val = find_key(json, key);
    if (val == NULL)
    {
        return false;
    }

    while (*val == ' ' || *val == '\t' || *val == '\r' || *val == '\n')
    {
        val++;
    }

    if (!isdigit((unsigned char)*val))
    {
        return false;
    }

    char *endptr = NULL;
    unsigned long n = strtoul(val, &endptr, 10);
    if (endptr == val)
    {
        return false;
    }

    *out = (uint32_t)n;
    return true;
}

/**
 * @brief Parses a string value associated with a JSON key.
 */
static bool parse_str(const char *json, const char *key, char *out, size_t max_len)
{
    const char *val = find_key(json, key);
    if (val == NULL)
    {
        return false;
    }

    while (*val == ' ' || *val == '\t' || *val == '\r' || *val == '\n')
    {
        val++;
    }

    if (*val != '"')
    {
        return false;
    }
    val++;

    size_t i = 0;
    while (*val != '\0' && *val != '"' && i < (max_len - 1))
    {
        out[i++] = *val++;
    }
    out[i] = '\0';

    return (i > 0);
}

/**
 * @brief Parses JSON string into configuration structure with validation.
 * @param json Input JSON string.
 * @param cfg Output configuration structure.
 * @return true on success, false on parse error or invalid values.
 */
bool SystemConfig_FromJson(const char *json, SystemConfig_t *cfg)
{
    if (json == NULL || cfg == NULL)
    {
        return false;
    }

    SystemConfig_t temp;
    SystemConfig_Get(&temp);

    /* GOOSE fields */
    parse_bool(json, "timing_check_enabled", &temp.goose.timing_check_enabled);
    parse_bool(json, "state_check_enabled", &temp.goose.state_check_enabled);
    parse_bool(json, "baseline_check_enabled", &temp.goose.baseline_check_enabled);
    parse_uint(json, "min_time_fallback_ms", &temp.goose.min_time_fallback_ms);
    parse_uint(json, "max_time_fallback_ms", &temp.goose.max_time_fallback_ms);
    parse_uint(json, "ttl_multiplier", &temp.goose.ttl_multiplier);

    /* SV fields */
    parse_bool(json, "smpcnt_check_enabled", &temp.sv.smpcnt_check_enabled);
    const char *sv_section = strstr(json, "\"sv\"");
    if (sv_section != NULL)
    {
        parse_bool(sv_section, "baseline_check_enabled", &temp.sv.baseline_check_enabled);
    }
    parse_uint(json, "sample_rate_fallback", &temp.sv.sample_rate_fallback);
    parse_uint(json, "idle_timeout_ms", &temp.sv.idle_timeout_ms);
    parse_uint(json, "wrap_boundary_tolerance", &temp.sv.wrap_boundary_tolerance);

    /* MMS fields */
    parse_bool(json, "inspection_enabled", &temp.mms.inspection_enabled);
    const char *mms_section = strstr(json, "\"mms\"");
    if (mms_section != NULL)
    {
        parse_bool(mms_section, "baseline_check_enabled", &temp.mms.baseline_check_enabled);
    }
    uint32_t port = 0;
    if (parse_uint(json, "tcp_port", &port) && port <= 65535)
    {
        temp.mms.tcp_port = (uint16_t)port;
    }

    /* Alerts fields */
    parse_uint(json, "alert_aggregation_window_ms", &temp.alerts.alert_aggregation_window_ms);
    parse_uint(json, "alert_aggregation_max_ms", &temp.alerts.alert_aggregation_max_ms);
    parse_uint(json, "normal_traffic_log_interval_ms", &temp.alerts.normal_traffic_log_interval_ms);
    parse_uint(json, "anomaly_print_interval_ms", &temp.alerts.anomaly_print_interval_ms);
    parse_bool(json, "sd_logging_enabled", &temp.alerts.sd_logging_enabled);

    /* System identity */
    parse_str(json, "gateway_name", temp.system.gateway_name, sizeof(temp.system.gateway_name));

    if (!SystemConfig_Validate(&temp))
    {
        SysLog_Print(SYSLOG_LEVEL_WARN, "CONFIG", "Parsed JSON failed validation");
        return false;
    }

    *cfg = temp;
    return true;
}

#define SYS_CONFIG_BIN_MAGIC 0x53594346 /* "SYCF" */
#define SYS_CONFIG_BIN_VERSION 1

typedef struct
{
    uint32_t magic;
    uint16_t version;
    uint16_t struct_size;
    uint32_t crc32;
    SystemConfig_t config;
} SystemConfig_Bin_t;

/**
 * @brief Calculates the CRC-32 checksum of a data buffer.
 */
static uint32_t sys_crc32(const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t crc = 0xFFFFFFFF;
    while (len--)
    {
        crc ^= *p++;
        for (int i = 0; i < 8; i++)
        {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

/**
 * @brief Persists the active configuration to SD card storage (0:/system_config.json).
 * @return true on success, false on error.
 */
bool SystemConfig_SaveToSD(void)
{
    if (!Security_LockSD(1000))
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "CONFIG", "Failed to acquire SD lock for SaveToSD");
        return false;
    }

    SystemConfig_Bin_t bin;
    memset(&bin, 0, sizeof(bin));
    bin.magic = SYS_CONFIG_BIN_MAGIC;
    bin.version = SYS_CONFIG_BIN_VERSION;
    bin.struct_size = (uint16_t)sizeof(SystemConfig_t);
    SystemConfig_Get(&bin.config);
    bin.crc32 = sys_crc32(&bin.config, sizeof(SystemConfig_t));

    FIL fil;
    memset(&fil, 0, sizeof(fil));
    FRESULT res = f_open(&fil, SYS_CONFIG_FILE, FA_CREATE_ALWAYS | FA_WRITE);
    if (res != FR_OK)
    {
        Security_UnlockSD();
        SysLog_Print(SYSLOG_LEVEL_ERROR, "CONFIG", "Failed to open %s for writing (err=%d)", SYS_CONFIG_FILE, (int)res);
        return false;
    }

    UINT bw = 0;
    res = f_write(&fil, &bin, (UINT)sizeof(bin), &bw);
    f_sync(&fil);
    f_close(&fil);

    if (res != FR_OK || bw != (UINT)sizeof(bin))
    {
        Security_UnlockSD();
        SysLog_Print(SYSLOG_LEVEL_ERROR, "CONFIG", "Failed to write %s (err=%d, wrote=%u/%u)", SYS_CONFIG_FILE, (int)res, bw, (unsigned int)sizeof(bin));
        return false;
    }

    Security_UnlockSD();
    SysLog_Print(SYSLOG_LEVEL_INFO, "CONFIG", "Configuration saved to SD (%u bytes)", bw);
    return true;
}

/**
 * @brief Loads the active configuration from SD card storage (0:/system_config.json).
 * @return true on success, false if file does not exist or parse error.
 */
bool SystemConfig_LoadFromSD(void)
{
    if (!Security_LockSD(1000))
    {
        SysLog_Print(SYSLOG_LEVEL_WARN, "CONFIG", "Failed to acquire SD lock for LoadFromSD");
        return false;
    }

    SystemConfig_Bin_t bin;
    FIL fil;
    memset(&fil, 0, sizeof(fil));
    FRESULT res = f_open(&fil, SYS_CONFIG_FILE, FA_READ);
    if (res == FR_OK)
    {
        UINT br = 0;
        res = f_read(&fil, &bin, sizeof(bin), &br);
        f_close(&fil);

        if (res == FR_OK && br == sizeof(bin) &&
            bin.magic == SYS_CONFIG_BIN_MAGIC &&
            bin.version == SYS_CONFIG_BIN_VERSION &&
            bin.struct_size == sizeof(SystemConfig_t))
        {
            uint32_t calc_crc = sys_crc32(&bin.config, sizeof(SystemConfig_t));
            if (calc_crc == bin.crc32 && SystemConfig_Validate(&bin.config))
            {
                lock_config();
                s_active_config = bin.config;
                unlock_config();
                Security_UnlockSD();
                return true;
            }
            else
            {
                SysLog_Print(SYSLOG_LEVEL_WARN, "CONFIG", "Binary configuration CRC or validation mismatch");
            }
        }
    }

    static char s_load_buf[1024];
    memset(&fil, 0, sizeof(fil));
    res = f_open(&fil, SYS_CONFIG_LEGACY_FILE, FA_READ);
    if (res == FR_OK)
    {
        UINT br = 0;
        res = f_read(&fil, s_load_buf, sizeof(s_load_buf) - 1, &br);
        f_close(&fil);

        if (res == FR_OK && br > 0)
        {
            s_load_buf[br] = '\0';
            SystemConfig_t loaded;
            if (SystemConfig_FromJson(s_load_buf, &loaded))
            {
                lock_config();
                s_active_config = loaded;
                unlock_config();
                SysLog_Print(SYSLOG_LEVEL_INFO, "CONFIG", "Migrated legacy JSON config to %s", SYS_CONFIG_FILE);
                f_unlink(SYS_CONFIG_LEGACY_FILE);
                Security_UnlockSD();
                SystemConfig_SaveToSD();
                return true;
            }
        }
    }

    Security_UnlockSD();
    return false;
}

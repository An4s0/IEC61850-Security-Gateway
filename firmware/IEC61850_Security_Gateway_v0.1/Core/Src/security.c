#include "security.h"
#include "fatfs.h"
#include "ff.h"
#include "cmsis_os.h"
#include <stdio.h>
#include <string.h>
#include "http_api.h"
#include "system_config.h"
#include "system_logger.h"

static uint32_t s_alert_counter = 0;
static volatile bool s_counter_initialized = false;

static osMutexId s_slots_mutex = NULL;
osMutexDef(SecuritySlotsMutex);

static osMutexId s_sd_file_mutex = NULL;
osMutexDef(SecuritySDMutex);

static uint32_t s_alert_record_count = 0;

static uint32_t s_total_goose = 0;
static uint32_t s_total_sv = 0;
static uint32_t s_total_mms = 0;
static uint32_t s_total_crit = 0;
static uint32_t s_total_high = 0;
static uint32_t s_total_warn = 0;
static uint32_t s_total_info = 0;

static FIL s_sd_file;
static char s_json_line[512];
static char s_read_buf[512];
static char s_safe_details[160];
static char s_safe_target[64];
static char s_frame_ts_str[32];

#define ALERT_TRACK_SLOTS 32

typedef struct
{
    bool in_use;
    uint64_t sequence;
    Security_Protocol_t protocol;
    Security_Severity_t severity;
    uint16_t app_id;
    uint16_t vlan_id;
    uint32_t conf_rev;
    uint32_t st_num;
    uint32_t sq_num;
    uint32_t timestamp_ms;
    uint64_t frame_timestamp_ms;
    char event_type[32];
    char src_str[24];
    char dst_str[24];
    char target[64];
    char details[128];
} AlertSlot_t;

static AlertSlot_t s_slots[ALERT_TRACK_SLOTS];
static AlertSlot_t s_flush_slot;
static uint64_t s_slot_sequence;
static volatile int s_pending_index = -1;
static FSIZE_t s_pending_offset;
static int s_pending_length;
static bool s_pending_issued;
static bool s_pending_committed;
static Security_Stats_t s_sec_stats = {0};
#define SEC_STAT_INC(field) do { taskENTER_CRITICAL(); if (s_sec_stats.field != UINT32_MAX) s_sec_stats.field++; taskEXIT_CRITICAL(); } while (0)

/**
 * @brief Scans the alerts log file on the SD card to build checkpoint index and sync counters.
 *        Must be called with s_sd_file_mutex held.
 */
static void sync_last_alert_id_from_sd(void)
{
    if (s_counter_initialized)
    {
        return;
    }

    FRESULT res = FR_DISK_ERR;
    for (int retry = 0; retry < 5; retry++)
    {
        memset(&s_sd_file, 0, sizeof(s_sd_file));
        res = f_open(&s_sd_file, SECURITY_ALERTS_FILE, FA_READ);
        if (res == FR_OK || res == FR_NO_FILE || res == FR_NO_PATH)
        {
            break;
        }
        osDelay(50);
    }

    if (res != FR_OK)
    {
        if (res == FR_NO_FILE || res == FR_NO_PATH)
        {
            s_counter_initialized = true;
            s_alert_record_count = 0;
            s_total_goose = 0;
            s_total_sv = 0;
            s_total_mms = 0;
            s_total_crit = 0;
            s_total_high = 0;
            s_total_warn = 0;
            s_total_info = 0;
        }
        else
            SEC_STAT_INC(storage_errors);
        SysLog_Print(SYSLOG_LEVEL_WARN, "SD", "Alert log f_open failed (res=%d)", (int)res);
        return;
    }

    uint32_t max_id = 0;
    uint32_t line_count = 0;
    uint32_t goose = 0, sv = 0, mms = 0;
    uint32_t crit = 0, high = 0, warn = 0, info = 0;
    UINT bytes_read = 0;
    FRESULT read_result;

    static char parse_line[384];
    size_t parse_len = 0;

    while ((read_result = f_read(&s_sd_file, s_read_buf, sizeof(s_read_buf), &bytes_read)) == FR_OK && bytes_read > 0)
    {
        for (UINT i = 0; i < bytes_read; i++)
        {
            char c = s_read_buf[i];
            if (parse_len < sizeof(parse_line) - 1)
            {
                parse_line[parse_len++] = c;
            }

            if (c == '\n')
            {
                line_count++;

                parse_line[parse_len] = '\0';

                const char *p = strstr(parse_line, "ALT-");
                if (p != NULL)
                {
                    unsigned long id_val = 0;
                    if (sscanf(p + 4, "%lu", &id_val) == 1)
                    {
                        if (id_val > max_id)
                            max_id = (uint32_t)id_val;
                    }
                }

                if (strstr(parse_line, "\"proto\":\"GOOSE\""))
                    goose++;
                else if (strstr(parse_line, "\"proto\":\"SV\""))
                    sv++;
                else if (strstr(parse_line, "\"proto\":\"MMS\""))
                    mms++;

                if (strstr(parse_line, "\"sev\":\"CRITICAL\""))
                    crit++;
                else if (strstr(parse_line, "\"sev\":\"HIGH\""))
                    high++;
                else if (strstr(parse_line, "\"sev\":\"WARNING\""))
                    warn++;
                else if (strstr(parse_line, "\"sev\":\"INFO\""))
                    info++;

                parse_len = 0;
            }
        }
    }

    FRESULT close_result = f_close(&s_sd_file);
    memset(&s_sd_file, 0, sizeof(s_sd_file));

    if (read_result != FR_OK || close_result != FR_OK || parse_len != 0)
    {
        SEC_STAT_INC(storage_errors);
        return;
    }

    s_alert_record_count = line_count;
    s_alert_counter = (max_id > line_count) ? max_id : line_count;
    s_total_goose = goose;
    s_total_sv = sv;
    s_total_mms = mms;
    s_total_crit = crit;
    s_total_high = high;
    s_total_warn = warn;
    s_total_info = info;
    s_counter_initialized = true;

    SysLog_Print(SYSLOG_LEVEL_INFO, "SD", "Alert log synced: %lu records, Last ID=ALT-%04lu",
                 (unsigned long)s_alert_record_count,
                 (unsigned long)s_alert_counter);
}

/**
 * @brief Initializes the Security logging subsystem and mutexes.
 */
void Security_Init(void)
{
    if (s_slots_mutex == NULL)
    {
        s_slots_mutex = osMutexCreate(osMutex(SecuritySlotsMutex));
    }
    if (s_sd_file_mutex == NULL)
    {
        s_sd_file_mutex = osMutexCreate(osMutex(SecuritySDMutex));
    }
}

/**
 * @brief Synchronizes alert counter from SD card once RTOS scheduler is running.
 */
void Security_SyncAlertCounter(void)
{
    if (xTaskGetSchedulerState() != taskSCHEDULER_RUNNING)
    {
        return;
    }

    if (!s_counter_initialized)
    {
        if (s_sd_file_mutex == NULL || osMutexWait(s_sd_file_mutex, 50) != osOK)
            return;
        sync_last_alert_id_from_sd();
        osMutexRelease(s_sd_file_mutex);
    }
}

/**
 * @brief Converts a security severity enum to its string representation.
 */
const char *Security_SeverityToString(Security_Severity_t sev)
{
    switch (sev)
    {
    case SEC_SEV_INFO:
        return "INFO";
    case SEC_SEV_WARNING:
        return "WARNING";
    case SEC_SEV_HIGH:
        return "HIGH";
    case SEC_SEV_CRITICAL:
        return "CRITICAL";
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Converts a security protocol enum to its string representation.
 */
const char *Security_ProtocolToString(Security_Protocol_t proto)
{
    switch (proto)
    {
    case SEC_PROTO_GOOSE:
        return "GOOSE";
    case SEC_PROTO_SV:
        return "SV";
    case SEC_PROTO_MMS:
        return "MMS";
    default:
        return "GENERIC";
    }
}

/**
 * @brief Returns the total number of detected alerts recorded.
 */
uint32_t Security_GetAlertCount(void)
{
    return s_alert_record_count;
}

bool Security_IsReady(void)
{
    return s_counter_initialized;
}

/**
 * @brief Retrieves current security subsystem statistics.
 */
void Security_GetStats(Security_Stats_t *stats)
{
    if (stats == NULL)
    {
        return;
    }

    taskENTER_CRITICAL();
    *stats = s_sec_stats;
    taskEXIT_CRITICAL();
}

/**
 * @brief Escapes special JSON characters in a string buffer.
 */
static void escape_json_str(const char *src, char *dst, size_t dst_size)
{
    if (src == NULL || dst == NULL || dst_size == 0)
    {
        if (dst != NULL && dst_size > 0)
        {
            dst[0] = '\0';
        }
        return;
    }

    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 2 < dst_size; i++)
    {
        if (src[i] == '"' || src[i] == '\\')
        {
            dst[j++] = '\\';
            dst[j++] = src[i];
        }
        else if (src[i] == '\n')
        {
            dst[j++] = '\\';
            dst[j++] = 'n';
        }
        else if (src[i] == '\r')
        {
            dst[j++] = '\\';
            dst[j++] = 'r';
        }
        else
        {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

/**
 * @brief Converts a 64-bit unsigned integer to a decimal string.
 */
static void format_uint64(uint64_t val, char *buf, size_t buf_size)
{
    if (buf == NULL || buf_size == 0)
    {
        return;
    }
    if (val == 0)
    {
        if (buf_size > 1)
        {
            buf[0] = '0';
            buf[1] = '\0';
        }
        return;
    }
    char temp[32];
    int pos = 0;
    while (val > 0 && pos < 30)
    {
        temp[pos++] = '0' + (char)(val % 10);
        val /= 10;
    }
    if ((size_t)pos >= buf_size)
    {
        pos = (int)buf_size - 1;
    }
    for (int i = 0; i < pos; i++)
    {
        buf[i] = temp[pos - 1 - i];
    }
    buf[pos] = '\0';
}

/**
 * @brief Formats a single alert slot into a JSON line string.
 */
static int format_alert_json(const AlertSlot_t *slot, uint32_t alert_id, char *out_buf, size_t max_len)
{
    escape_json_str(slot->details[0] ? slot->details : "Anomaly detected",
                    s_safe_details, sizeof(s_safe_details));
    escape_json_str(slot->target[0] ? slot->target : "N/A", s_safe_target, sizeof(s_safe_target));
    format_uint64(slot->frame_timestamp_ms, s_frame_ts_str, sizeof(s_frame_ts_str));

    return snprintf(out_buf, max_len,
                    "{\"id\":\"ALT-%04lu\",\"ts\":%lu,\"frameTs\":%s,\"proto\":\"%s\",\"type\":\"%s\",\"sev\":\"%s\","
                    "\"srcMac\":\"%s\",\"dstMac\":\"%s\",\"target\":\"%s\",\"appId\":\"0x%04X\","
                    "\"vlan\":%u,\"confRev\":%lu,\"stNum\":%lu,\"sqNum\":%lu,\"details\":\"%s\"}\n",
                    (unsigned long)alert_id,
                    (unsigned long)slot->timestamp_ms,
                    s_frame_ts_str,
                    Security_ProtocolToString(slot->protocol),
                    slot->event_type[0] ? slot->event_type : "GENERIC_ANOMALY",
                    Security_SeverityToString(slot->severity),
                    slot->src_str,
                    slot->dst_str,
                    s_safe_target,
                    (unsigned int)slot->app_id,
                    (unsigned int)slot->vlan_id,
                    (unsigned long)slot->conf_rev,
                    (unsigned long)slot->st_num,
                    (unsigned long)slot->sq_num,
                    s_safe_details);
}

/**
 * @brief Enqueues one independent security event in RAM.
 * @param alert Pointer to alert log descriptor.
 * @return true if successfully recorded, false on error.
 */
bool Security_LogAlertToSD(const Security_AlertLog_t *alert)
{
    if (alert == NULL)
    {
        return false;
    }

    SEC_STAT_INC(alerts_attempted);

    if (s_slots_mutex == NULL)
    {
        Security_Init();
        if (s_slots_mutex == NULL)
        {
            SEC_STAT_INC(alerts_dropped);
            return false;
        }
    }

    if (osMutexWait(s_slots_mutex, 0) != osOK)
    {
        SEC_STAT_INC(alerts_dropped);
        SEC_STAT_INC(alerts_dropped_mutex_busy);
        return false;
    }

    uint32_t now = HAL_GetTick();
    const char *ev_type = alert->event_type ? alert->event_type : "GENERIC";

    char cur_src_str[24];
    char cur_dst_str[24];
    strncpy(cur_src_str, "00:00:00:00:00:00", sizeof(cur_src_str) - 1);
    cur_src_str[sizeof(cur_src_str) - 1] = '\0';
    strncpy(cur_dst_str, "00:00:00:00:00:00", sizeof(cur_dst_str) - 1);
    cur_dst_str[sizeof(cur_dst_str) - 1] = '\0';

    if (alert->src_mac != NULL)
    {
        snprintf(cur_src_str, sizeof(cur_src_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 alert->src_mac[0], alert->src_mac[1], alert->src_mac[2],
                 alert->src_mac[3], alert->src_mac[4], alert->src_mac[5]);
    }
    else if (alert->src_ip != NULL)
    {
        strncpy(cur_src_str, alert->src_ip, sizeof(cur_src_str) - 1);
        cur_src_str[sizeof(cur_src_str) - 1] = '\0';
    }

    if (alert->dst_mac != NULL)
    {
        snprintf(cur_dst_str, sizeof(cur_dst_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 alert->dst_mac[0], alert->dst_mac[1], alert->dst_mac[2],
                 alert->dst_mac[3], alert->dst_mac[4], alert->dst_mac[5]);
    }
    else if (alert->dst_ip != NULL)
    {
        strncpy(cur_dst_str, alert->dst_ip, sizeof(cur_dst_str) - 1);
        cur_dst_str[sizeof(cur_dst_str) - 1] = '\0';
    }

    const char *target_str = alert->target ? alert->target : "N/A";

    AlertSlot_t *slot = NULL;
    AlertSlot_t *free_slot = NULL;
    for (int i = 0; i < ALERT_TRACK_SLOTS; i++)
    {
        if (!s_slots[i].in_use)
        {
            free_slot = &s_slots[i];
            break;
        }
    }
    if (free_slot == NULL)
    {
        SEC_STAT_INC(alerts_dropped);
        SEC_STAT_INC(alerts_dropped_buffer_full);
        osMutexRelease(s_slots_mutex);
        return false;
    }

    if (free_slot != NULL)
    {
        slot = free_slot;
        slot->in_use = true;
        slot->sequence = ++s_slot_sequence;
        slot->protocol = alert->protocol;
        slot->severity = alert->severity;
        slot->app_id = alert->app_id;
        slot->vlan_id = alert->vlan_id;
        slot->conf_rev = alert->conf_rev;
        slot->st_num = alert->st_num;
        slot->sq_num = alert->sq_num;
        slot->timestamp_ms = alert->timestamp_ms ? alert->timestamp_ms : now;
        slot->frame_timestamp_ms = alert->frame_timestamp_ms;
        strncpy(slot->event_type, ev_type, sizeof(slot->event_type) - 1);
        slot->event_type[sizeof(slot->event_type) - 1] = '\0';
        strncpy(slot->src_str, cur_src_str, sizeof(slot->src_str) - 1);
        slot->src_str[sizeof(slot->src_str) - 1] = '\0';
        strncpy(slot->dst_str, cur_dst_str, sizeof(slot->dst_str) - 1);
        slot->dst_str[sizeof(slot->dst_str) - 1] = '\0';
        strncpy(slot->target, target_str, sizeof(slot->target) - 1);
        slot->target[sizeof(slot->target) - 1] = '\0';
        strncpy(slot->details, alert->details ? alert->details : "Anomaly detected", sizeof(slot->details) - 1);
        slot->details[sizeof(slot->details) - 1] = '\0';

        SEC_STAT_INC(alerts_generated);
        taskENTER_CRITICAL();
        s_sec_stats.slots_in_use++;
        if (s_sec_stats.slots_in_use > s_sec_stats.slots_high_water)
            s_sec_stats.slots_high_water = s_sec_stats.slots_in_use;
        taskEXIT_CRITICAL();
    }

    osMutexRelease(s_slots_mutex);
    return true;
}

/**
 * @brief Periodically flushes pending alert records to SD and SSE.
 *        Executes in low-priority background task (defaultTask).
 *        Preemptible by high-priority real-time packet tasks (SV, GOOSE, MMS).
 */
void Security_PeriodicFlush(void)
{
    if (s_sd_file_mutex == NULL || s_slots_mutex == NULL)
        return;

    if (!s_counter_initialized)
    {
        if (osMutexWait(s_sd_file_mutex, 0) != osOK)
            return;
        sync_last_alert_id_from_sd();
        osMutexRelease(s_sd_file_mutex);
        if (!s_counter_initialized)
            return;
    }

    for (int batch = 0; batch < ALERT_TRACK_SLOTS; batch++)
    {
        if (s_pending_index < 0)
        {
            SystemConfig_t sys_cfg;
            SystemConfig_Get(&sys_cfg);
            if (!sys_cfg.alerts.sd_logging_enabled)
                return;

            if (osMutexWait(s_slots_mutex, 10) != osOK)
                return;

            int oldest = -1;
            for (int i = 0; i < ALERT_TRACK_SLOTS; i++)
            {
                if (s_slots[i].in_use &&
                    (oldest < 0 || s_slots[i].sequence < s_slots[oldest].sequence))
                    oldest = i;
            }
            if (oldest >= 0)
            {
                s_pending_index = oldest;
                s_flush_slot = s_slots[oldest];
                s_pending_issued = false;
                s_pending_committed = false;
            }
            osMutexRelease(s_slots_mutex);
            if (oldest < 0)
                return;
        }

        if (!s_pending_committed)
        {
            if (osMutexWait(s_sd_file_mutex, 0) != osOK)
                return;

            if (!s_counter_initialized)
                sync_last_alert_id_from_sd();
            if (!s_counter_initialized || s_alert_counter == UINT32_MAX)
            {
                SEC_STAT_INC(storage_errors);
                osMutexRelease(s_sd_file_mutex);
                return;
            }

            s_pending_length = format_alert_json(&s_flush_slot, s_alert_counter + 1U,
                                                s_json_line, sizeof(s_json_line));
            if (s_pending_length <= 0 || (size_t)s_pending_length >= sizeof(s_json_line))
            {
                SEC_STAT_INC(storage_errors);
                osMutexRelease(s_sd_file_mutex);
                return;
            }

            memset(&s_sd_file, 0, sizeof(s_sd_file));
            FRESULT res = f_open(&s_sd_file, SECURITY_ALERTS_FILE, FA_OPEN_ALWAYS | FA_READ | FA_WRITE);
            if (res != FR_OK)
            {
                SEC_STAT_INC(storage_errors);
                osMutexRelease(s_sd_file_mutex);
                return;
            }

            if (s_pending_issued)
            {
                SEC_STAT_INC(persistence_retries);
                FSIZE_t size = f_size(&s_sd_file);
                FSIZE_t end = s_pending_offset + (FSIZE_t)s_pending_length;
                if (size < s_pending_offset || size > end)
                    res = FR_INT_ERR;
                else if (size > s_pending_offset)
                {
                    UINT read_len = 0;
                    UINT expected = (UINT)(size - s_pending_offset);
                    res = f_lseek(&s_sd_file, s_pending_offset);
                    if (res == FR_OK)
                        res = f_read(&s_sd_file, s_read_buf, expected, &read_len);
                    if (res == FR_OK && (read_len != expected ||
                                         memcmp(s_read_buf, s_json_line, expected) != 0))
                        res = FR_INT_ERR;
                    if (res == FR_OK && size == end)
                    {
                        res = f_sync(&s_sd_file);
                        if (res == FR_OK)
                            s_pending_committed = true;
                    }
                    else if (res == FR_OK)
                    {
                        res = f_lseek(&s_sd_file, s_pending_offset);
                        if (res == FR_OK)
                            res = f_truncate(&s_sd_file);
                        if (res == FR_OK)
                            res = f_sync(&s_sd_file);
                        if (res == FR_OK)
                            s_pending_issued = false;
                    }
                }
                else
                    s_pending_issued = false;
            }

            if (res == FR_OK && !s_pending_issued && !s_pending_committed)
            {
                s_pending_offset = f_size(&s_sd_file);
                res = f_lseek(&s_sd_file, s_pending_offset);
                if (res == FR_OK)
                {
                    UINT written = 0;
                    s_pending_issued = true;
                    res = f_write(&s_sd_file, s_json_line, (UINT)s_pending_length, &written);
                    if (res == FR_OK && written != (UINT)s_pending_length)
                        res = FR_DISK_ERR;
                    if (res == FR_OK)
                        res = f_sync(&s_sd_file);
                    if (res == FR_OK)
                        s_pending_committed = true;
                }
            }

            if (res != FR_OK)
                SEC_STAT_INC(storage_errors);
            if (f_close(&s_sd_file) != FR_OK)
                SEC_STAT_INC(storage_errors);
            memset(&s_sd_file, 0, sizeof(s_sd_file));

            if (s_pending_committed)
            {
                s_alert_counter++;
                s_alert_record_count++;
                if (s_flush_slot.protocol == SEC_PROTO_GOOSE)
                    s_total_goose++;
                else if (s_flush_slot.protocol == SEC_PROTO_SV)
                    s_total_sv++;
                else if (s_flush_slot.protocol == SEC_PROTO_MMS)
                    s_total_mms++;

                if (s_flush_slot.severity == SEC_SEV_CRITICAL)
                    s_total_crit++;
                else if (s_flush_slot.severity == SEC_SEV_HIGH)
                    s_total_high++;
                else if (s_flush_slot.severity == SEC_SEV_WARNING)
                    s_total_warn++;
                else if (s_flush_slot.severity == SEC_SEV_INFO)
                    s_total_info++;
                SEC_STAT_INC(alerts_written);
            }
            osMutexRelease(s_sd_file_mutex);
            if (!s_pending_committed)
                return;
        }

        if (osMutexWait(s_slots_mutex, 10) != osOK)
            return;
        s_slots[s_pending_index].in_use = false;
        taskENTER_CRITICAL();
        if (s_sec_stats.slots_in_use > 0)
            s_sec_stats.slots_in_use--;
        taskEXIT_CRITICAL();
        s_pending_index = -1;
        s_pending_committed = false;
        s_pending_issued = false;
        osMutexRelease(s_slots_mutex);

        HTTP_API_BroadcastAlert(s_json_line, (uint16_t)s_pending_length);
    }
}

/**
 * @brief Clears the alert history on the SD card.
 */
bool Security_ClearAlertsOnSD(void)
{
    if (s_slots_mutex == NULL || s_sd_file_mutex == NULL)
    {
        Security_Init();
    }

    if (s_slots_mutex == NULL || s_sd_file_mutex == NULL)
        return false;

    if (s_sd_file_mutex != NULL)
    {
        if (osMutexWait(s_sd_file_mutex, 50) != osOK)
            return false;
    }

    if (s_pending_index >= 0)
    {
        osMutexRelease(s_sd_file_mutex);
        return false;
    }

    f_mkdir("0:/alerts");
    memset(&s_sd_file, 0, sizeof(s_sd_file));
    FRESULT res = f_open(&s_sd_file, SECURITY_ALERTS_FILE, FA_CREATE_ALWAYS | FA_WRITE);
    if (res == FR_OK)
    {
        res = f_close(&s_sd_file);
    }
    if (res == FR_OK)
    {
        s_alert_record_count = 0;
        s_total_goose = 0;
        s_total_sv = 0;
        s_total_mms = 0;
        s_total_crit = 0;
        s_total_high = 0;
        s_total_warn = 0;
        s_total_info = 0;
        s_counter_initialized = true;
    }
    else
    {
        SEC_STAT_INC(storage_errors);
        s_counter_initialized = false;
    }
    memset(&s_sd_file, 0, sizeof(s_sd_file));

    if (s_sd_file_mutex != NULL)
    {
        osMutexRelease(s_sd_file_mutex);
    }

    SysLog_Print(SYSLOG_LEVEL_INFO, "SD", "Cleared alerts log file and reset sequence counter (res=%d)", (int)res);
    return (res == FR_OK);
}

/**
 * @brief Reports whether a record is currently being committed to SD.
 *        Used by the storage owner before it truncates the alert log.
 */
bool Security_HasPendingAlert(void)
{
    return (s_pending_index >= 0);
}

/**
 * @brief Discards every RAM alert slot that has not been committed yet.
 *        Caller must ensure no record is in flight (see Security_HasPendingAlert).
 * @return number of discarded slots.
 */
uint32_t Security_PurgePendingAlerts(void)
{
    if (s_slots_mutex == NULL)
    {
        return 0;
    }
    if (osMutexWait(s_slots_mutex, 50) != osOK)
    {
        return 0;
    }

    uint32_t purged = 0;
    for (int i = 0; i < ALERT_TRACK_SLOTS; i++)
    {
        if (s_slots[i].in_use)
        {
            s_slots[i].in_use = false;
            purged++;
        }
    }

    s_pending_index = -1;
    s_pending_issued = false;
    s_pending_committed = false;
    s_pending_length = 0;

    taskENTER_CRITICAL();
    s_sec_stats.slots_in_use = 0;
    if (purged != 0U)
    {
        s_sec_stats.alerts_purged += purged;
    }
    taskEXIT_CRITICAL();

    osMutexRelease(s_slots_mutex);
    return purged;
}

/**
 * @brief Retrieves global persistent alert statistics across all protocols.
 */
void Security_GetGlobalStats(uint32_t *total, uint32_t *goose, uint32_t *sv, uint32_t *mms)
{
    if (total)
        *total = s_alert_record_count;
    if (goose)
        *goose = s_total_goose;
    if (sv)
        *sv = s_total_sv;
    if (mms)
        *mms = s_total_mms;
}

/**
 * @brief Retrieves global persistent alert statistics across severity levels.
 */
void Security_GetGlobalSevStats(uint32_t *crit, uint32_t *high, uint32_t *warn, uint32_t *info)
{
    if (crit)
        *crit = s_total_crit;
    if (high)
        *high = s_total_high;
    if (warn)
        *warn = s_total_warn;
    if (info)
        *info = s_total_info;
}

/**
 * @brief Locks SD alert file mutex for non-conflicting access.
 */
bool Security_LockSD(uint32_t timeout_ms)
{
    if (s_sd_file_mutex == NULL)
    {
        Security_Init();
        if (s_sd_file_mutex == NULL)
        {
            return false;
        }
    }
    return (osMutexWait(s_sd_file_mutex, timeout_ms) == osOK);
}

/**
 * @brief Releases SD alert file mutex.
 */
void Security_UnlockSD(void)
{
    if (s_sd_file_mutex != NULL)
    {
        osMutexRelease(s_sd_file_mutex);
    }
}

#include "security.h"
#include "fatfs.h"
#include "ff.h"
#include "cmsis_os.h"
#include <stdio.h>
#include <string.h>
#include "http_api.h"

static uint32_t s_alert_counter = 0;
static bool s_counter_initialized = false;
static osMutexId s_sd_log_mutex = NULL;
osMutexDef(SecuritySDMutex);

/**
 * @brief Scans the alerts log file on the SD card to find the highest/last alert ID.
 */
static void sync_last_alert_id_from_sd(void)
{
    if (s_counter_initialized)
    {
        return;
    }

    FIL file;
    FRESULT res = f_open(&file, SECURITY_ALERTS_FILE, FA_READ);
    if (res != FR_OK)
    {
        return;
    }

    s_counter_initialized = true;

    uint32_t max_id = 0;
    char read_buf[512];
    UINT bytes_read = 0;

    while (f_read(&file, read_buf, sizeof(read_buf) - 1, &bytes_read) == FR_OK && bytes_read > 0)
    {
        read_buf[bytes_read] = '\0';
        const char *p = read_buf;
        while ((p = strstr(p, "ALT-")) != NULL)
        {
            p += 4;
            unsigned long id_val = 0;
            if (sscanf(p, "%lu", &id_val) == 1)
            {
                if (id_val > max_id)
                {
                    max_id = (uint32_t)id_val;
                }
            }
        }
    }

    f_close(&file);
    s_alert_counter = max_id;

    printf("[SD_LOG] Initialized alert sequence: Last ID = ALT-%04lu (Next will be ALT-%04lu)\n",
           (unsigned long)s_alert_counter,
           (unsigned long)(s_alert_counter + 1));
}

/**
 * @brief Initializes the Security logging subsystem and mutex.
 */
void Security_Init(void)
{
    if (s_sd_log_mutex == NULL)
    {
        s_sd_log_mutex = osMutexCreate(osMutex(SecuritySDMutex));
    }
}

/**
 * @brief Converts a security severity enum to its string representation.
 * @param sev Severity enum value.
 * @return String representation of severity.
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
 * @param proto Protocol enum value.
 * @return String representation of protocol.
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
    if (!s_counter_initialized)
    {
        Security_Init();
    }
    return s_alert_counter;
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
 * @param val Value to convert.
 * @param buf Destination character buffer.
 * @param buf_size Size of destination buffer in bytes.
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
 * @brief Appends a detected security anomaly alert to the SD card in JSON Lines format.
 * @param alert Pointer to the alert log structure.
 * @return true if successfully written to SD card, false otherwise.
 */
bool Security_LogAlertToSD(const Security_AlertLog_t *alert)
{
    if (alert == NULL)
    {
        return false;
    }

    if (s_sd_log_mutex == NULL)
    {
        Security_Init();
    }

    if (s_sd_log_mutex != NULL)
    {
        osMutexWait(s_sd_log_mutex, osWaitForever);
    }

    if (!s_counter_initialized)
    {
        sync_last_alert_id_from_sd();
    }

    s_alert_counter++;

    char src_mac_str[24] = "00:00:00:00:00:00";
    char dst_mac_str[24] = "00:00:00:00:00:00";

    if (alert->src_mac != NULL)
    {
        snprintf(src_mac_str, sizeof(src_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 alert->src_mac[0], alert->src_mac[1], alert->src_mac[2],
                 alert->src_mac[3], alert->src_mac[4], alert->src_mac[5]);
    }
    else if (alert->src_ip != NULL)
    {
        strncpy(src_mac_str, alert->src_ip, sizeof(src_mac_str) - 1);
        src_mac_str[sizeof(src_mac_str) - 1] = '\0';
    }

    if (alert->dst_mac != NULL)
    {
        snprintf(dst_mac_str, sizeof(dst_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 alert->dst_mac[0], alert->dst_mac[1], alert->dst_mac[2],
                 alert->dst_mac[3], alert->dst_mac[4], alert->dst_mac[5]);
    }
    else if (alert->dst_ip != NULL)
    {
        strncpy(dst_mac_str, alert->dst_ip, sizeof(dst_mac_str) - 1);
        dst_mac_str[sizeof(dst_mac_str) - 1] = '\0';
    }

    char safe_details[160];
    char safe_target[64];
    escape_json_str(alert->details ? alert->details : "Anomaly detected on protection stream", safe_details, sizeof(safe_details));
    escape_json_str(alert->target ? alert->target : "N/A", safe_target, sizeof(safe_target));

    char frame_ts_str[32];
    format_uint64(alert->frame_timestamp_ms, frame_ts_str, sizeof(frame_ts_str));

    char json_line[512];
    int line_len = snprintf(json_line, sizeof(json_line),
                            "{\"id\":\"ALT-%04lu\",\"ts\":%lu,\"frameTs\":%s,\"proto\":\"%s\",\"type\":\"%s\",\"sev\":\"%s\","
                            "\"srcMac\":\"%s\",\"dstMac\":\"%s\",\"target\":\"%s\",\"appId\":\"0x%04X\","
                            "\"vlan\":%u,\"confRev\":%lu,\"stNum\":%lu,\"sqNum\":%lu,\"details\":\"%s\"}\n",
                            (unsigned long)s_alert_counter,
                            (unsigned long)alert->timestamp_ms,
                            frame_ts_str,
                            Security_ProtocolToString(alert->protocol),
                            alert->event_type ? alert->event_type : "GENERIC_ANOMALY",
                            Security_SeverityToString(alert->severity),
                            src_mac_str,
                            dst_mac_str,
                            safe_target,
                            (unsigned int)alert->app_id,
                            (unsigned int)alert->vlan_id,
                            (unsigned long)alert->conf_rev,
                            (unsigned long)alert->st_num,
                            (unsigned long)alert->sq_num,
                            safe_details);

    if (line_len <= 0 || (size_t)line_len >= sizeof(json_line))
    {
        if (s_sd_log_mutex != NULL)
            osMutexRelease(s_sd_log_mutex);
        return false;
    }

    FIL file;
    FRESULT res = f_open(&file, SECURITY_ALERTS_FILE, FA_OPEN_ALWAYS | FA_WRITE);
    if (res != FR_OK)
    {
        printf("[SD_LOG] Failed to open %s (FRESULT %d)\n", SECURITY_ALERTS_FILE, res);
        if (s_sd_log_mutex != NULL)
        {
            osMutexRelease(s_sd_log_mutex);
        }
        return false;
    }

    res = f_lseek(&file, f_size(&file));
    if (res != FR_OK)
    {
        f_close(&file);
        if (s_sd_log_mutex != NULL)
            osMutexRelease(s_sd_log_mutex);
        return false;
    }

    UINT bytes_written = 0;
    res = f_write(&file, json_line, (UINT)line_len, &bytes_written);
    if (res != FR_OK || bytes_written != (UINT)line_len)
    {
        printf("[SD_LOG] Write error to SD (wrote %u/%d bytes, FRESULT %d)\n", bytes_written, line_len, res);
        f_close(&file);
        if (s_sd_log_mutex != NULL)
            osMutexRelease(s_sd_log_mutex);
        return false;
    }

    f_sync(&file);
    f_close(&file);

    HTTP_API_BroadcastAlert(json_line, (uint16_t)line_len);

    printf("[SD_LOG] Saved alert ALT-%04lu to SD (%s): %s\n",
           (unsigned long)s_alert_counter,
           SECURITY_ALERTS_FILE,
           alert->event_type ? alert->event_type : "ALERT");

    if (s_sd_log_mutex != NULL)
    {
        osMutexRelease(s_sd_log_mutex);
    }

    return true;
}

/**
 * @brief Clears the alerts log file on the SD card and resets the alert counter to 0.
 * @return true if successfully cleared, false otherwise.
 */
bool Security_ClearAlertsOnSD(void)
{
    if (s_sd_log_mutex == NULL)
    {
        Security_Init();
    }

    if (s_sd_log_mutex != NULL)
    {
        osMutexWait(s_sd_log_mutex, osWaitForever);
    }

    s_alert_counter = 0;
    s_counter_initialized = true;

    FIL file;
    FRESULT res = f_open(&file, SECURITY_ALERTS_FILE, FA_CREATE_ALWAYS | FA_WRITE);
    if (res == FR_OK)
    {
        f_close(&file);
    }

    if (s_sd_log_mutex != NULL)
    {
        osMutexRelease(s_sd_log_mutex);
    }

    printf("[SD_LOG] Cleared alerts log file and reset sequence counter to 0 (res = %d)\n", res);
    return (res == FR_OK);
}

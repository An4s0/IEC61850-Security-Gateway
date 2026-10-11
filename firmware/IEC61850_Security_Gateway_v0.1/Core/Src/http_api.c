#include "http_api.h"
#include "scd_storage.h"
#include "scd_config.h"
#include "system_config.h"
#include "system_logger.h"
#include "security.h"
#include "fatfs.h"
#include "ff.h"
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define HTTP_API_PORT 8080
#define HTTP_API_REQUEST_BUFFER_SIZE 2048
#define MAX_HTTP_CLIENTS 8
#define MAX_SSE_CLIENTS 4
#define MAX_ALERT_POOL 4

#define BODY_CHUNK_SIZE 512

static struct tcp_pcb *api_pcb = NULL;

typedef struct HTTP_API_Client_s
{
    char request[HTTP_API_REQUEST_BUFFER_SIZE];
    uint16_t header_len;
    uint32_t content_length;
    uint32_t body_received;
    uint8_t header_complete;
    uint8_t post_active;
    uint8_t post_config_active;
    uint8_t alerts_active;
    int8_t alert_buf_idx;
    uint8_t is_sse;
    uint8_t in_use;
    uint32_t last_activity;
    char *resp_buf;
    uint32_t resp_len;
    uint32_t resp_sent;
    struct tcp_pcb *pcb;
    struct HTTP_API_Client_s *next_sse;
} HTTP_API_Client_t;

static HTTP_API_Client_t s_clients[MAX_HTTP_CLIENTS];
static HTTP_API_Client_t *sse_clients = NULL;
static uint8_t sse_client_count = 0;

#define ALERT_RESP_BUF_SIZE 22528
#define NUM_ALERT_RESP_BUFS 2
static char s_alert_resp_buffers[NUM_ALERT_RESP_BUFS][ALERT_RESP_BUF_SIZE];
static uint8_t s_alert_buf_busy[NUM_ALERT_RESP_BUFS] = {0, 0};

static int acquire_alert_resp_buffer(void)
{
    for (int i = 0; i < NUM_ALERT_RESP_BUFS; i++)
    {
        if (!s_alert_buf_busy[i])
        {
            s_alert_buf_busy[i] = 1;
            return i;
        }
    }
    return -1;
}

static void release_alert_resp_buffer(int idx)
{
    if (idx >= 0 && idx < NUM_ALERT_RESP_BUFS)
    {
        s_alert_buf_busy[idx] = 0;
    }
}

static volatile uint8_t s_scd_upload_active = 0;

typedef struct
{
    char data[512];
    uint16_t len;
    uint8_t in_use;
} SSE_Message_t;

static SSE_Message_t s_alert_pool[MAX_ALERT_POOL];
osMutexDef(AlertPoolMutex);
static osMutexId s_alert_pool_mutex = NULL;

static void api_close_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static void api_abort_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static void stream_alerts_response(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static bool process_scd_data(struct tcp_pcb *pcb, HTTP_API_Client_t *client, const uint8_t *data, uint16_t len);
static void finish_post(struct tcp_pcb *pcb, HTTP_API_Client_t *client);

/**
 * @brief Allocates a client state slot from the static pool.
 */
static HTTP_API_Client_t *alloc_client(struct tcp_pcb *pcb)
{
    for (int i = 0; i < MAX_HTTP_CLIENTS; i++)
    {
        if (!s_clients[i].in_use)
        {
            memset(&s_clients[i], 0, sizeof(HTTP_API_Client_t));
            s_clients[i].in_use = 1;
            s_clients[i].alert_buf_idx = -1;
            s_clients[i].pcb = pcb;
            s_clients[i].last_activity = HAL_GetTick();
            return &s_clients[i];
        }
    }
    return NULL;
}

/**
 * @brief Releases a client state slot back to the static pool.
 */
static void free_client(HTTP_API_Client_t *client)
{
    if (client != NULL)
    {
        if (client->alert_buf_idx >= 0)
        {
            release_alert_resp_buffer(client->alert_buf_idx);
            client->alert_buf_idx = -1;
        }
        client->alerts_active = 0;
        client->in_use = 0;
        client->pcb = NULL;
    }
}

/**
 * @brief Removes an SSE client from the active broadcast list.
 */
static void remove_sse_client(HTTP_API_Client_t *client)
{
    if (client != NULL && client->is_sse)
    {
        HTTP_API_Client_t **curr = &sse_clients;
        while (*curr != NULL)
        {
            if (*curr == client)
            {
                *curr = client->next_sse;
                if (sse_client_count > 0)
                {
                    sse_client_count--;
                }
                break;
            }
            curr = &((*curr)->next_sse);
        }
        client->is_sse = 0;
        client->next_sse = NULL;
    }
}

/**
 * @brief Callback invoked when data has been successfully transmitted.
 */
static err_t api_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)len;
    HTTP_API_Client_t *client = (HTTP_API_Client_t *)arg;
    if (client != NULL)
    {
        client->last_activity = HAL_GetTick();
        if (client->alerts_active)
        {
            stream_alerts_response(pcb, client);
        }
    }
    return ERR_OK;
}

/**
 * @brief Periodic poll callback to detect stale connections and keep SSE alive.
 */
static err_t api_poll(void *arg, struct tcp_pcb *pcb)
{
    HTTP_API_Client_t *client = (HTTP_API_Client_t *)arg;
    if (client == NULL)
    {
        tcp_abort(pcb);
        return ERR_ABRT;
    }

    uint32_t now = HAL_GetTick();

    if (client->alerts_active)
    {
        if (client->resp_sent >= client->resp_len)
        {
            client->alerts_active = 0;
            api_close_conn(pcb, client);
            return ERR_OK;
        }
        else
        {
            stream_alerts_response(pcb, client);
        }
    }

    if (client->is_sse)
    {
        if (now - client->last_activity >= 5000)
        {
            client->last_activity = now;
            const char *hb = ": keepalive\n\n";
            err_t err = tcp_write(pcb, hb, (u16_t)strlen(hb), TCP_WRITE_FLAG_COPY);
            if (err == ERR_OK)
            {
                tcp_output(pcb);
            }
            else
            {
                SysLog_Print(SYSLOG_LEVEL_DEBUG, "HTTP", "SSE keepalive failed (%d), aborting", err);
                api_abort_conn(pcb, client);
                return ERR_ABRT;
            }
        }
    }
    else
    {
        if (now - client->last_activity >= 15000)
        {
            SysLog_Print(SYSLOG_LEVEL_DEBUG, "HTTP", "Connection timed out, aborting");
            api_abort_conn(pcb, client);
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

/**
 * @brief Locates the boundary between HTTP headers and body.
 */
static int find_header_end(const char *data, uint16_t len)
{
    if (len < 4)
    {
        return -1;
    }

    for (uint16_t i = 0; i <= len - 4; i++)
    {
        if (data[i] == '\r' &&
            data[i + 1] == '\n' &&
            data[i + 2] == '\r' &&
            data[i + 3] == '\n')
        {
            return i + 4;
        }
    }

    return -1;
}

/**
 * @brief Parses the Content-Length header value from an HTTP request header.
 */
static uint32_t parse_content_length(const char *headers)
{
    const char *p = strstr(headers, "Content-Length:");
    if (p == NULL)
    {
        p = strstr(headers, "content-length:");
    }
    if (p == NULL)
    {
        return 0;
    }

    p += strlen("Content-Length:");
    while (*p == ' ')
    {
        p++;
    }

    return (uint32_t)strtoul(p, NULL, 10);
}

/**
 * @brief Sends an HTTP response string over a TCP connection.
 */
static void send_response(struct tcp_pcb *pcb, const char *response)
{
    tcp_write(pcb, response, (u16_t)strlen(response), TCP_WRITE_FLAG_COPY);
    tcp_output(pcb);
}

static char s_scd_json_body[256];
static char s_scd_response[512];

/**
 * @brief Handles GET /api/scd requests and returns active configuration metadata in JSON.
 */
static void handle_get_scd(struct tcp_pcb *pcb)
{
    SCD_Config_Lock();
    SCD_ConfigState_t state = SCD_Config_GetState();
    const SCD_Config_t *cfg = SCD_Config_GetActive();

    if (cfg != NULL && state == SCD_CONFIG_STATE_READY && cfg->isValid)
    {
        char file_name[64];
        char id[SCD_MAX_NAME_LEN];
        char version[16];

        strncpy(file_name, cfg->header.fileName, sizeof(file_name) - 1);
        file_name[sizeof(file_name) - 1] = '\0';

        strncpy(id, cfg->header.id, sizeof(id) - 1);
        id[sizeof(id) - 1] = '\0';

        strncpy(version, cfg->header.version, sizeof(version) - 1);
        version[sizeof(version) - 1] = '\0';

        SCD_Config_Unlock();

        int json_len = snprintf(s_scd_json_body, sizeof(s_scd_json_body),
                                "{\"fileName\":\"%s\",\"id\":\"%s\",\"version\":\"%s\"}",
                                file_name, id, version);
        if (json_len < 0)
        {
            json_len = 0;
        }

        int resp_len = snprintf(s_scd_response, sizeof(s_scd_response),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Access-Control-Allow-Origin: *\r\n"
                                "Content-Length: %d\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s",
                                json_len, s_scd_json_body);

        if (resp_len > 0)
        {
            send_response(pcb, s_scd_response);
        }
    }
    else
    {
        SCD_Config_Unlock();

        const char *json_body = "{\"error\":\"No SCD configuration loaded\"}";
        int json_len = (int)strlen(json_body);

        int resp_len = snprintf(s_scd_response, sizeof(s_scd_response),
                                "HTTP/1.1 404 Not Found\r\n"
                                "Content-Type: application/json\r\n"
                                "Access-Control-Allow-Origin: *\r\n"
                                "Content-Length: %d\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s",
                                json_len, json_body);

        if (resp_len > 0)
        {
            send_response(pcb, s_scd_response);
        }
    }
}

static char s_config_json_body[1024];
static char s_config_response[1280];

/**
 * @brief Handles GET /api/config requests and returns runtime system/IDS settings in JSON.
 */
static void handle_get_config(struct tcp_pcb *pcb)
{
    SystemConfig_t cfg;
    SystemConfig_Get(&cfg);

    int body_len = SystemConfig_ToJson(&cfg, s_config_json_body, sizeof(s_config_json_body));
    if (body_len < 0)
    {
        body_len = 0;
    }

    int resp_len = snprintf(s_config_response, sizeof(s_config_response),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: application/json\r\n"
                            "Access-Control-Allow-Origin: *\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "%s",
                            body_len, s_config_json_body);

    if (resp_len > 0)
    {
        send_response(pcb, s_config_response);
    }
}

/**
 * @brief Handles POST /api/config/reset requests and resets settings to factory defaults.
 */
static void handle_reset_config(struct tcp_pcb *pcb)
{
    SystemConfig_ResetToDefaults();
    SystemConfig_SaveToSD();

    SystemConfig_t cfg;
    SystemConfig_Get(&cfg);

    int body_len = SystemConfig_ToJson(&cfg, s_config_json_body, sizeof(s_config_json_body));
    if (body_len < 0)
    {
        body_len = 0;
    }

    int resp_len = snprintf(s_config_response, sizeof(s_config_response),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: application/json\r\n"
                            "Access-Control-Allow-Origin: *\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "%s",
                            body_len, s_config_json_body);

    if (resp_len > 0)
    {
        send_response(pcb, s_config_response);
    }
}

/**
 * @brief Handles POST /api/config requests, validates payload, applies settings, and saves to SD.
 */
static void handle_post_config(struct tcp_pcb *pcb, const char *body, uint16_t body_len)
{
    (void)body_len;
    SystemConfig_t new_cfg;

    if (!SystemConfig_FromJson(body, &new_cfg))
    {
        const char *err_resp =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 42\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"error\":\"Invalid configuration parameters\"}";
        send_response(pcb, err_resp);
        return;
    }

    if (!SystemConfig_Set(&new_cfg))
    {
        const char *err_resp =
            "HTTP/1.1 422 Unprocessable Entity\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 39\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"error\":\"Validation failed on values\"}";
        send_response(pcb, err_resp);
        return;
    }

    SystemConfig_SaveToSD();

    int body_size = SystemConfig_ToJson(&new_cfg, s_config_json_body, sizeof(s_config_json_body));
    if (body_size < 0)
    {
        body_size = 0;
    }

    int total_len = snprintf(s_config_response, sizeof(s_config_response),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/json\r\n"
                             "Access-Control-Allow-Origin: *\r\n"
                             "Content-Length: %d\r\n"
                             "Connection: close\r\n"
                             "\r\n"
                             "%s",
                             body_size, s_config_json_body);

    if (total_len > 0)
    {
        send_response(pcb, s_config_response);
    }
}

/**
 * @brief Streams the alerts response to the HTTP client in TCP-sized chunks.
 */
static void stream_alerts_response(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (client == NULL || pcb == NULL || !client->alerts_active)
    {
        return;
    }

    while (client->resp_sent < client->resp_len)
    {
        u16_t avail = tcp_sndbuf(pcb);
        if (avail == 0)
        {
            break;
        }

        u16_t remaining = (u16_t)(client->resp_len - client->resp_sent);
        u16_t chunk = (remaining > avail) ? avail : remaining;
        if (chunk > 1460)
        {
            chunk = 1460;
        }

        err_t err = tcp_write(pcb, &client->resp_buf[client->resp_sent], chunk, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK)
        {
            break;
        }

        client->resp_sent += chunk;
    }

    if (client->resp_sent > 0)
    {
        tcp_output(pcb);
    }

    if (client->resp_sent >= client->resp_len)
    {
        if (client->alert_buf_idx >= 0)
        {
            release_alert_resp_buffer(client->alert_buf_idx);
            client->alert_buf_idx = -1;
        }
        client->alerts_active = 0;
        api_close_conn(pcb, client);
    }
}

/**
 * @brief Handles GET /api/alerts (or /api/alerts/history) requests without pagination.
 */
static void handle_get_alerts(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (client == NULL || pcb == NULL)
    {
        api_close_conn(pcb, NULL);
        return;
    }

    Security_PeriodicFlush();

    uint32_t total = Security_GetAlertCount();
    uint32_t tot = 0, goose = 0, sv = 0, mms = 0;
    uint32_t crit = 0, high = 0, warn = 0, info = 0;
    Security_GetGlobalStats(&tot, &goose, &sv, &mms);
    Security_GetGlobalSevStats(&crit, &high, &warn, &info);

    int buf_idx = acquire_alert_resp_buffer();
    if (buf_idx < 0)
    {
        const char *busy =
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 27\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"Server is busy\"}";
        send_response(pcb, busy);
        api_close_conn(pcb, client);
        return;
    }

    char *raw_buf = s_alert_resp_buffers[buf_idx];

    if (total == 0)
    {
        int body_len = snprintf(raw_buf + 256, 512,
                                "{\"total\":0,\"total_goose\":0,\"total_sv\":0,\"total_mms\":0,"
                                "\"total_critical\":0,\"total_high\":0,\"total_warning\":0,\"total_info\":0,"
                                "\"alerts\":[],\"count\":0}");

        char hdr[256];
        int hdr_len = snprintf(hdr, sizeof(hdr),
                               "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/json\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Content-Length: %d\r\n"
                               "Connection: close\r\n\r\n",
                               body_len);

        char *full_resp = (raw_buf + 256) - hdr_len;
        memcpy(full_resp, hdr, hdr_len);

        client->resp_buf = full_resp;
        client->resp_len = hdr_len + body_len;
        client->resp_sent = 0;
        client->alert_buf_idx = buf_idx;
        client->alerts_active = 1;

        stream_alerts_response(pcb, client);
        return;
    }

    if (!Security_LockSD(50))
    {
        release_alert_resp_buffer(buf_idx);
        const char *busy =
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 27\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"Server is busy\"}";
        send_response(pcb, busy);
        api_close_conn(pcb, client);
        return;
    }

    FIL file;
    memset(&file, 0, sizeof(file));
    FRESULT res = f_open(&file, SECURITY_ALERTS_FILE, FA_READ);
    if (res != FR_OK)
    {
        Security_UnlockSD();
        release_alert_resp_buffer(buf_idx);
        SysLog_Print(SYSLOG_LEVEL_WARN, "HTTP", "Alerts file open failed (res=%d)", (int)res);
        char body[256];
        int body_len = snprintf(body, sizeof(body),
                                "{\"total\":%lu,\"total_goose\":%lu,\"total_sv\":%lu,\"total_mms\":%lu,"
                                "\"total_critical\":%lu,\"total_high\":%lu,\"total_warning\":%lu,\"total_info\":%lu,"
                                "\"alerts\":[],\"count\":0}",
                                (unsigned long)total,
                                (unsigned long)goose, (unsigned long)sv, (unsigned long)mms,
                                (unsigned long)crit, (unsigned long)high, (unsigned long)warn, (unsigned long)info);

        char resp[512];
        (void)snprintf(resp, sizeof(resp),
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json\r\n"
                       "Access-Control-Allow-Origin: *\r\n"
                       "Content-Length: %d\r\n"
                       "Connection: close\r\n\r\n%s",
                       body_len, body);
        send_response(pcb, resp);
        api_close_conn(pcb, client);
        return;
    }

    char *body_start = raw_buf + 256;
    int body_offset = snprintf(body_start, 512,
                               "{\"total\":%lu,\"total_goose\":%lu,\"total_sv\":%lu,\"total_mms\":%lu,"
                               "\"total_critical\":%lu,\"total_high\":%lu,\"total_warning\":%lu,\"total_info\":%lu,"
                               "\"alerts\":[",
                               (unsigned long)total,
                               (unsigned long)goose, (unsigned long)sv, (unsigned long)mms,
                               (unsigned long)crit, (unsigned long)high, (unsigned long)warn, (unsigned long)info);

    static char temp_line[384];
    uint32_t records_read = 0;
    while ((ALERT_RESP_BUF_SIZE - 256 - body_offset) > 400)
    {
        if (f_gets(temp_line, sizeof(temp_line), &file) == NULL)
        {
            break;
        }

        size_t slen = strlen(temp_line);
        while (slen > 0 && (temp_line[slen - 1] == '\r' || temp_line[slen - 1] == '\n'))
        {
            temp_line[--slen] = '\0';
        }

        if (slen == 0)
        {
            continue;
        }

        if (records_read > 0)
        {
            body_start[body_offset++] = ',';
        }

        memcpy(&body_start[body_offset], temp_line, slen);
        body_offset += (int)slen;
        records_read++;
    }

    body_offset += snprintf(&body_start[body_offset], 64,
                            "],\"count\":%lu}", (unsigned long)records_read);

    f_close(&file);
    Security_UnlockSD();

    char hdr[256];
    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Content-Length: %d\r\n"
                           "Connection: close\r\n\r\n",
                           body_offset);

    char *full_resp = body_start - hdr_len;
    memcpy(full_resp, hdr, hdr_len);

    client->resp_buf = full_resp;
    client->resp_len = hdr_len + body_offset;
    client->resp_sent = 0;
    client->alert_buf_idx = buf_idx;
    client->alerts_active = 1;

    tcp_nagle_disable(pcb);
    stream_alerts_response(pcb, client);
}

/**
 * @brief Handles DELETE /api/alerts and POST /api/alerts/clear requests.
 */
static void handle_clear_alerts(struct tcp_pcb *pcb)
{
    Security_ClearAlertsOnSD();
    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: 32\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"ok\",\"cleared\":true}\r\n";
    send_response(pcb, resp);
}

/**
 * @brief Forwards incoming SCD payload chunks to storage with bounded flow control.
 */
static bool process_scd_data(struct tcp_pcb *pcb, HTTP_API_Client_t *client, const uint8_t *data, uint16_t len)
{
    if (!client->post_active || len == 0)
    {
        return true;
    }

    uint32_t remaining = client->content_length - client->body_received;
    if (remaining == 0)
    {
        return true;
    }

    if ((uint32_t)len > remaining)
    {
        len = (uint16_t)remaining;
    }

    if (!SCD_Storage_Enqueue(data, len))
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "HTTP", "SCD Storage enqueue failed, aborting upload");
        SCD_Storage_Abort();
        client->post_active = 0;
        s_scd_upload_active = 0;

        const char *err_resp =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 26\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"error\":\"Storage failed\"}";
        send_response(pcb, err_resp);
        api_close_conn(pcb, client);
        return false;
    }

    client->body_received += len;
    tcp_recved(pcb, len);
    return true;
}

/**
 * @brief Finalizes an SCD upload POST request.
 *
 * IMPORTANT: This function must NOT block the lwIP tcpip thread.
 * SCD_Storage_End_NoWait() merely enqueues the END event; the storage task
 * performs the actual file sync and then signals SCD_Config_Task to reload.
 * We send the HTTP 202 Accepted response immediately and close the connection.
 * The config reload completes asynchronously on the SCD_ConfigTask.
 */
static void finish_post(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (!client->post_active)
    {
        return;
    }

    client->post_active = 0;
    s_scd_upload_active = 0;

    SCD_Storage_End_Async();

    SysLog_Print(SYSLOG_LEVEL_INFO, "HTTP", "SCD upload complete (%lu bytes), reload triggered",
                 client->body_received);

    const char *response =
        "HTTP/1.1 202 Accepted\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: 34\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"ok\",\"reloading\":true}  ";

    send_response(pcb, response);
    api_close_conn(pcb, client);
}

/**
 * @brief Closes a TCP connection cleanly and frees associated client resources.
 */
static void api_close_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (client != NULL)
    {
        if (client->post_active)
        {
            SCD_Storage_Abort();
            client->post_active = 0;
            s_scd_upload_active = 0;
        }
        remove_sse_client(client);
        free_client(client);
    }

    if (pcb != NULL)
    {
        tcp_arg(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        tcp_poll(pcb, NULL, 0);

        err_t close_err = tcp_close(pcb);
        if (close_err != ERR_OK)
        {
            tcp_abort(pcb);
        }
    }
}

/**
 * @brief Aborts a TCP connection immediately (sends RST and frees PCB).
 *        Must be used when returning ERR_ABRT from callbacks.
 */
static void api_abort_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (client != NULL)
    {
        if (client->post_active)
        {
            SCD_Storage_Abort();
            client->post_active = 0;
            s_scd_upload_active = 0;
        }
        remove_sse_client(client);
        free_client(client);
    }

    if (pcb != NULL)
    {
        tcp_arg(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        tcp_poll(pcb, NULL, 0);
        tcp_abort(pcb);
    }
}

/**
 * @brief TCP error callback invoked on connection errors.
 */
static void api_err(void *arg, err_t err)
{
    HTTP_API_Client_t *client = (HTTP_API_Client_t *)arg;
    SysLog_Print(SYSLOG_LEVEL_DEBUG, "HTTP", "Connection error: %d", err);
    if (client != NULL)
    {
        if (client->post_active)
        {
            SCD_Storage_Abort();
            client->post_active = 0;
            s_scd_upload_active = 0;
        }
        remove_sse_client(client);
        free_client(client);
    }
}

/**
 * @brief TCP receive callback handling incoming HTTP requests.
 */
static err_t api_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    HTTP_API_Client_t *client = (HTTP_API_Client_t *)arg;

    if (p == NULL)
    {
        api_close_conn(pcb, client);
        return ERR_OK;
    }

    if (err != ERR_OK)
    {
        pbuf_free(p);
        api_abort_conn(pcb, client);
        return ERR_ABRT;
    }

    if (client == NULL)
    {
        client = alloc_client(pcb);
        if (client == NULL)
        {
            SysLog_Print(SYSLOG_LEVEL_WARN, "HTTP", "Client pool exhausted (SSE=%u)", sse_client_count);
            pbuf_free(p);
            tcp_abort(pcb);
            return ERR_ABRT;
        }

        tcp_arg(pcb, client);
        tcp_poll(pcb, api_poll, 4);
    }

    client->last_activity = HAL_GetTick();

    if (!client->header_complete)
    {
        uint16_t copy_len = p->tot_len;
        uint16_t remaining = (uint16_t)(HTTP_API_REQUEST_BUFFER_SIZE - 1 - client->header_len);

        if (copy_len > remaining)
        {
            copy_len = remaining;
        }

        pbuf_copy_partial(p, client->request + client->header_len, copy_len, 0);
        client->header_len += copy_len;
        client->request[client->header_len] = '\0';

        int header_end = find_header_end(client->request, client->header_len);
        if (header_end < 0)
        {
            tcp_recved(pcb, p->tot_len);
            pbuf_free(p);
            return ERR_OK;
        }

        client->header_complete = 1;

        if (strncmp(client->request, "OPTIONS ", 8) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            const char *response =
                "HTTP/1.1 204 No Content\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, Accept, Authorization, X-Requested-With\r\n"
                "Access-Control-Max-Age: 86400\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";

            send_response(pcb, response);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "GET /api/scd", 12) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            handle_get_scd(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "GET /api/alerts/events", 22) == 0 ||
            strncmp(client->request, "GET /api/alerts/stream", 22) == 0 ||
            (strncmp(client->request, "GET /api/alerts", 15) == 0 && strstr(client->request, "text/event-stream") != NULL))
        {
            tcp_recved(pcb, p->tot_len);
            if (sse_client_count >= MAX_SSE_CLIENTS)
            {
                const char *resp =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Connection: close\r\n\r\n";
                send_response(pcb, resp);
                pbuf_free(p);
                api_close_conn(pcb, client);
                return ERR_OK;
            }

            client->is_sse = 1;
            client->next_sse = sse_clients;
            sse_clients = client;
            sse_client_count++;

            const char *sse_headers =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: keep-alive\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n";

            tcp_write(pcb, sse_headers, (u16_t)strlen(sse_headers), TCP_WRITE_FLAG_COPY);
            tcp_output(pcb);

            pbuf_free(p);
            return ERR_OK;
        }

        if (strncmp(client->request, "GET /api/alerts", 15) == 0 ||
            strncmp(client->request, "GET /api/alerts/history", 23) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            handle_get_alerts(pcb, client);
            pbuf_free(p);
            return ERR_OK;
        }

        if (strncmp(client->request, "DELETE /api/alerts", 18) == 0 ||
            strncmp(client->request, "POST /api/alerts/clear", 22) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            SysLog_Print(SYSLOG_LEVEL_INFO, "SEC", "Alert history cleared via HTTP API");
            handle_clear_alerts(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "GET /api/config", 15) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            handle_get_config(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "POST /api/config/reset", 22) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            SysLog_Print(SYSLOG_LEVEL_INFO, "CONFIG", "Configuration reset to factory defaults");
            handle_reset_config(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "POST /api/config", 16) == 0)
        {
            client->content_length = parse_content_length(client->request);
            uint16_t body_offset = (uint16_t)header_end;
            uint16_t body_available = 0;
            if (client->header_len > body_offset)
            {
                body_available = client->header_len - body_offset;
            }

            SysLog_Print(SYSLOG_LEVEL_INFO, "CONFIG", "POST /api/config received (Length: %lu)",
                         (unsigned long)client->content_length);

            if (body_available >= client->content_length)
            {
                tcp_recved(pcb, p->tot_len);
                client->request[body_offset + client->content_length] = '\0';
                handle_post_config(pcb, client->request + body_offset, (uint16_t)client->content_length);
                pbuf_free(p);
                api_close_conn(pcb, client);
                return ERR_OK;
            }
            else
            {
                client->post_config_active = 1;
                client->body_received = body_available;
                tcp_recved(pcb, p->tot_len);
                pbuf_free(p);
                return ERR_OK;
            }
        }

        if (strncmp(client->request, "POST /api/scd", 13) == 0)
        {
            if (s_scd_upload_active)
            {
                SysLog_Print(SYSLOG_LEVEL_WARN, "HTTP", "POST /api/scd rejected: upload already in progress");
                tcp_recved(pcb, p->tot_len);
                const char *busy_resp =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Type: application/json\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Content-Length: 30\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "{\"error\":\"Upload in progress\"}";
                send_response(pcb, busy_resp);
                pbuf_free(p);
                api_close_conn(pcb, client);
                return ERR_OK;
            }

            s_scd_upload_active = 1;
            client->content_length = parse_content_length(client->request);
            client->body_received = 0;
            client->post_active = 1;

            SysLog_Print(SYSLOG_LEVEL_INFO, "HTTP", "POST /api/scd started (Length: %lu)", client->content_length);

            SCD_Storage_Start();

            uint16_t body_offset = (uint16_t)header_end;
            tcp_recved(pcb, body_offset);

            if (client->header_len > body_offset)
            {
                uint16_t body_len = client->header_len - body_offset;
                if (!process_scd_data(pcb, client, (const uint8_t *)client->request + body_offset, body_len))
                {
                    pbuf_free(p);
                    return ERR_OK;
                }
            }

            if (client->body_received >= client->content_length)
            {
                finish_post(pcb, client);
            }

            pbuf_free(p);
            return ERR_OK;
        }

        tcp_recved(pcb, p->tot_len);
        const char *response =
            "HTTP/1.1 404 Not Found\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";

        send_response(pcb, response);
        pbuf_free(p);
        api_close_conn(pcb, client);
        return ERR_OK;
    }

    if (client->post_active)
    {
        uint16_t total_len = p->tot_len;
        uint16_t processed = 0;

        while (processed < total_len)
        {
            uint8_t temp[BODY_CHUNK_SIZE];
            uint16_t copy_len = total_len - processed;
            if (copy_len > sizeof(temp))
            {
                copy_len = sizeof(temp);
            }

            pbuf_copy_partial(p, temp, copy_len, processed);
            if (!process_scd_data(pcb, client, temp, copy_len))
            {
                pbuf_free(p);
                return ERR_OK;
            }
            processed += copy_len;
        }

        if (client->body_received >= client->content_length)
        {
            finish_post(pcb, client);
            pbuf_free(p);
            return ERR_OK;
        }
    }
    else if (client->post_config_active)
    {
        uint16_t total_len = p->tot_len;
        int header_end = find_header_end(client->request, client->header_len);
        uint16_t body_offset = (header_end > 0) ? (uint16_t)header_end : 0;
        uint16_t space_remaining = 0;
        if ((body_offset + client->body_received) < (HTTP_API_REQUEST_BUFFER_SIZE - 1))
        {
            space_remaining = (HTTP_API_REQUEST_BUFFER_SIZE - 1) - (body_offset + client->body_received);
        }
        uint16_t copy_len = (total_len < space_remaining) ? total_len : space_remaining;

        pbuf_copy_partial(p, client->request + body_offset + client->body_received, copy_len, 0);
        client->body_received += copy_len;
        tcp_recved(pcb, total_len);

        if (client->body_received >= client->content_length)
        {
            client->request[body_offset + client->content_length] = '\0';
            handle_post_config(pcb, client->request + body_offset, (uint16_t)client->content_length);
            client->post_config_active = 0;
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        pbuf_free(p);
        return ERR_OK;
    }
    else
    {
        tcp_recved(pcb, p->tot_len);
    }

    pbuf_free(p);
    return ERR_OK;
}

/**
 * @brief TCP accept callback for incoming client connections on the API port.
 */
static err_t api_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;

    if (err != ERR_OK || newpcb == NULL)
    {
        return ERR_VAL;
    }

    HTTP_API_Client_t *client = alloc_client(newpcb);
    if (client == NULL)
    {
        SysLog_Print(SYSLOG_LEVEL_WARN, "HTTP", "Client pool exhausted on accept (SSE=%u)", sse_client_count);
        return ERR_MEM;
    }

    tcp_arg(newpcb, client);
    tcp_recv(newpcb, api_recv);
    tcp_sent(newpcb, api_sent);
    tcp_err(newpcb, api_err);
    tcp_poll(newpcb, api_poll, 4);
    tcp_nagle_disable(newpcb);

    return ERR_OK;
}

static uint8_t s_http_initialized = 0;

/**
 * @brief Initializes and starts the HTTP REST API server on port 8080.
 */
void HTTP_API_Init(void)
{
    if (api_pcb != NULL)
    {
        return;
    }

    memset(s_clients, 0, sizeof(s_clients));
    memset(s_alert_pool, 0, sizeof(s_alert_pool));
    s_scd_upload_active = 0;

    if (s_alert_pool_mutex == NULL)
    {
        s_alert_pool_mutex = osMutexCreate(osMutex(AlertPoolMutex));
    }

    api_pcb = tcp_new();
    if (api_pcb == NULL)
    {
        return;
    }

    if (tcp_bind(api_pcb, IP_ADDR_ANY, HTTP_API_PORT) != ERR_OK)
    {
        tcp_close(api_pcb);
        api_pcb = NULL;
        return;
    }

    api_pcb = tcp_listen(api_pcb);
    if (api_pcb == NULL)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "HTTP", "Failed to listen on port %d", HTTP_API_PORT);
        return;
    }

    tcp_accept(api_pcb, api_accept);
    s_http_initialized = 1;
    SysLog_Print(SYSLOG_LEVEL_INFO, "HTTP", "Server listening on port %d", HTTP_API_PORT);
}

/**
 * @brief Returns 1 if the HTTP server listening PCB is active, 0 otherwise.
 */
uint8_t HTTP_API_IsListening(void)
{
    return (api_pcb != NULL && api_pcb->state == LISTEN);
}

/**
 * @brief Verifies that the HTTP server is listening, re-initializing if needed.
 */
void HTTP_API_EnsureListening(void)
{
    if (!s_http_initialized)
    {
        return;
    }

    if (!HTTP_API_IsListening())
    {
        SysLog_Print(SYSLOG_LEVEL_WARN, "HTTP", "Server not listening! Re-initializing port %d...", HTTP_API_PORT);
        HTTP_API_Init();
    }
}

/**
 * @brief Broadcasts an SSE alert payload to all connected SSE clients.
 */
static void do_broadcast_alert(void *ctx)
{
    SSE_Message_t *msg = (SSE_Message_t *)ctx;
    if (msg == NULL)
    {
        return;
    }

    char sse_payload[576];
    int sse_len = snprintf(sse_payload, sizeof(sse_payload), "data: %s\n\n", msg->data);

    if (sse_len > 0 && sse_len < (int)sizeof(sse_payload))
    {
        HTTP_API_Client_t *curr = sse_clients;
        while (curr != NULL)
        {
            HTTP_API_Client_t *next = curr->next_sse;
            if (curr->is_sse && curr->pcb != NULL)
            {
                err_t err = tcp_write(curr->pcb, sse_payload, (u16_t)sse_len, TCP_WRITE_FLAG_COPY);
                if (err == ERR_OK)
                {
                    tcp_output(curr->pcb);
                    curr->last_activity = HAL_GetTick();
                }
                else if (err == ERR_MEM)
                {
                }
                else
                {
                    SysLog_Print(SYSLOG_LEVEL_DEBUG, "HTTP", "SSE broadcast failed (%d), dropping client", err);
                    api_close_conn(curr->pcb, curr);
                }
            }
            curr = next;
        }
    }

    if (s_alert_pool_mutex != NULL)
    {
        osMutexWait(s_alert_pool_mutex, osWaitForever);
        msg->in_use = 0;
        osMutexRelease(s_alert_pool_mutex);
    }
    else
    {
        msg->in_use = 0;
    }
}

/**
 * @brief Enqueues an alert JSON line for broadcast to all connected SSE clients.
 */
void HTTP_API_BroadcastAlert(const char *json_line, uint16_t len)
{
    if (json_line == NULL || len == 0 || sse_clients == NULL)
    {
        return;
    }

    if (s_alert_pool_mutex == NULL)
    {
        s_alert_pool_mutex = osMutexCreate(osMutex(AlertPoolMutex));
        if (s_alert_pool_mutex == NULL)
        {
            return;
        }
    }

    if (osMutexWait(s_alert_pool_mutex, 100) != osOK)
    {
        return;
    }

    SSE_Message_t *msg = NULL;
    for (int i = 0; i < MAX_ALERT_POOL; i++)
    {
        if (!s_alert_pool[i].in_use)
        {
            msg = &s_alert_pool[i];
            msg->in_use = 1;
            break;
        }
    }

    if (msg == NULL)
    {
        osMutexRelease(s_alert_pool_mutex);
        return;
    }

    if (len >= sizeof(msg->data))
    {
        len = sizeof(msg->data) - 1;
    }

    memcpy(msg->data, json_line, len);
    msg->data[len] = '\0';

    if (len > 0 && msg->data[len - 1] == '\n')
    {
        msg->data[len - 1] = '\0';
    }

    msg->len = (uint16_t)strlen(msg->data);

    osMutexRelease(s_alert_pool_mutex);

    if (tcpip_callback(do_broadcast_alert, msg) != ERR_OK)
    {
        if (s_alert_pool_mutex != NULL)
        {
            osMutexWait(s_alert_pool_mutex, osWaitForever);
            msg->in_use = 0;
            osMutexRelease(s_alert_pool_mutex);
        }
        else
        {
            msg->in_use = 0;
        }
    }
}

#include "raw_eth.h"
#include "http_api.h"
#include "scd_storage.h"
#include "scd_config.h"
#include "system_config.h"
#include "system_logger.h"
#include "security.h"
#include "ethernetif.h"
#include "sdmmc.h"
#include "storage_service.h"
#include "runtime_stats.h"
#include "health_monitor.h"
#include "sys_diag.h"
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

#define HTTP_JSON_BODY_MAX 4096
#define HTTP_JSON_RESP_MAX (HTTP_JSON_BODY_MAX + 256)
#define HTTP_JSON_SMALL_BODY_MAX 512
#define HTTP_JSON_SMALL_RESP_MAX (HTTP_JSON_SMALL_BODY_MAX + 256)

static void send_json_overflow(struct tcp_pcb *pcb);

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
    uint32_t gen;
    struct StorageRequest_s *storage_req;
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

/**
 * @brief Reserves one shared alert response buffer.
 * @return Buffer index, or -1 when every buffer is currently in use.
 */
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

/**
 * @brief Returns a shared alert response buffer to the pool.
 * @param idx Buffer index previously returned by acquire_alert_resp_buffer().
 */
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

static volatile uint32_t s_sse_delivered = 0;
static volatile uint32_t s_sse_pool_exhausted = 0;
static volatile uint32_t s_sse_post_failed = 0;
static volatile uint32_t s_storage_callback_failures = 0;

static void api_close_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static void api_abort_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static void stream_alerts_response(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static bool process_scd_data(struct tcp_pcb *pcb, HTTP_API_Client_t *client, const uint8_t *data, uint16_t len);
static void finish_post(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static void do_storage_complete(void *ctx);

/**
 * @brief Allocates a client state slot from the static pool.
 * @param pcb Connection the client record belongs to.
 * @return Allocated client record, or NULL when the table is full.
 */
static HTTP_API_Client_t *alloc_client(struct tcp_pcb *pcb)
{
    for (int i = 0; i < MAX_HTTP_CLIENTS; i++)
    {
        if (!s_clients[i].in_use)
        {
            uint32_t gen = s_clients[i].gen + 1U;
            memset(&s_clients[i], 0, sizeof(HTTP_API_Client_t));
            s_clients[i].gen = gen;
            s_clients[i].in_use = 1;
            s_clients[i].alert_buf_idx = -1;
            s_clients[i].storage_req = NULL;
            s_clients[i].pcb = pcb;
            s_clients[i].last_activity = HAL_GetTick();
            return &s_clients[i];
        }
    }
    return NULL;
}

/**
 * @brief Releases a client state slot back to the static pool.
 *
 * An alert response buffer owned by an in-flight storage request is NOT
 * released here: the request keeps ownership and the completion callback
 * releases it. This prevents a recycled buffer being written by the storage
 * task while another client is using it.
 * @param client Client record to release; ignored when NULL.
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
        client->storage_req = NULL;
        client->alerts_active = 0;
        client->in_use = 0;
        client->pcb = NULL;
    }
}

/**
 * @brief Removes an SSE client from the active broadcast list.
 * @param client SSE client to unlink from the broadcast list.
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
 * @param arg Callback argument (unused).
 * @param pcb Connection that acknowledged the data.
 * @param len Number of bytes acknowledged.
 * @return ERR_OK.
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
 * @param arg Callback argument (unused).
 * @param pcb Connection to service.
 * @return ERR_OK, or ERR_ABRT after the connection was closed.
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
        else if (now - client->last_activity >= 15000U)
        {
            SysLog_Print(SYSLOG_LEVEL_DEBUG, "HTTP", "Alert stream stalled, aborting");
            api_abort_conn(pcb, client);
            return ERR_ABRT;
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
 * @param data Received bytes.
 * @param len Number of bytes available.
 * @return Offset just past the terminating CRLFCRLF, or -1 when the headers are incomplete.
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
 * @param headers NUL-terminated request headers.
 * @return Declared Content-Length, or 0 when the header is absent or invalid.
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
 * @param pcb Connection to write to.
 * @param response Complete HTTP response text, including the status line and headers.
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
 * @param pcb Connection to answer.
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
 * @param pcb Connection to answer.
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
 * @brief Queues a configuration persistence request for the storage owner.
 *        The HTTP response is produced by do_storage_complete().
 * @param pcb Connection to answer.
 * @param client Client state owning the request.
 */
static void submit_config_save(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    StorageRequest_t *req = StorageService_Acquire();
    if (req == NULL || !StorageService_Submit(req))
    {
        if (req != NULL)
        {
            StorageService_Release(req);
        }
        const char *err_resp =
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 30\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"Storage is busy\"}";
        send_response(pcb, err_resp);
        api_close_conn(pcb, client);
        return;
    }

    req->op = STORAGE_OP_CONFIG_SAVE;
    req->ctx = client;
    req->ctx_gen = client->gen;
    req->buf_idx = -1;
    client->storage_req = req;
}

/**
 * @brief Handles POST /api/config/reset requests and resets settings to factory defaults.
 * @param pcb Connection to answer.
 * @param client Client state owning the request.
 */
static void handle_reset_config(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    SystemConfig_ResetToDefaults();
    submit_config_save(pcb, client);
}

/**
 * @brief Handles POST /api/config requests, validates payload, applies settings, and saves to SD.
 * @param pcb Connection to answer.
 * @param body Request body.
 * @param body_len Length of the request body.
 * @param client Client state owning the request.
 */
static void handle_post_config(struct tcp_pcb *pcb, const char *body, uint16_t body_len, HTTP_API_Client_t *client)
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
        api_close_conn(pcb, client);
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
        api_close_conn(pcb, client);
        return;
    }

    submit_config_save(pcb, client);
}

/**
 * @brief Streams the alerts response to the HTTP client in TCP-sized chunks.
 * @param pcb Connection to stream to.
 * @param client Client state holding the stream cursor.
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
 * @brief Handles GET /api/accounting requests.
 * @param pcb Connection to answer.
 */
static void handle_get_accounting(struct tcp_pcb *pcb)
{
    PacketAccounting a;
    Security_Stats_t health;
    Ethernet_Diagnostics_t ethernet;
    SDMMC_Diagnostics_t sd;
    StorageService_Stats_t storage;
    StorageService_MediaStats_t media;
    SysLog_Stats_t logstats;
    SysDiag_Stats_t diag;
    static char body[HTTP_JSON_BODY_MAX], response[HTTP_JSON_RESP_MAX];
    Accounting_Get(&a);
    Security_GetStats(&health);
    Ethernet_GetDiagnostics(&ethernet);
    SDMMC_GetDiagnostics(&sd);
    StorageService_GetStats(&storage);
    StorageService_GetMediaStats(&media);
    SysLog_GetStats(&logstats);
    SysDiag_Get(&diag);
    int n = snprintf(body, sizeof(body), "{\"protocols\":[");
    for (int i = 0; i < ACCOUNT_PROTOCOLS && n > 0 && n < (int)sizeof(body); i++)
    {
        n += snprintf(body + n, sizeof(body) - (size_t)n,
                      "%s{\"rx\":%lu,\"parsed\":%lu,\"parse_failed\":%lu,\"drop_size_or_init\":%lu,\"drop_pool\":%lu,\"drop_queue\":%lu}",
                      i ? "," : "", (unsigned long)a.values[i][ACCOUNT_RX],
                      (unsigned long)a.values[i][ACCOUNT_PARSED], (unsigned long)a.values[i][ACCOUNT_PARSE_FAILED],
                      (unsigned long)a.values[i][ACCOUNT_DROP_SIZE_OR_INIT], (unsigned long)a.values[i][ACCOUNT_DROP_POOL],
                      (unsigned long)a.values[i][ACCOUNT_DROP_QUEUE]);
    }
    if (n <= 0 || n >= (int)sizeof(body))
    {
        send_json_overflow(pcb);
        return;
    }
    n += snprintf(body + n, sizeof(body) - (size_t)n,
                  "],\"saturated\":%lu,\"last_parsed_ms\":%lu,\"alerts_created\":%lu,\"alerts_persisted\":%lu,\"alert_queue_failures\":%lu,\"storage_errors\":%lu,\"queue_used\":%lu,\"queue_high_water\":%lu,\"queue_capacity\":%lu,\"alerts_attempted\":%lu,\"persistence_retries\":%lu,\"alerts_dropped_buffer_full\":%lu,\"alerts_dropped_mutex_busy\":%lu,\"alerts_purged\":%lu,\"alert_tail_repairs\":%lu,\"driver_delivered\":%lu,\"rx_alloc_failures\":%lu,\"dma_error_callbacks\":%lu,\"rx_buffer_unavailable_events\":%lu,\"lwip_input_failures\":%lu,\"dma_region_violations\":%lu,\"free_heap_bytes\":%lu,\"min_free_heap_bytes\":%lu,\"task_count\":%lu,\"sd_read_failures\":%lu,\"sd_write_failures\":%lu,\"sd_write_retries\":%lu,\"sd_write_recovered\":%lu,\"sd_timeouts\":%lu,\"sd_max_write_ms\":%lu,\"sd_card_ready_timeouts\":%lu,\"sd_max_irq_off_us\":%lu,\"storage_submitted\":%lu,\"storage_ok\":%lu,\"storage_fail\":%lu,\"storage_queue_full\":%lu,\"storage_lock_timeouts\":%lu,\"storage_cb_failures\":%lu,\"sd_card_present\":%lu,\"sd_drive_ready\":%lu,\"sd_mounted\":%lu,\"sd_media_removals\":%lu,\"sd_media_insertions\":%lu,\"sd_drive_faults\":%lu,\"sd_drive_recoveries\":%lu,\"sd_remount_attempts\":%lu,\"sd_remount_ok\":%lu,\"sd_remount_fail\":%lu,\"sd_remount_verify_fail\":%lu,\"sd_disk_init_attempts\":%lu,\"sd_disk_init_failures\":%lu,\"sse_delivered\":%lu,\"sse_pool_exhausted\":%lu,\"sse_post_failed\":%lu,\"uptime_ms\":%lu,\"boot_count\":%lu,\"reset_flags\":%lu",
                  (unsigned long)a.saturated, (unsigned long)a.last_parsed_ms, (unsigned long)health.alerts_generated,
                  (unsigned long)health.alerts_written, (unsigned long)health.alerts_dropped, (unsigned long)health.storage_errors,
                  (unsigned long)health.slots_in_use, (unsigned long)health.slots_high_water,
                  (unsigned long)Security_GetPipelineCapacity(),
                  (unsigned long)health.alerts_attempted, (unsigned long)health.persistence_retries,
                  (unsigned long)health.alerts_dropped_buffer_full, (unsigned long)health.alerts_dropped_mutex_busy,
                  (unsigned long)health.alerts_purged, (unsigned long)health.alert_tail_repairs,
                  (unsigned long)ethernet.delivered, (unsigned long)ethernet.rx_alloc_failures,
                  (unsigned long)ethernet.dma_error_callbacks, (unsigned long)ethernet.rx_buffer_unavailable,
                  (unsigned long)ethernet.lwip_input_failures,
                  (unsigned long)ethernet.dma_region_violations, (unsigned long)xPortGetFreeHeapSize(), (unsigned long)xPortGetMinimumEverFreeHeapSize(), (unsigned long)uxTaskGetNumberOfTasks(),
                  (unsigned long)sd.read_failures, (unsigned long)sd.write_failures,
                  (unsigned long)sd.write_retries, (unsigned long)sd.write_recovered,
                  (unsigned long)sd.timeouts, (unsigned long)sd.max_write_ms,
                  (unsigned long)sd.card_ready_timeouts, (unsigned long)sd.max_irq_off_us,
                  (unsigned long)storage.submitted, (unsigned long)storage.completed_ok,
                  (unsigned long)storage.completed_fail, (unsigned long)storage.queue_full,
                  (unsigned long)storage.lock_timeouts, (unsigned long)s_storage_callback_failures,
                  (unsigned long)media.card_present, (unsigned long)media.drive_ready, (unsigned long)media.mounted,
                  (unsigned long)media.removals, (unsigned long)media.insertions,
                  (unsigned long)media.drive_faults, (unsigned long)media.drive_recoveries,
                  (unsigned long)media.remount_attempts, (unsigned long)media.remount_ok,
                  (unsigned long)media.remount_fail, (unsigned long)media.verify_failures,
                  (unsigned long)media.disk_init_attempts, (unsigned long)media.disk_init_failures,
                  (unsigned long)s_sse_delivered, (unsigned long)s_sse_pool_exhausted,
                  (unsigned long)s_sse_post_failed,
                  (unsigned long)diag.uptime_ms, (unsigned long)diag.boot_count,
                  (unsigned long)diag.reset_flags);
    if (n <= 0 || n >= (int)sizeof(body))
    {
        send_json_overflow(pcb);
        return;
    }
    {
        HealthMonitor_Stats_t wd;
        uint32_t p_start_ms, p_stop_ms, p_start_cyc, p_stop_cyc;
        HealthMonitor_GetStats(&wd);
        HealthMonitor_GetProbe(&p_start_ms, &p_stop_ms, &p_start_cyc, &p_stop_cyc);
        n += snprintf(body + n, sizeof(body) - (size_t)n,
                      ",\"wd_enabled\":%u,\"wd_configured\":%u,\"wd_feeds\":%lu,\"wd_withheld\":%lu,"
                      "\"wd_max_service_gap_ms\":%lu,\"wd_max_beat_gap_ms\":%lu,"
                      "\"wd_last_fail_task\":%u,\"wd_reset_by_iwdg\":%u,"
                      "\"wd_pr\":%lu,\"wd_rlr\":%lu,"
                      "\"wd_probe_ms\":%lu,\"wd_probe_cycles\":%lu,"
                      "\"wd_probe_start_ms\":%lu,\"wd_probe_stop_ms\":%lu,"
                      "\"rx_irq_to_task_min_us\":%lu,\"rx_irq_to_task_avg_us\":%lu,"
                      "\"rx_irq_to_task_max_us\":%lu,\"rx_irq_to_task_samples\":%lu,"
                      "\"rx_irq_to_task_over_1ms\":%lu,"
                      "\"rx_process_min_us\":%lu,\"rx_process_avg_us\":%lu,"
                      "\"rx_process_max_us\":%lu,\"rx_process_samples\":%lu,"
                      "\"rx_process_over_1ms\":%lu,\"dmasr\":%lu,"
                      "\"rx_max_frame_len\":%lu,\"rx_len_corrected\":%lu,\"rx_len_unverifiable\":%lu,\"rx_last_raw_len\":%lu,\"rx_last_fixed_len\":%lu,\"rx_last_tail\":%lu,"
                      "\"rx_frames_ge_1024\":%lu,"
                      "\"rx_frames_ge_1400\":%lu,"
                      "\"tx_frames\":%lu,\"tx_max_len\":%lu,\"tx_failures\":%lu,\"tx_last_err\":%lu,"
                      "\"rx_last_tot_len\":%lu,\"rx_last_ip_total_len\":%lu,\"rx_last_etype\":%lu,"
                      "\"rx_probe_ihl\":%lu,\"rx_probe_icmp_type\":%lu,\"rx_probe_icmp_sum\":%lu,"
                      "\"rx_probe_icmp_verify\":%lu,\"rx_probe_dmasr\":%lu,"
                      "\"rx_probe_last\":%lu,\"rx_probe_beyond\":%lu,\"rx_probe_count\":%lu,"
                      "\"log_stored\":%lu,\"log_unpersisted\":%lu,\"log_queue_dropped\":%lu,"
                      "\"log_queue_high_water\":%lu,\"log_segment_index\":%lu,\"log_segments\":%lu,"
                      "\"log_segment_bytes\":%lu,\"log_tail_repairs\":%lu,\"log_last_error\":%ld,"
                      "\"log_storage_full\":%u}",
                      (unsigned)wd.enabled, (unsigned)wd.configured,
                      (unsigned long)wd.feeds,
                      (unsigned long)wd.withheld, (unsigned long)wd.max_service_gap_ms,
                      (unsigned long)wd.max_beat_gap_ms[HEALTH_TASK_ETH_RX],
                      (unsigned)wd.last_fail_task, (unsigned)wd.reset_by_iwdg,
                      (unsigned long)(IWDG->PR & 7U), (unsigned long)(IWDG->RLR & 0xFFFU),
                      (unsigned long)(p_stop_ms - p_start_ms),
                      (unsigned long)(p_stop_cyc - p_start_cyc),
                      (unsigned long)p_start_ms, (unsigned long)p_stop_ms,
                      (unsigned long)ethernet.rx_irq_to_task_min_us,
                      (unsigned long)ethernet.rx_irq_to_task_avg_us,
                      (unsigned long)ethernet.rx_irq_to_task_max_us,
                      (unsigned long)ethernet.rx_irq_to_task_samples,
                      (unsigned long)ethernet.rx_irq_to_task_over_1ms,
                      (unsigned long)ethernet.rx_process_min_us,
                      (unsigned long)ethernet.rx_process_avg_us,
                      (unsigned long)ethernet.rx_process_max_us,
                      (unsigned long)ethernet.rx_process_samples,
                      (unsigned long)ethernet.rx_process_over_1ms,
                      (unsigned long)ethernet.dmasr,
                      (unsigned long)ethernet.rx_max_frame_len,
                      (unsigned long)ethernet.rx_len_corrected, (unsigned long)ethernet.rx_len_unverifiable, (unsigned long)ethernet.rx_last_raw_len,
                      (unsigned long)ethernet.rx_last_fixed_len, (unsigned long)ethernet.rx_last_tail,
                      (unsigned long)ethernet.rx_frames_ge_1024,
                      (unsigned long)ethernet.rx_frames_ge_1400,
                      (unsigned long)ethernet.tx_frames,
                      (unsigned long)ethernet.tx_max_len,
                      (unsigned long)ethernet.tx_failures,
                      (unsigned long)ethernet.tx_last_err,
                      (unsigned long)ethernet.rx_last_tot_len,
                      (unsigned long)ethernet.rx_last_ip_total_len,
                      (unsigned long)ethernet.rx_last_etype,
                      (unsigned long)ethernet.rx_probe_ihl,
                      (unsigned long)ethernet.rx_probe_icmp_type,
                      (unsigned long)ethernet.rx_probe_icmp_sum,
                      (unsigned long)ethernet.rx_probe_icmp_verify,
                      (unsigned long)ethernet.rx_probe_dmasr,
                      (unsigned long)ethernet.rx_probe_last,
                      (unsigned long)ethernet.rx_probe_beyond,
                      (unsigned long)ethernet.rx_probe_count,
                      (unsigned long)logstats.stored, (unsigned long)logstats.unpersisted,
                      (unsigned long)logstats.queue_dropped, (unsigned long)logstats.queue_high_water,
                      (unsigned long)logstats.segment_index, (unsigned long)logstats.segments,
                      (unsigned long)logstats.segment_bytes, (unsigned long)logstats.tail_repairs,
                      (long)logstats.last_error, (unsigned)logstats.storage_full);
        if (n <= 0 || n >= (int)sizeof(body))
        {
            send_json_overflow(pcb);
            return;
        }
    }
    int r = snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", n, body);
    if (r > 0 && r < (int)sizeof(response))
    {
        send_response(pcb, response);
    }
    else
    {
        send_json_overflow(pcb);
    }
}

/**
 * @brief Reports a response that did not fit its buffer.
 *
 * Truncated JSON must never be sent as a success: a client parsing a partial
 * document would silently see fewer records or fields than actually exist.
 * @param pcb Connection to answer with the overflow response.
 */
static void send_json_overflow(struct tcp_pcb *pcb)
{
    static const char msg[] = "{\"error\":\"response_buffer_too_small\"}";
    char hdr[224];
    int r = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 500 Internal Server Error\r\n"
                     "Content-Type: application/json\r\n"
                     "Cache-Control: no-store\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Content-Length: %u\r\n"
                     "Connection: close\r\n\r\n%s",
                     (unsigned)(sizeof(msg) - 1U), msg);
    if (r > 0 && r < (int)sizeof(hdr))
    {
        send_response(pcb, hdr);
    }
}

/**
 * @brief Converts a part/whole ratio to a tenths-of-percent integer.
 * @param part Numerator.
 * @param whole Denominator.
 * @return Percentage in tenths, or 0 when whole is 0.
 */
static uint32_t ratio_pct_x10(uint32_t part, uint32_t whole)
{
    if (whole == 0U)
    {
        return 0U;
    }
    uint64_t v = (uint64_t)part * 1000ULL;
    return (uint32_t)(v / whole);
}

/**
 * @brief Reports the supervised task health table as JSON.
 * @param pcb Connection to answer.
 */
static void handle_get_task_health(struct tcp_pcb *pcb)
{
#define TASK_HEALTH_MAX_TASKS 16
    static TaskStatus_t tasks[TASK_HEALTH_MAX_TASKS];
    static TaskStatus_t prev[TASK_HEALTH_MAX_TASKS];
    static UBaseType_t prev_count = 0;
    static uint8_t prev_valid = 0;
    static uint32_t prev_total = 0;
    static char body[HTTP_JSON_BODY_MAX], response[HTTP_JSON_RESP_MAX];

    uint32_t total_run_time = 0;
    UBaseType_t count = uxTaskGetSystemState(tasks, TASK_HEALTH_MAX_TASKS, &total_run_time);
    if (count == 0)
    {
        send_response(pcb, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    }

    uint32_t window_delta = prev_valid ? (total_run_time - prev_total) : 0U;

    uint32_t idle_runtime = 0;
    for (UBaseType_t i = 0; i < count; i++)
    {
        if (strncmp(tasks[i].pcTaskName, "IDLE", 4) == 0)
        {
            idle_runtime = tasks[i].ulRunTimeCounter;
            break;
        }
    }

    uint32_t idle_x10 = ratio_pct_x10(idle_runtime, total_run_time);
    uint32_t busy_x10 = (idle_x10 >= 1000U) ? 0U : (1000U - idle_x10);

    int n = snprintf(body, sizeof(body),
                     "{\"runtime_available\":true,\"counter_hz\":%lu,\"stack_unit_bytes\":%u,"
                     "\"total_run_ms\":%lu,\"window_ms\":%lu,"
                     "\"total_cpu_pct\":%lu.%01lu,\"idle_cpu_pct\":%lu.%01lu,\"tasks\":[",
                     (unsigned long)RUNTIME_STATS_COUNTER_HZ,
                     (unsigned int)sizeof(StackType_t),
                     (unsigned long)(total_run_time / (RUNTIME_STATS_COUNTER_HZ / 1000U)),
                     (unsigned long)(window_delta / (RUNTIME_STATS_COUNTER_HZ / 1000U)),
                     (unsigned long)(busy_x10 / 10U), (unsigned long)(busy_x10 % 10U),
                     (unsigned long)(idle_x10 / 10U), (unsigned long)(idle_x10 % 10U));
    if (n <= 0 || n >= (int)sizeof(body))
    {
        return;
    }

    for (UBaseType_t i = 0; i < count && n > 0 && n < (int)sizeof(body); i++)
    {
        uint32_t prev_runtime = 0;
        if (prev_valid)
        {
            for (UBaseType_t j = 0; j < prev_count; j++)
            {
                if (prev[j].xHandle == tasks[i].xHandle)
                {
                    prev_runtime = prev[j].ulRunTimeCounter;
                    break;
                }
            }
        }

        uint32_t task_x10 = ratio_pct_x10(tasks[i].ulRunTimeCounter, total_run_time);
        uint32_t win_x10 = prev_valid
                               ? ratio_pct_x10(tasks[i].ulRunTimeCounter - prev_runtime, window_delta)
                               : 0U;

        n += snprintf(body + n, sizeof(body) - (size_t)n,
                      "%s{\"name\":\"%s\",\"state\":%u,\"priority\":%lu,"
                      "\"stack_high_water_words\":%lu,\"stack_high_water_bytes\":%lu,\"runtime\":%lu,"
                      "\"cpu_pct\":%lu.%01lu,\"window_cpu_pct\":%lu.%01lu}",
                      i ? "," : "", tasks[i].pcTaskName, (unsigned int)tasks[i].eCurrentState,
                      (unsigned long)tasks[i].uxCurrentPriority,
                      (unsigned long)tasks[i].usStackHighWaterMark,
                      (unsigned long)(tasks[i].usStackHighWaterMark * sizeof(StackType_t)),
                      (unsigned long)tasks[i].ulRunTimeCounter,
                      (unsigned long)(task_x10 / 10U), (unsigned long)(task_x10 % 10U),
                      (unsigned long)(win_x10 / 10U), (unsigned long)(win_x10 % 10U));
    }

    if (n <= 0 || n >= (int)sizeof(body) - 2)
    {
        return;
    }
    n += snprintf(body + n, sizeof(body) - (size_t)n, "]}");

    memcpy(prev, tasks, sizeof(TaskStatus_t) * (size_t)count);
    prev_count = count;
    prev_total = total_run_time;
    prev_valid = 1;

    int r = snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
                     "Access-Control-Allow-Origin: *\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                     n, body);
    if (r > 0 && r < (int)sizeof(response))
    {
        send_response(pcb, response);
    }
#undef TASK_HEALTH_MAX_TASKS
}

/**
 * @brief Case-insensitive comparison of a query parameter value against a
 *        keyword. The value ends at '&', ' ', '\r' or end of string.
 * @param value Query value taken from the request URL.
 * @param keyword Value to compare against.
 * @return true when both name the same option.
 */
static bool query_value_equals(const char *value, const char *keyword)
{
    size_t i = 0;

    while (keyword[i] != '\0')
    {
        char c = value[i];
        if (c >= 'a' && c <= 'z')
        {
            c = (char)(c - 'a' + 'A');
        }
        if (c != keyword[i])
        {
            return false;
        }
        i++;
    }
    return (value[i] == '\0' || value[i] == '&' || value[i] == ' ' || value[i] == '\r');
}

/**
 * @brief Handles GET /api/alerts and /api/alerts/history requests.
 *
 * Supports newest-first cursor pagination with optional protocol and severity
 * filtering. Filters are applied by the storage owner while it scans the log,
 * so a page always contains up to `limit` matching records and never requires
 * the whole history to be transferred.
 * @param pcb Connection to answer.
 * @param client Client state holding the paging cursor.
 */
static void handle_get_alerts(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (client == NULL || pcb == NULL)
    {
        api_close_conn(pcb, NULL);
        return;
    }

    if (!Security_IsReady())
    {
        send_response(pcb, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        api_close_conn(pcb, client);
        return;
    }

    unsigned long offset = 0, limit = 40;
    unsigned long cursor = 0;
    bool legacy_order = false;
    bool cursor_given = false;
    uint8_t proto_filter = (uint8_t)STORAGE_ALERT_PROTO_ANY;
    uint8_t sev_filter = (uint8_t)STORAGE_ALERT_SEV_ANY;
    bool bad_filter = false;
    const char *query = strchr(client->request, '?');
    if (query != NULL)
    {
        const char *v = strstr(query, "offset=");
        if (v != NULL)
        {
            (void)sscanf(v + 7, "%lu", &offset);
            legacy_order = true;
        }
        v = strstr(query, "cursor=");
        if (v != NULL)
        {
            (void)sscanf(v + 7, "%lu", &cursor);
            cursor_given = true;
        }
        v = strstr(query, "limit=");
        if (v != NULL)
        {
            (void)sscanf(v + 6, "%lu", &limit);
        }

        v = strstr(query, "protocol=");
        if (v != NULL)
        {
            const char *val = v + 9;
            if (query_value_equals(val, "GOOSE"))
            {
                proto_filter = (uint8_t)STORAGE_ALERT_PROTO_GOOSE;
            }
            else if (query_value_equals(val, "SV"))
            {
                proto_filter = (uint8_t)STORAGE_ALERT_PROTO_SV;
            }
            else if (query_value_equals(val, "MMS"))
            {
                proto_filter = (uint8_t)STORAGE_ALERT_PROTO_MMS;
            }
            else if (!query_value_equals(val, "ALL"))
            {
                bad_filter = true;
            }
        }

        v = strstr(query, "severity=");
        if (v != NULL)
        {
            const char *val = v + 9;
            if (query_value_equals(val, "CRITICAL"))
            {
                sev_filter = (uint8_t)STORAGE_ALERT_SEV_CRITICAL;
            }
            else if (query_value_equals(val, "HIGH"))
            {
                sev_filter = (uint8_t)STORAGE_ALERT_SEV_HIGH;
            }
            else if (query_value_equals(val, "WARNING"))
            {
                sev_filter = (uint8_t)STORAGE_ALERT_SEV_WARNING;
            }
            else if (query_value_equals(val, "INFO"))
            {
                sev_filter = (uint8_t)STORAGE_ALERT_SEV_INFO;
            }
            else if (!query_value_equals(val, "ALL"))
            {
                bad_filter = true;
            }
        }
    }
    if (limit == 0 || limit > 40)
    {
        limit = 40;
    }

    if (bad_filter)
    {
        /* Prebuilt so the response never depends on a stack snprintf buffer. */
        static const char bad_filter_resp[] =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 138\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"unsupported filter\",\"allowed_protocol\":[\"GOOSE\",\"SV\",\"MMS\",\"ALL\"],"
            "\"allowed_severity\":[\"CRITICAL\",\"HIGH\",\"WARNING\",\"INFO\",\"ALL\"]}";
        send_response(pcb, bad_filter_resp);
        api_close_conn(pcb, client);
        return;
    }

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
    char *body_start = raw_buf + 256;

    if (total == 0)
    {
        int body_len = snprintf(body_start, 512,
                                "{\"total\":0,\"total_goose\":0,\"total_sv\":0,\"total_mms\":0,"
                                "\"total_critical\":0,\"total_high\":0,\"total_warning\":0,\"total_info\":0,"
                                "\"alerts\":[],\"count\":0,\"has_more\":false,\"next_cursor\":null}");

        char hdr[256];
        int hdr_len = snprintf(hdr, sizeof(hdr),
                               "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/json\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Content-Length: %d\r\n"
                               "Connection: close\r\n\r\n",
                               body_len);

        char *full_resp = body_start - hdr_len;
        memcpy(full_resp, hdr, hdr_len);

        client->resp_buf = full_resp;
        client->resp_len = hdr_len + body_len;
        client->resp_sent = 0;
        client->alert_buf_idx = buf_idx;
        client->alerts_active = 1;

        stream_alerts_response(pcb, client);
        return;
    }

    int body_offset = snprintf(body_start, 512,
                               "{\"total\":%lu,\"total_goose\":%lu,\"total_sv\":%lu,\"total_mms\":%lu,"
                               "\"total_critical\":%lu,\"total_high\":%lu,\"total_warning\":%lu,\"total_info\":%lu,"
                               "\"alerts\":[",
                               (unsigned long)total,
                               (unsigned long)goose, (unsigned long)sv, (unsigned long)mms,
                               (unsigned long)crit, (unsigned long)high, (unsigned long)warn, (unsigned long)info);
    if (body_offset <= 0 || body_offset >= 512)
    {
        release_alert_resp_buffer(buf_idx);
        send_response(pcb, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        api_close_conn(pcb, client);
        return;
    }

    StorageRequest_t *req = StorageService_Acquire();
    if (req == NULL)
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

    req->op = (legacy_order && !cursor_given) ? STORAGE_OP_ALERT_HISTORY : STORAGE_OP_ALERT_PAGE;
    req->offset = (uint32_t)offset;
    req->limit = (uint32_t)limit;
    req->cursor_in = cursor_given ? (uint32_t)cursor : UINT32_MAX;
    req->proto_filter = proto_filter;
    req->sev_filter = sev_filter;
    req->out = body_start;
    req->out_cap = ALERT_RESP_BUF_SIZE - 256U;
    req->out_used = (uint32_t)body_offset;
    req->ctx = client;
    req->ctx_gen = client->gen;
    req->buf_idx = (int16_t)buf_idx;

    client->storage_req = req;
    client->alert_buf_idx = -1;

    if (!StorageService_Submit(req))
    {
        client->storage_req = NULL;
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
    }
}

/**
 * @brief Handles GET /api/alerts/summary.
 *
 * Returns the alert totals maintained in RAM. No file is opened and no record
 * is transferred, so a dashboard can display the count cheaply.
 * @param pcb Connection to answer.
 */
static void handle_get_alerts_summary(struct tcp_pcb *pcb)
{
    static char body[HTTP_JSON_SMALL_BODY_MAX], response[HTTP_JSON_SMALL_RESP_MAX];

    uint32_t total = Security_GetAlertCount();
    uint32_t tot = 0, goose = 0, sv = 0, mms = 0;
    uint32_t crit = 0, high = 0, warn = 0, info = 0;
    Security_GetGlobalStats(&tot, &goose, &sv, &mms);
    Security_GetGlobalSevStats(&crit, &high, &warn, &info);

    Security_Stats_t health;
    Security_GetStats(&health);

    int n = snprintf(body, sizeof(body),
                     "{\"total\":%lu,\"total_goose\":%lu,\"total_sv\":%lu,\"total_mms\":%lu,"
                     "\"total_critical\":%lu,\"total_high\":%lu,\"total_warning\":%lu,\"total_info\":%lu,"
                     "\"pending\":%lu,\"ready\":%s}",
                     (unsigned long)total,
                     (unsigned long)goose, (unsigned long)sv, (unsigned long)mms,
                     (unsigned long)crit, (unsigned long)high, (unsigned long)warn, (unsigned long)info,
                     (unsigned long)health.slots_in_use,
                     Security_IsReady() ? "true" : "false");
    if (n <= 0 || n >= (int)sizeof(body))
    {
        return;
    }

    int r = snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
                     "Access-Control-Allow-Origin: *\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                     n, body);
    if (r > 0 && r < (int)sizeof(response))
    {
        send_response(pcb, response);
    }
}

/**
 * @brief Handles DELETE /api/alerts and POST /api/alerts/clear requests.
 *        The alert log is truncated by the storage owner, not the TCP/IP thread.
 * @param pcb Connection to answer.
 * @param client Client state owning the request.
 */
static void handle_clear_alerts(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    StorageRequest_t *req = StorageService_Acquire();
    if (req == NULL)
    {
        const char *error =
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 24\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"clear failed\"}";
        send_response(pcb, error);
        api_close_conn(pcb, client);
        return;
    }

    req->op = STORAGE_OP_ALERT_CLEAR;
    req->ctx = client;
    req->ctx_gen = client->gen;
    req->buf_idx = -1;

    client->storage_req = req;

    if (!StorageService_Submit(req))
    {
        client->storage_req = NULL;
        const char *error =
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: 24\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"clear failed\"}";
        send_response(pcb, error);
        api_close_conn(pcb, client);
    }
}

/**
 * @brief Sends a JSON error response with a computed Content-Length.
 * @param pcb Connection to answer.
 * @param status HTTP status line text.
 * @param json JSON body to send.
 */
static void send_json_error(struct tcp_pcb *pcb, const char *status, const char *json)
{
    char buf[192];
    int n = snprintf(buf, sizeof(buf),
                     "HTTP/1.1 %s\r\n"
                     "Content-Type: application/json\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Content-Length: %u\r\n"
                     "Connection: close\r\n\r\n%s",
                     status, (unsigned)strlen(json), json);
    if (n > 0 && n < (int)sizeof(buf))
    {
        send_response(pcb, buf);
    }
}

/**
 * @brief Runs on the TCP/IP thread when the storage owner finishes a request.
 *        Validates that the client is still the one that submitted the request.
 * @param ctx Context passed to the deferred call.
 */
static void do_storage_complete(void *ctx)
{
    StorageRequest_t *req = (StorageRequest_t *)ctx;
    if (req == NULL)
    {
        return;
    }

    HTTP_API_Client_t *client = (HTTP_API_Client_t *)req->ctx;
    int buf_idx = req->buf_idx;

    if (client == NULL || !client->in_use || client->gen != req->ctx_gen || client->pcb == NULL)
    {
        if (buf_idx >= 0)
        {
            release_alert_resp_buffer(buf_idx);
        }
        StorageService_Release(req);
        return;
    }

    struct tcp_pcb *pcb = client->pcb;
    client->storage_req = NULL;

    switch ((StorageOp_t)req->op)
    {
    case STORAGE_OP_ALERT_HISTORY:
    case STORAGE_OP_ALERT_PAGE:
    {
        if (buf_idx < 0)
        {
            break;
        }
        if (!req->ok)
        {
            release_alert_resp_buffer(buf_idx);
            SysLog_Print(SYSLOG_LEVEL_WARN, "HTTP", "Alert history read failed");
            send_json_error(pcb, "503 Service Unavailable", "{\"error\":\"history unavailable\"}");
            api_close_conn(pcb, client);
            break;
        }

        char *body_start = s_alert_resp_buffers[buf_idx] + 256;
        int body_offset = (int)req->out_used;
        int tail;
        if (req->op == STORAGE_OP_ALERT_PAGE)
        {
            if (req->has_more)
            {
                tail = snprintf(&body_start[body_offset], 96,
                                "],\"count\":%lu,\"order\":\"newest\",\"has_more\":true,"
                                "\"next_cursor\":%lu}",
                                (unsigned long)req->records_read,
                                (unsigned long)req->cursor_out);
            }
            else
            {
                tail = snprintf(&body_start[body_offset], 96,
                                "],\"count\":%lu,\"order\":\"newest\",\"has_more\":false,"
                                "\"next_cursor\":null}",
                                (unsigned long)req->records_read);
            }
        }
        else
        {
            tail = snprintf(&body_start[body_offset], 96,
                            "],\"count\":%lu,\"order\":\"oldest\",\"has_more\":false,"
                            "\"next_cursor\":null}",
                            (unsigned long)req->records_read);
        }
        if (tail <= 0 || tail >= 96)
        {
            release_alert_resp_buffer(buf_idx);
            send_json_error(pcb, "500 Internal Server Error", "{\"error\":\"internal\"}");
            api_close_conn(pcb, client);
            break;
        }
        body_offset += tail;

        char hdr[256];
        int hdr_len = snprintf(hdr, sizeof(hdr),
                               "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/json\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Content-Length: %d\r\n"
                               "Connection: close\r\n\r\n",
                               body_offset);
        if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr))
        {
            release_alert_resp_buffer(buf_idx);
            api_close_conn(pcb, client);
            break;
        }

        char *full_resp = body_start - hdr_len;
        memcpy(full_resp, hdr, hdr_len);

        client->resp_buf = full_resp;
        client->resp_len = (uint32_t)(hdr_len + body_offset);
        client->resp_sent = 0;
        client->alert_buf_idx = (int8_t)buf_idx;
        client->alerts_active = 1;
        req->buf_idx = -1; /* ownership returned to the client */

        tcp_nagle_disable(pcb);
        stream_alerts_response(pcb, client);
        break;
    }

    case STORAGE_OP_ALERT_CLEAR:
        if (req->ok)
        {
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
        else
        {
            send_json_error(pcb, "503 Service Unavailable", "{\"error\":\"clear failed\"}");
        }
        api_close_conn(pcb, client);
        break;

    case STORAGE_OP_CONFIG_SAVE:
    {
        SystemConfig_t cfg;
        SystemConfig_Get(&cfg);

        int body_len = SystemConfig_ToJson(&cfg, s_config_json_body, sizeof(s_config_json_body));
        if (body_len < 0)
        {
            body_len = 0;
        }

        int resp_len = snprintf(s_config_response, sizeof(s_config_response),
                                "HTTP/1.1 %s\r\n"
                                "Content-Type: application/json\r\n"
                                "Access-Control-Allow-Origin: *\r\n"
                                "Content-Length: %d\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s",
                                req->ok ? "200 OK" : "500 Internal Server Error",
                                body_len, s_config_json_body);

        if (resp_len > 0 && resp_len < (int)sizeof(s_config_response))
        {
            send_response(pcb, s_config_response);
        }
        api_close_conn(pcb, client);
        break;
    }

    default:
        /* Never leak a reserved response buffer on an unknown operation. */
        if (buf_idx >= 0)
        {
            release_alert_resp_buffer(buf_idx);
        }
        api_close_conn(pcb, client);
        break;
    }

    StorageService_Release(req);
}

/**
 * @brief Storage-owner completion hook. Runs on the storage task; must not block
 *        on filesystem or TCP/IP resources.
 * @param req Completed storage request.
 */
static void storage_complete_hook(StorageRequest_t *req)
{
    for (int attempt = 0; attempt < 3; attempt++)
    {
        if (tcpip_try_callback(do_storage_complete, req) == ERR_OK)
        {
            return;
        }
        osDelay(5);
    }

    s_storage_callback_failures++;
    if (req->buf_idx >= 0)
    {
        release_alert_resp_buffer(req->buf_idx);
        req->buf_idx = -1;
    }
    StorageService_Release(req);
}

/**
 * @brief Forwards incoming SCD payload chunks to storage with bounded flow control.
 * @param pcb Connection the data arrived on.
 * @param client Client state owning the upload.
 * @param data Body bytes received so far.
 * @param len Number of bytes in this fragment.
 * @return true when the upload may continue.
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
 * @param pcb Connection to answer.
 * @param client Client state owning the request.
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
 * @param pcb Connection being closed.
 * @param client Client state to release.
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
 * @param pcb Connection being aborted.
 * @param client Client state to release.
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
 * @param arg Callback argument (unused).
 * @param err Error reported by lwIP.
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
 * @param arg Callback argument (unused).
 * @param pcb Connection that received data.
 * @param p Received packet buffer, NULL when the peer closed the connection.
 * @param err Accumulated lwIP error for the connection.
 * @return ERR_OK when the data was consumed, or an abort code.
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

    if (client->storage_req != NULL)
    {
        tcp_recved(pcb, p->tot_len);
        pbuf_free(p);
        return ERR_OK;
    }

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

        if (strncmp(client->request, "GET /api/accounting", 19) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            handle_get_accounting(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "GET /api/task-health", 20) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            handle_get_task_health(pcb);
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

        if (strncmp(client->request, "GET /api/alerts/summary", 23) == 0)
        {
            tcp_recved(pcb, p->tot_len);
            handle_get_alerts_summary(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
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
            handle_clear_alerts(pcb, client);
            pbuf_free(p);
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
            handle_reset_config(pcb, client);
            pbuf_free(p);
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
                handle_post_config(pcb, client->request + body_offset, (uint16_t)client->content_length, client);
                pbuf_free(p);
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
            handle_post_config(pcb, client->request + body_offset, (uint16_t)client->content_length, client);
            client->post_config_active = 0;
            pbuf_free(p);
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
 * @param arg Callback argument (unused).
 * @param newpcb Newly accepted connection.
 * @param err lwIP error for the new connection.
 * @return ERR_OK to keep the connection, or an abort code to refuse it.
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

    StorageService_SetCompleteHook(storage_complete_hook);

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
    SysLog_Print(SYSLOG_LEVEL_INFO, "HTTP", "Listening on port %d (API and dashboard ready)", HTTP_API_PORT);
    SysLog_Print(SYSLOG_LEVEL_INFO, "HTTP", "Server listening on port %d", HTTP_API_PORT);
}

/**
 * @brief Returns 1 if the HTTP server listening PCB is active, 0 otherwise.
 * @return 1 while the listener is active, 0 otherwise.
 */
uint8_t HTTP_API_IsListening(void)
{
    return (api_pcb != NULL && api_pcb->state == LISTEN);
}

/*
 * Human-readable server state for boot/link diagnostics.
 *
 * The listener is created by HTTP_API_Init(), which the storage-owner task runs
 * after lwIP starts. A link-up event can arrive before that, so the diagnostic
 * must distinguish "not initialised yet" from "initialised but not listening"
 * instead of reporting a single "NOT listening" for both.
 */
const char *HTTP_API_StateString(void)
{
    if (HTTP_API_IsListening())
    {
        return "listening:8080";
    }
    if (!s_http_initialized)
    {
        return "starting";
    }
    return "unavailable";
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
 * @param ctx Context passed to the deferred call.
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
                    s_sse_delivered++;
                }
                else if (err == ERR_MEM)
                {
                    s_sse_post_failed++;
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
 * @param json_line NDJSON line to send to the connected SSE clients.
 * @param len Length of json_line.
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
        s_sse_pool_exhausted++;
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

    if (tcpip_try_callback(do_broadcast_alert, msg) != ERR_OK)
    {
        s_sse_post_failed++;
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

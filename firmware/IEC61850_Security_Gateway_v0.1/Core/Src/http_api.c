#include "http_api.h"
#include "scd_storage.h"
#include "scd_config.h"
#include "security.h"
#include "fatfs.h"
#include "ff.h"
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lwip/tcpip.h"

#define HTTP_API_PORT 8080
#define HTTP_API_REQUEST_BUFFER_SIZE 2048
#define MAX_SSE_CLIENTS 4

static struct tcp_pcb *api_pcb = NULL;

typedef struct HTTP_API_Client_s
{
    char request[HTTP_API_REQUEST_BUFFER_SIZE];
    uint16_t header_len;
    uint32_t content_length;
    uint32_t body_received;
    uint8_t header_complete;
    uint8_t post_active;
    uint8_t alerts_active;
    uint8_t is_sse;
    struct tcp_pcb *pcb;
    struct HTTP_API_Client_s *next;
} HTTP_API_Client_t;

static HTTP_API_Client_t *sse_clients = NULL;
static uint8_t sse_client_count = 0;

static void api_close_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client);
static void send_alerts_chunk(struct tcp_pcb *pcb, HTTP_API_Client_t *client);

/**
 * @brief Callback invoked when data has been successfully transmitted.
 * @param arg User supplied argument.
 * @param pcb TCP protocol control block.
 * @param len Number of bytes acknowledged.
 * @return ERR_OK on success.
 */
static err_t api_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)len;
    HTTP_API_Client_t *client = (HTTP_API_Client_t *)arg;
    if (client != NULL && client->alerts_active)
    {
        send_alerts_chunk(pcb, client);
    }
    return ERR_OK;
}

/**
 * @brief Locates the boundary between HTTP headers and body.
 * @param data Pointer to header character buffer.
 * @param len Length of the buffer.
 * @return Index of body start, or -1 if header end is not found.
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
 * @param headers Pointer to the raw HTTP header string.
 * @return Content length in bytes, or 0 if not present.
 */
static uint32_t parse_content_length(const char *headers)
{
    const char *p = strstr(headers, "Content-Length:");
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
 * @param pcb TCP protocol control block.
 * @param response Null-terminated response string.
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
 * @param pcb TCP protocol control block.
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

static FIL s_alerts_file;
static bool s_alerts_file_open = false;
static char s_alerts_read_buf[256];
static char s_alerts_header[192];

/**
 * @brief Streams SD card alert data chunks to a client over TCP.
 * @param pcb TCP protocol control block.
 * @param client Client state pointer.
 */
static void send_alerts_chunk(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (!s_alerts_file_open)
    {
        if (client != NULL)
        {
            client->alerts_active = 0;
        }
        api_close_conn(pcb, client);
        return;
    }

    u16_t snd_avail = tcp_sndbuf(pcb);
    while (snd_avail >= sizeof(s_alerts_read_buf))
    {
        UINT bytes_read = 0;
        FRESULT r = f_read(&s_alerts_file, s_alerts_read_buf, sizeof(s_alerts_read_buf), &bytes_read);
        if (r != FR_OK || bytes_read == 0)
        {
            f_close(&s_alerts_file);
            s_alerts_file_open = false;
            if (client != NULL)
            {
                client->alerts_active = 0;
            }
            tcp_output(pcb);
            api_close_conn(pcb, client);
            return;
        }

        err_t write_err = tcp_write(pcb, s_alerts_read_buf, (u16_t)bytes_read, TCP_WRITE_FLAG_COPY);
        if (write_err != ERR_OK)
        {
            break;
        }

        snd_avail = tcp_sndbuf(pcb);
    }

    if (snd_avail > 0 && snd_avail < sizeof(s_alerts_read_buf))
    {
        UINT bytes_read = 0;
        FRESULT r = f_read(&s_alerts_file, s_alerts_read_buf, (UINT)snd_avail, &bytes_read);
        if (r == FR_OK && bytes_read > 0)
        {
            tcp_write(pcb, s_alerts_read_buf, (u16_t)bytes_read, TCP_WRITE_FLAG_COPY);
        }
        else
        {
            f_close(&s_alerts_file);
            s_alerts_file_open = false;
            if (client != NULL)
            {
                client->alerts_active = 0;
            }
            tcp_output(pcb);
            api_close_conn(pcb, client);
            return;
        }
    }

    tcp_output(pcb);
}

/**
 * @brief Handles GET /api/alerts requests and returns recorded security alerts from SD card.
 * @param pcb TCP protocol control block.
 * @param client Client state pointer.
 */
static void handle_get_alerts(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (s_alerts_file_open)
    {
        f_close(&s_alerts_file);
        s_alerts_file_open = false;
    }

    FRESULT res = f_open(&s_alerts_file, SECURITY_ALERTS_FILE, FA_READ);
    if (res != FR_OK)
    {
        const char *json_body = "[]";
        int json_len = (int)strlen(json_body);
        int resp_len = snprintf(s_alerts_header, sizeof(s_alerts_header),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Access-Control-Allow-Origin: *\r\n"
                                "Content-Length: %d\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s",
                                json_len, json_body);
        if (resp_len > 0)
        {
            send_response(pcb, s_alerts_header);
        }
        api_close_conn(pcb, client);
        return;
    }

    FSIZE_t file_size = f_size(&s_alerts_file);
    if (file_size == 0)
    {
        f_close(&s_alerts_file);
        const char *json_body = "[]";
        int json_len = (int)strlen(json_body);
        int resp_len = snprintf(s_alerts_header, sizeof(s_alerts_header),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Access-Control-Allow-Origin: *\r\n"
                                "Content-Length: %d\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s",
                                json_len, json_body);
        if (resp_len > 0)
        {
            send_response(pcb, s_alerts_header);
        }
        api_close_conn(pcb, client);
        return;
    }

    s_alerts_file_open = true;
    if (client != NULL)
    {
        client->alerts_active = 1;
    }

    int header_len = snprintf(s_alerts_header, sizeof(s_alerts_header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: application/json\r\n"
                              "Access-Control-Allow-Origin: *\r\n"
                              "Content-Length: %lu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              (unsigned long)file_size);
    if (header_len > 0)
    {
        tcp_write(pcb, s_alerts_header, (u16_t)header_len, TCP_WRITE_FLAG_COPY);
    }

    send_alerts_chunk(pcb, client);
}

/**
 * @brief Handles DELETE /api/alerts and POST /api/alerts/clear requests.
 * @param pcb TCP protocol control block.
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
 * @brief Forwards incoming SCD payload chunks to the storage queue.
 * @param client Pointer to the active client connection state.
 * @param data Pointer to chunk data buffer.
 * @param len Length of chunk data in bytes.
 */
static void process_scd_data(HTTP_API_Client_t *client, const uint8_t *data, uint16_t len)
{
    if (!client->post_active || len == 0)
    {
        return;
    }

    uint32_t remaining = client->content_length - client->body_received;
    if (remaining == 0)
    {
        return;
    }

    if ((uint32_t)len > remaining)
    {
        len = (uint16_t)remaining;
    }

    SCD_Storage_Enqueue(data, len);
    client->body_received += len;
}

/**
 * @brief Finalizes an SCD upload POST request and returns success response.
 * @param pcb TCP protocol control block.
 * @param client Pointer to the active client connection state.
 */
static void finish_post(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    if (!client->post_active)
    {
        return;
    }

    client->post_active = 0;
    SCD_Storage_End();

    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: 15\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"ok\"}";

    printf("[HTTP] POST complete (Upload size: %lu)\n", client->body_received);
    send_response(pcb, response);
    api_close_conn(pcb, client);
}

/**
 * @brief Removes an SSE client from the active broadcast list.
 * @param client Pointer to the client connection to remove.
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
                *curr = client->next;
                sse_client_count--;
                break;
            }
            curr = &((*curr)->next);
        }
        client->is_sse = 0;
    }
}

/**
 * @brief Closes a TCP connection and frees associated client resources.
 * @param pcb TCP protocol control block.
 * @param client Client state pointer to free.
 */
static void api_close_conn(struct tcp_pcb *pcb, HTTP_API_Client_t *client)
{
    remove_sse_client(client);

    if (s_alerts_file_open && client != NULL && client->alerts_active)
    {
        f_close(&s_alerts_file);
        s_alerts_file_open = false;
        client->alerts_active = 0;
    }

    if (client != NULL)
    {
        free(client);
    }
    tcp_arg(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    err_t close_err = tcp_close(pcb);
    if (close_err != ERR_OK)
    {
        tcp_abort(pcb);
    }
}

/**
 * @brief TCP error callback invoked on connection errors.
 * @param arg Pointer to client connection state.
 * @param err Error code.
 */
static void api_err(void *arg, err_t err)
{
    HTTP_API_Client_t *client = (HTTP_API_Client_t *)arg;
    printf("[HTTP] Connection error: %d\n", err);
    if (s_alerts_file_open)
    {
        f_close(&s_alerts_file);
        s_alerts_file_open = false;
    }

    remove_sse_client(client);

    if (client != NULL)
    {
        free(client);
    }
}

/**
 * @brief TCP receive callback handling incoming HTTP requests.
 * @param arg Pointer to client connection state.
 * @param pcb TCP protocol control block.
 * @param p Incoming packet buffer.
 * @param err TCP error status.
 * @return ERR_OK on success or error code.
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
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return err;
    }

    tcp_recved(pcb, p->tot_len);

    if (client == NULL)
    {
        client = (HTTP_API_Client_t *)malloc(sizeof(HTTP_API_Client_t));
        if (client == NULL)
        {
            pbuf_free(p);
            tcp_abort(pcb);
            return ERR_ABRT;
        }

        memset(client, 0, sizeof(HTTP_API_Client_t));
        client->pcb = pcb;
        tcp_arg(pcb, client);
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
            pbuf_free(p);
            return ERR_OK;
        }

        client->header_complete = 1;

        if (strncmp(client->request, "OPTIONS /api/scd", 16) == 0 ||
            strncmp(client->request, "OPTIONS /api/alerts", 19) == 0)
        {
            const char *response =
                "HTTP/1.1 204 No Content\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, Accept\r\n"
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
            printf("[HTTP] Method/Path: GET /api/scd\n");
            handle_get_scd(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "GET /api/alerts/history", 23) == 0)
        {
            printf("[HTTP] Method/Path: GET /api/alerts/history\n");
            handle_get_alerts(pcb, client);
            pbuf_free(p);
            return ERR_OK;
        }

        if (strncmp(client->request, "GET /api/alerts", 15) == 0)
        {
            printf("[HTTP] Method/Path: GET /api/alerts (SSE)\n");
            if (sse_client_count >= MAX_SSE_CLIENTS)
            {
                const char *resp = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n";
                send_response(pcb, resp);
                pbuf_free(p);
                api_close_conn(pcb, client);
                return ERR_OK;
            }

            client->is_sse = 1;
            client->next = sse_clients;
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

        if (strncmp(client->request, "DELETE /api/alerts", 18) == 0 ||
            strncmp(client->request, "POST /api/alerts/clear", 22) == 0)
        {
            printf("[HTTP] Method/Path: DELETE /api/alerts\n");
            handle_clear_alerts(pcb);
            pbuf_free(p);
            api_close_conn(pcb, client);
            return ERR_OK;
        }

        if (strncmp(client->request, "POST /api/scd", 13) == 0)
        {
            client->content_length = parse_content_length(client->request);
            client->body_received = 0;
            client->post_active = 1;

            printf("[HTTP] Method/Path: POST /api/scd (Length: %lu)\n", client->content_length);

            SCD_Storage_Start();

            uint16_t body_offset = (uint16_t)header_end;
            if (client->header_len > body_offset)
            {
                uint16_t body_len = client->header_len - body_offset;
                process_scd_data(client, (const uint8_t *)client->request + body_offset, body_len);
            }

            if (client->body_received >= client->content_length)
            {
                finish_post(pcb, client);
            }

            pbuf_free(p);
            return ERR_OK;
        }

        const char *response =
            "HTTP/1.1 404 Not Found\r\n"
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
        uint16_t len = p->tot_len;
        static uint8_t temp[SCD_CHUNK_SIZE];
        uint16_t processed = 0;

        while (processed < len)
        {
            uint16_t copy_len = len - processed;
            if (copy_len > sizeof(temp))
            {
                copy_len = sizeof(temp);
            }

            pbuf_copy_partial(p, temp, copy_len, processed);
            process_scd_data(client, temp, copy_len);
            processed += copy_len;
        }

        if (client->body_received >= client->content_length)
        {
            finish_post(pcb, client);
        }
    }

    pbuf_free(p);
    return ERR_OK;
}

/**
 * @brief TCP accept callback for incoming client connections on the API port.
 * @param arg User supplied argument.
 * @param newpcb New TCP protocol control block for the connected client.
 * @param err TCP connection error status.
 * @return ERR_OK on success or error code.
 */
static err_t api_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;

    if (err != ERR_OK)
    {
        return err;
    }

    printf("[HTTP] New connection accepted\n");
    tcp_arg(newpcb, NULL);
    tcp_recv(newpcb, api_recv);
    tcp_sent(newpcb, api_sent);
    tcp_err(newpcb, api_err);

    return ERR_OK;
}

/**
 * @brief Initializes and starts the HTTP REST API server on port 8080.
 */
void HTTP_API_Init(void)
{
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
        printf("[HTTP] Failed to listen on port %d\n", HTTP_API_PORT);
        return;
    }

    tcp_accept(api_pcb, api_accept);
    printf("[HTTP] Server listening on port %d\n", HTTP_API_PORT);
}

typedef struct
{
    char data[512];
    uint16_t len;
} SSE_Message_t;

/**
 * @brief Broadcasts an SSE alert payload to all connected SSE clients.
 * @param ctx Pointer to an SSE_Message_t heap-allocated message (freed on completion).
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
            if (curr->is_sse && curr->pcb != NULL)
            {
                err_t err = tcp_write(curr->pcb, sse_payload, (u16_t)sse_len, TCP_WRITE_FLAG_COPY);
                if (err == ERR_OK)
                {
                    tcp_output(curr->pcb);
                }
            }
            curr = curr->next;
        }
    }

    free(msg);
}

/**
 * @brief Enqueues an alert JSON line for broadcast to all connected SSE clients.
 * @param json_line Null-terminated JSON line string.
 * @param len Length of json_line in bytes.
 */
void HTTP_API_BroadcastAlert(const char *json_line, uint16_t len)
{
    if (json_line == NULL || len == 0 || sse_clients == NULL)
    {
        return;
    }

    SSE_Message_t *msg = (SSE_Message_t *)malloc(sizeof(SSE_Message_t));
    if (msg == NULL)
    {
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

    if (tcpip_callback(do_broadcast_alert, msg) != ERR_OK)
    {
        free(msg);
    }
}
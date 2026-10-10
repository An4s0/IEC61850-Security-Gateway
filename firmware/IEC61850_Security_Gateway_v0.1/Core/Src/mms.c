#include "mms.h"
#include "main.h"
#include "system_config.h"
#include "system_logger.h"
#include "cmsis_os.h"
#include <string.h>
#include <stdio.h>

extern osMessageQId MMSQueueHandle;

osPoolDef(MmsPool, MMS_FRAME_POOL_SIZE, Mms_Frame_t);
static osPoolId MmsPoolHandle = NULL;

typedef struct
{
    char src_ip[SCD_MAX_IP_LEN];
    char dst_ip[SCD_MAX_IP_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;
    bool has_tpkt;
    uint16_t tpkt_len;
    bool has_cotp;
    uint8_t cotp_type;
    char src_tsel[16];
    char dst_tsel[16];
    bool is_mms_write;
    bool is_mms_read;
    char mms_service[32];
    uint32_t rx_ms;
} ParsedMms_t;

/**
 * @brief Parses an IPv4/TCP Ethernet frame for TPKT/COTP/MMS payload.
 * @param data Raw Ethernet packet data.
 * @param len Frame length.
 * @param now_ms Arrival timestamp in milliseconds.
 * @param p Output parsed MMS structure.
 * @return true if successfully parsed, false if malformed.
 */
static bool parse_mms_frame(const uint8_t *data, uint16_t len, uint32_t now_ms, ParsedMms_t *p)
{
    if (data == NULL || len < 34 || p == NULL)
    {
        return false;
    }

    memset(p, 0, sizeof(*p));
    p->rx_ms = now_ms;

    uint16_t ip_off = 14;
    uint16_t etype = (uint16_t)((data[12] << 8) | data[13]);

    if (etype == 0x8100)
    {
        if (len < 38)
        {
            return false;
        }
        etype = (uint16_t)((data[16] << 8) | data[17]);
        ip_off = 18;
    }

    if (etype != 0x0800 || len < ip_off + 20)
    {
        return false;
    }

    const uint8_t *ip = &data[ip_off];
    uint8_t ip_ver = (ip[0] >> 4) & 0x0F;
    uint8_t ip_ihl = (ip[0] & 0x0F) * 4;
    if (ip_ver != 4 || ip_ihl < 20 || len < ip_off + ip_ihl + 20)
    {
        return false;
    }

    uint8_t ip_proto = ip[9];
    if (ip_proto != 6)
    {
        return false;
    }

    snprintf(p->src_ip, sizeof(p->src_ip), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
    snprintf(p->dst_ip, sizeof(p->dst_ip), "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);

    const uint8_t *tcp = ip + ip_ihl;
    p->src_port = (uint16_t)((tcp[0] << 8) | tcp[1]);
    p->dst_port = (uint16_t)((tcp[2] << 8) | tcp[3]);
    uint8_t tcp_doff = ((tcp[12] >> 4) & 0x0F) * 4;
    if (tcp_doff < 20 || len < ip_off + ip_ihl + tcp_doff)
    {
        return false;
    }

    p->tcp_flags = tcp[13];
    const uint8_t *payload = tcp + tcp_doff;
    uint16_t payload_len = len - (ip_off + ip_ihl + tcp_doff);

    strncpy(p->src_tsel, "0001", sizeof(p->src_tsel) - 1);
    strncpy(p->dst_tsel, "0001", sizeof(p->dst_tsel) - 1);
    strncpy(p->mms_service, "COTP_CONNECTION", sizeof(p->mms_service) - 1);

    if (payload_len >= 4 && payload[0] == 0x03 && payload[1] == 0x00)
    {
        p->has_tpkt = true;
        p->tpkt_len = (uint16_t)((payload[2] << 8) | payload[3]);

        if (payload_len >= 7)
        {
            p->has_cotp = true;
            uint8_t cotp_li = payload[4];
            p->cotp_type = payload[5];

            if (p->cotp_type == 0xE0)
            {
                strncpy(p->mms_service, "COTP_CR", sizeof(p->mms_service) - 1);
                uint16_t param_idx = 9;
                while (param_idx + 2 <= 4 + 1 + cotp_li && param_idx + 2 <= payload_len)
                {
                    uint8_t pcode = payload[param_idx++];
                    uint8_t plen = payload[param_idx++];
                    if (param_idx + plen > payload_len)
                    {
                        break;
                    }

                    if (pcode == 0xC1)
                    {
                        char hex[16] = {0};
                        for (uint8_t k = 0; k < plen && k < 4; k++)
                        {
                            snprintf(&hex[k * 2], 3, "%02X", payload[param_idx + k]);
                        }
                        strncpy(p->src_tsel, hex, sizeof(p->src_tsel) - 1);
                    }
                    else if (pcode == 0xC2)
                    {
                        char hex[16] = {0};
                        for (uint8_t k = 0; k < plen && k < 4; k++)
                        {
                            snprintf(&hex[k * 2], 3, "%02X", payload[param_idx + k]);
                        }
                        strncpy(p->dst_tsel, hex, sizeof(p->dst_tsel) - 1);
                    }
                    param_idx += plen;
                }
            }
            else if (p->cotp_type == 0xD0)
            {
                strncpy(p->mms_service, "COTP_CC", sizeof(p->mms_service) - 1);
            }
            else if (p->cotp_type == 0xF0)
            {
                strncpy(p->mms_service, "MMS_DATA", sizeof(p->mms_service) - 1);
                const uint8_t *mms_data = payload + 7;
                uint16_t mms_len = (payload_len > 7) ? (payload_len - 7) : 0;

                for (uint16_t m = 0; m < mms_len; m++)
                {
                    if (mms_data[m] == 0x85 || mms_data[m] == 0xA5)
                    {
                        p->is_mms_write = true;
                        strncpy(p->mms_service, "MMS_WRITE_REQUEST", sizeof(p->mms_service) - 1);
                        break;
                    }
                    else if (mms_data[m] == 0x84 || mms_data[m] == 0xA4)
                    {
                        p->is_mms_read = true;
                        strncpy(p->mms_service, "MMS_READ_REQUEST", sizeof(p->mms_service) - 1);
                    }
                    else if (mms_data[m] == 0x86 || mms_data[m] == 0xA6)
                    {
                        strncpy(p->mms_service, "MMS_GET_VAR_ATTR", sizeof(p->mms_service) - 1);
                    }
                    else if (mms_data[m] == 0xA3)
                    {
                        strncpy(p->mms_service, "MMS_INFO_REPORT", sizeof(p->mms_service) - 1);
                    }
                }
            }
        }

        for (uint16_t k = 4; k + 1 < payload_len; k++)
        {
            if (payload[k] == 0x85 || payload[k] == 0xA5)
            {
                p->is_mms_write = true;
                strncpy(p->mms_service, "MMS_WRITE_REQUEST", sizeof(p->mms_service) - 1);
                break;
            }
        }
    }

    return true;
}

static MMS_Event_t s_mms_event;
static char s_mms_target_str[128];
static uint32_t s_last_mms_print_tick = 0;
static uint32_t s_mms_suppressed_prints = 0;

/**
 * @brief Emits an MMS security event and logs anomalies to SD card.
 * @param e Pointer to security event structure.
 */
static void emit_mms_event(const MMS_Event_t *e)
{
    if (e == NULL)
    {
        return;
    }

    if (e->type != MMS_EVENT_ACCEPT)
    {
        SystemConfig_t sys_cfg;
        SystemConfig_Get(&sys_cfg);
        uint32_t interval = sys_cfg.alerts.anomaly_print_interval_ms ? sys_cfg.alerts.anomaly_print_interval_ms : 1000;
        uint32_t now = HAL_GetTick();
        bool print_to_console = (e->type != MMS_EVENT_UNEXPECTED_ENDPOINT &&
                                 e->type != MMS_EVENT_UNAUTHORIZED_WRITE &&
                                 e->type != MMS_EVENT_UNKNOWN_DESTINATION);
        if (print_to_console)
        {
            if ((now - s_last_mms_print_tick) >= interval)
            {
                if (s_mms_suppressed_prints > 0)
                {
                    SysLog_Print(SYSLOG_LEVEL_DEBUG, "IDS", "MMS: %lu anomaly events suppressed in last %lu ms",
                                 (unsigned long)s_mms_suppressed_prints, (unsigned long)(now - s_last_mms_print_tick));
                    s_mms_suppressed_prints = 0;
                }
                s_last_mms_print_tick = now;

                if (e->severity >= SEC_SEV_HIGH)
                {
                    printf("[IDS] %s | %s | %s -> %s:%u\r\n",
                           Mms_EventToString(e->type),
                           Security_SeverityToString(e->severity),
                           e->src_ip, e->dst_ip, (unsigned int)e->dst_port);
                }
            }
            else
            {
                s_mms_suppressed_prints++;
            }
        }

        s_mms_target_str[0] = '\0';
        if (e->ied[0] != '\0')
        {
            if (e->ap[0] != '\0')
            {
                snprintf(s_mms_target_str, sizeof(s_mms_target_str), "%s/%s", e->ied, e->ap);
            }
            else
            {
                snprintf(s_mms_target_str, sizeof(s_mms_target_str), "%s", e->ied);
            }
        }
        else
        {
            snprintf(s_mms_target_str, sizeof(s_mms_target_str), "%s:%u", e->dst_ip, (unsigned int)e->dst_port);
        }

        Security_AlertLog_t alert = {
            .timestamp_ms = e->timestamp_ms ? e->timestamp_ms : now,
            .frame_timestamp_ms = e->frame_timestamp_ms,
            .protocol = SEC_PROTO_MMS,
            .severity = e->severity,
            .event_type = Mms_EventToString(e->type),
            .src_mac = NULL,
            .dst_mac = NULL,
            .src_ip = e->src_ip,
            .dst_ip = e->dst_ip,
            .target = s_mms_target_str[0] ? s_mms_target_str : NULL,
            .app_id = e->dst_port,
            .vlan_id = 0,
            .conf_rev = 1,
            .st_num = 0,
            .sq_num = 0,
            .details = e->details,
            .recommendation = NULL};

        Security_LogAlertToSD(&alert);
    }
    else
    {
        uint32_t now = HAL_GetTick();
        s_mms_target_str[0] = '\0';
        if (e->ied[0] != '\0')
        {
            if (e->ap[0] != '\0')
            {
                snprintf(s_mms_target_str, sizeof(s_mms_target_str), "%s/%s", e->ied, e->ap);
            }
            else
            {
                snprintf(s_mms_target_str, sizeof(s_mms_target_str), "%s", e->ied);
            }
        }
        else
        {
            snprintf(s_mms_target_str, sizeof(s_mms_target_str), "%s:%u", e->dst_ip, (unsigned int)e->dst_port);
        }

        Security_AlertLog_t alert = {
            .timestamp_ms = e->timestamp_ms ? e->timestamp_ms : now,
            .frame_timestamp_ms = e->frame_timestamp_ms,
            .protocol = SEC_PROTO_MMS,
            .severity = SEC_SEV_INFO,
            .event_type = Mms_EventToString(e->type),
            .src_mac = NULL,
            .dst_mac = NULL,
            .src_ip = e->src_ip,
            .dst_ip = e->dst_ip,
            .target = s_mms_target_str[0] ? s_mms_target_str : NULL,
            .app_id = e->dst_port,
            .vlan_id = 0,
            .conf_rev = 1,
            .st_num = 0,
            .sq_num = 0,
            .details = "Normal MMS connection validated against active SCD baseline",
            .recommendation = NULL};

        Security_LogAlertToSD(&alert);
    }
}

/**
 * @brief Populates base fields of an MMS security event.
 * @param e Event structure to populate.
 * @param p Parsed MMS frame.
 * @param m Matched SCD MMS server block (optional).
 * @param ied Matched SCD IED block (optional).
 */
static void fill_mms_event_base(MMS_Event_t *e, const ParsedMms_t *p, const SCD_MMS_t *m, const SCD_IED_t *ied)
{
    memset(e, 0, sizeof(*e));
    e->type = MMS_EVENT_ACCEPT;
    e->severity = SEC_SEV_INFO;
    e->timestamp_ms = p->rx_ms;
    strncpy(e->src_ip, p->src_ip, sizeof(e->src_ip) - 1);
    strncpy(e->dst_ip, p->dst_ip, sizeof(e->dst_ip) - 1);
    e->src_port = p->src_port;
    e->dst_port = p->dst_port;
    strncpy(e->src_tsel, p->src_tsel, sizeof(e->src_tsel) - 1);
    strncpy(e->dst_tsel, p->dst_tsel, sizeof(e->dst_tsel) - 1);
    strncpy(e->service, p->mms_service, sizeof(e->service) - 1);

    if (m != NULL)
    {
        strncpy(e->ied, m->ied, sizeof(e->ied) - 1);
        strncpy(e->ap, m->accessPoint, sizeof(e->ap) - 1);
    }
    else if (ied != NULL)
    {
        strncpy(e->ied, ied->id, sizeof(e->ied) - 1);
        strncpy(e->ap, ied->apName, sizeof(e->ap) - 1);
    }
}

/**
 * @brief Validates an MMS frame against the active SCD configuration.
 * @param frame Pointer to the raw received MMS frame.
 * @return Detection result event type.
 */
MMS_EventType_t Mms_IDS_Process(const Mms_Frame_t *frame)
{
    if (frame == NULL || frame->length == 0)
    {
        return MMS_EVENT_NONE;
    }

    uint32_t now_ms = (frame->rx_timestamp_ms > 0) ? frame->rx_timestamp_ms : HAL_GetTick();
    ParsedMms_t p;

    if (!parse_mms_frame(frame->data, frame->length, now_ms, &p))
    {
        memset(&s_mms_event, 0, sizeof(s_mms_event));
        s_mms_event.type = MMS_EVENT_MALFORMED_FRAME;
        s_mms_event.severity = SEC_SEV_HIGH;
        s_mms_event.timestamp_ms = now_ms;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "Malformed IPv4/TCP MMS packet (len=%u)", frame->length);
        emit_mms_event(&s_mms_event);
        return MMS_EVENT_MALFORMED_FRAME;
    }

    SCD_Config_Lock();
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    SCD_ConfigState_t state = SCD_Config_GetState();

    if (cfg == NULL || state != SCD_CONFIG_STATE_READY || !cfg->isValid)
    {
        SCD_Config_Unlock();
        fill_mms_event_base(&s_mms_event, &p, NULL, NULL);
        s_mms_event.type = MMS_EVENT_UNKNOWN_ENDPOINT;
        s_mms_event.severity = SEC_SEV_HIGH;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "No active SCD configuration for MMS");
        emit_mms_event(&s_mms_event);
        return MMS_EVENT_UNKNOWN_ENDPOINT;
    }

    const SCD_MMS_t *mms_server = SCD_Config_FindMMSByIP(p.dst_ip);
    const SCD_IED_t *dst_ied = SCD_Config_FindIEDByIP(p.dst_ip);
    const SCD_IED_t *src_ied = SCD_Config_FindIEDByIP(p.src_ip);
    const SCD_MMS_t *src_mms = SCD_Config_FindMMSByIP(p.src_ip);

    SystemConfig_t sys_cfg;
    SystemConfig_Get(&sys_cfg);
    if (!sys_cfg.mms.inspection_enabled)
    {
        SCD_Config_Unlock();
        return MMS_EVENT_ACCEPT;
    }

    fill_mms_event_base(&s_mms_event, &p, mms_server, dst_ied);
    MMS_EventType_t result = MMS_EVENT_ACCEPT;
    uint16_t expected_port = (sys_cfg.mms.tcp_port > 0) ? sys_cfg.mms.tcp_port : 102;

    if (sys_cfg.mms.baseline_check_enabled && mms_server == NULL && dst_ied == NULL)
    {
        s_mms_event.type = MMS_EVENT_UNKNOWN_DESTINATION;
        s_mms_event.severity = SEC_SEV_HIGH;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "MMS connection to unknown destination IP %s:%u",
                 p.dst_ip, (unsigned int)p.dst_port);
        result = MMS_EVENT_UNKNOWN_DESTINATION;
    }
    else if (sys_cfg.mms.baseline_check_enabled && src_ied == NULL && src_mms == NULL)
    {
        s_mms_event.type = MMS_EVENT_UNKNOWN_SOURCE;
        s_mms_event.severity = SEC_SEV_HIGH;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "MMS connection from unauthorized/unknown source IP %s",
                 p.src_ip);
        result = MMS_EVENT_UNKNOWN_SOURCE;
    }
    else if (sys_cfg.mms.baseline_check_enabled && mms_server == NULL && dst_ied != NULL)
    {
        s_mms_event.type = MMS_EVENT_UNEXPECTED_ENDPOINT;
        s_mms_event.severity = SEC_SEV_HIGH;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "MMS access to non-MMS interface %s (AP=%s - SV Process Bus only)",
                 dst_ied->id, dst_ied->apName);
        result = MMS_EVENT_UNEXPECTED_ENDPOINT;
    }
    else if (p.dst_port != expected_port && p.dst_port != 8080 && p.dst_port != 3782)
    {
        s_mms_event.type = MMS_EVENT_UNAUTHORIZED_PORT;
        s_mms_event.severity = SEC_SEV_HIGH;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "Unauthorized MMS TCP port %u (expected %u)",
                 (unsigned int)p.dst_port, (unsigned int)expected_port);
        result = MMS_EVENT_UNAUTHORIZED_PORT;
    }
    else if (p.has_cotp && (strcmp(p.src_tsel, "0001") != 0 || strcmp(p.dst_tsel, "0001") != 0))
    {
        s_mms_event.type = MMS_EVENT_TSEL_MISMATCH;
        s_mms_event.severity = SEC_SEV_WARNING;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "COTP TSEL mismatch: src=%s dst=%s (expected 0001)",
                 p.src_tsel, p.dst_tsel);
        result = MMS_EVENT_TSEL_MISMATCH;
    }
    else if (p.is_mms_write)
    {
        s_mms_event.type = MMS_EVENT_UNAUTHORIZED_WRITE;
        s_mms_event.severity = SEC_SEV_CRITICAL;
        snprintf(s_mms_event.details, sizeof(s_mms_event.details), "Unauthorized SCADA Control Write from %s to %s",
                 p.src_ip, mms_server ? mms_server->ied : dst_ied->id);
        result = MMS_EVENT_UNAUTHORIZED_WRITE;
    }

    SCD_Config_Unlock();
    emit_mms_event(&s_mms_event);
    return result;
}

/**
 * @brief Initializes the MMS frame memory pool.
 */
void Mms_Init(void)
{
    Security_Init();
    if (MmsPoolHandle == NULL)
    {
        MmsPoolHandle = osPoolCreate(osPool(MmsPool));
    }
}

/**
 * @brief Copies raw packet data into a frame pool element and enqueues it for MMS IDS processing.
 * @param p Pointer to lwIP packet buffer.
 */
void Mms_Enqueue(struct pbuf *p)
{
    if (p == NULL || MmsPoolHandle == NULL || p->tot_len > MMS_MAX_FRAME_SIZE)
    {
        return;
    }

    Mms_Frame_t *frame = (Mms_Frame_t *)osPoolAlloc(MmsPoolHandle);
    if (frame == NULL)
    {
        return;
    }

    frame->rx_timestamp_ms = HAL_GetTick();
    frame->length = pbuf_copy_partial(p, frame->data, p->tot_len, 0);

    if (osMessagePut(MMSQueueHandle, (uint32_t)frame, 0) != osOK)
    {
        osPoolFree(MmsPoolHandle, frame);
    }
}

/**
 * @brief FreeRTOS task function dequeuing and processing incoming MMS frames.
 * @param argument Unused task parameter.
 */
void Mms_Task(void const *argument)
{
    (void)argument;

    for (;;)
    {
        if (MMSQueueHandle == NULL)
        {
            osDelay(10);
            continue;
        }

        osEvent evt = osMessageGet(MMSQueueHandle, osWaitForever);
        if (evt.status == osEventMessage)
        {
            Mms_Frame_t *frame = (Mms_Frame_t *)evt.value.v;
            if (frame != NULL)
            {
                Mms_IDS_Process(frame);
                if (MmsPoolHandle != NULL)
                {
                    osPoolFree(MmsPoolHandle, frame);
                }
            }
        }
        else
        {
            osDelay(1);
        }
    }
}

/**
 * @brief Converts MMS event type to string representation.
 * @param type Event type enum value.
 * @return Constant string description of the event.
 */
const char *Mms_EventToString(MMS_EventType_t type)
{
    switch (type)
    {
    case MMS_EVENT_ACCEPT:
        return "MMS_TRAFFIC_NORMAL";
    case MMS_EVENT_UNKNOWN_ENDPOINT:
        return "MMS_UNKNOWN_ENDPOINT";
    case MMS_EVENT_UNKNOWN_SOURCE:
        return "MMS_UNKNOWN_SOURCE";
    case MMS_EVENT_UNKNOWN_DESTINATION:
        return "MMS_UNKNOWN_DESTINATION";
    case MMS_EVENT_UNEXPECTED_ENDPOINT:
        return "MMS_UNEXPECTED_ENDPOINT";
    case MMS_EVENT_UNAUTHORIZED_PORT:
        return "MMS_UNAUTHORIZED_PORT";
    case MMS_EVENT_UNAUTHORIZED_WRITE:
        return "MMS_UNAUTHORIZED_WRITE";
    case MMS_EVENT_TSEL_MISMATCH:
        return "MMS_TSEL_MISMATCH";
    case MMS_EVENT_CON_ANOMALY:
        return "MMS_CON_ANOMALY";
    case MMS_EVENT_MALFORMED_FRAME:
        return "MMS_MALFORMED_FRAME";
    default:
        return "MMS_EVENT_NONE";
    }
}

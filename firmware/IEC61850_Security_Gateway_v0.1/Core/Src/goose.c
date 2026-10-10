#include "goose.h"
#include "main.h"
#include "system_config.h"
#include "system_logger.h"
#include "cmsis_os.h"
#include <string.h>
#include <stdio.h>

extern osMessageQId GooseQueueHandle;

osPoolDef(GoosePool, GOOSE_FRAME_POOL_SIZE, Goose_Frame_t);
static osPoolId GoosePoolHandle = NULL;

typedef struct
{
    bool initialized;
    uint32_t last_st_num;
    uint32_t last_sq_num;
    uint32_t last_rx_ms;
    uint32_t last_ttl_ms;
} StreamState_t;

static StreamState_t g_streams[SCD_MAX_GOOSE];
static uint32_t g_cfg_version;

typedef struct
{
    uint8_t dst_mac[SCD_MAC_ADDR_LEN];
    uint8_t src_mac[SCD_MAC_ADDR_LEN];
    bool is_vlan_tagged;
    uint16_t vlan_id;
    uint8_t vlan_priority;
    uint16_t app_id;
    uint16_t apdu_length;
    char gocb_ref[SCD_MAX_NAME_LEN * 3];
    char go_id[SCD_MAX_NAME_LEN * 2];
    uint32_t time_allowed_to_live;
    uint64_t frame_timestamp_ms;
    uint32_t st_num;
    uint32_t sq_num;
    uint32_t conf_rev;
    uint32_t rx_ms;
} ParsedGoose_t;

/**
 * @brief Decodes ASN.1 BER length field.
 * @param buf Pointer to buffer.
 * @param max Maximum available bytes.
 * @param len Decoded length output.
 * @param hdr Decoded length field byte count output.
 * @return true on success, false on decode failure.
 */
static bool asn1_decode_length(const uint8_t *buf, size_t max, uint32_t *len, size_t *hdr)
{
    if (buf == NULL || max < 1)
    {
        return false;
    }

    uint8_t b = buf[0];
    if ((b & 0x80) == 0)
    {
        *len = b;
        *hdr = 1;
        return true;
    }

    uint8_t n = b & 0x7F;
    if (n == 0 || n > 4 || max < (size_t)(1 + n))
    {
        return false;
    }

    uint32_t v = 0;
    for (uint8_t i = 0; i < n; i++)
    {
        v = (v << 8) | buf[1 + i];
    }

    *len = v;
    *hdr = 1 + n;
    return true;
}

/**
 * @brief Decodes an ASN.1 integer into a 32-bit unsigned value.
 * @param v Pointer to value bytes.
 * @param n Length in bytes.
 * @return Decoded 32-bit integer.
 */
static uint32_t asn1_uint(const uint8_t *v, uint32_t n)
{
    uint32_t r = 0;
    for (uint32_t i = 0; i < n && i < 4; i++)
    {
        r = (r << 8) | v[i];
    }
    return r;
}

/**
 * @brief Copies and null-terminates an ASN.1 string value.
 * @param v Pointer to string bytes.
 * @param n Length in bytes.
 * @param dst Destination buffer.
 * @param max Size of destination buffer.
 */
static void asn1_str(const uint8_t *v, uint32_t n, char *dst, size_t max)
{
    if (dst == NULL || max == 0)
    {
        return;
    }

    if (v == NULL || n == 0)
    {
        dst[0] = '\0';
        return;
    }

    size_t c = (n < max - 1) ? n : (max - 1);
    memcpy(dst, v, c);
    dst[c] = '\0';
}

/**
 * @brief Parses raw Ethernet frame into a structured GOOSE representation.
 * @param data Raw Ethernet frame bytes.
 * @param len Frame length.
 * @param now_ms Frame arrival timestamp in milliseconds.
 * @param p Parsed GOOSE output structure.
 * @return true on success, false if malformed.
 */
static bool parse_frame(const uint8_t *data, uint16_t len, uint32_t now_ms, ParsedGoose_t *p)
{
    if (data == NULL || len < 14 || p == NULL)
    {
        return false;
    }

    memset(p, 0, sizeof(*p));
    p->rx_ms = now_ms;

    memcpy(p->dst_mac, &data[0], SCD_MAC_ADDR_LEN);
    memcpy(p->src_mac, &data[6], SCD_MAC_ADDR_LEN);
    uint16_t etype = (uint16_t)((data[12] << 8) | data[13]);

    uint16_t apdu_off;
    if (etype == 0x88B8)
    {
        p->is_vlan_tagged = false;
        apdu_off = 14;
    }
    else if (etype == 0x8100)
    {
        if (len < 18)
        {
            return false;
        }

        uint16_t tci = (uint16_t)((data[14] << 8) | data[15]);
        p->is_vlan_tagged = true;
        p->vlan_priority = (uint8_t)((tci >> 13) & 0x07);
        p->vlan_id = (uint16_t)(tci & 0x0FFF);
        if (((data[16] << 8) | data[17]) != 0x88B8)
        {
            return false;
        }
        apdu_off = 18;
    }
    else
    {
        return false;
    }

    if (len < apdu_off + 8)
    {
        return false;
    }

    const uint8_t *apdu = &data[apdu_off];
    p->app_id = (uint16_t)((apdu[0] << 8) | apdu[1]);
    p->apdu_length = (uint16_t)((apdu[2] << 8) | apdu[3]);
    if (p->apdu_length < 8 || p->apdu_length > (len - apdu_off))
    {
        return false;
    }

    const uint8_t *pdu = apdu + 8;
    uint16_t pdu_len = p->apdu_length - 8;
    if (pdu_len < 2 || pdu[0] != 0x61)
    {
        return false;
    }

    uint32_t content_len;
    size_t hdr_bytes;
    if (!asn1_decode_length(&pdu[1], pdu_len - 1, &content_len, &hdr_bytes))
    {
        return false;
    }

    const uint8_t *ptr = pdu + 1 + hdr_bytes;
    const uint8_t *end = ptr + content_len;
    if (end > pdu + pdu_len)
    {
        end = pdu + pdu_len;
    }

    while (ptr + 2 <= end)
    {
        uint8_t tag = *ptr++;
        uint32_t tl;
        size_t lb;
        if (!asn1_decode_length(ptr, (size_t)(end - ptr), &tl, &lb))
        {
            break;
        }
        ptr += lb;
        if (ptr + tl > end)
        {
            break;
        }

        switch (tag)
        {
        case 0x80:
            asn1_str(ptr, tl, p->gocb_ref, sizeof(p->gocb_ref));
            break;
        case 0x81:
            p->time_allowed_to_live = asn1_uint(ptr, tl);
            break;
        case 0x83:
            asn1_str(ptr, tl, p->go_id, sizeof(p->go_id));
            break;
        case 0x84:
            if (tl >= 4)
            {
                uint32_t sec = asn1_uint(ptr, 4);
                uint32_t frac_ms = 0;
                if (tl >= 7)
                {
                    uint32_t frac = (uint32_t)((ptr[4] << 16) | (ptr[5] << 8) | ptr[6]);
                    frac_ms = (uint32_t)((((uint64_t)frac * 1000ULL) + 8388608ULL) / 16777216ULL);
                }
                p->frame_timestamp_ms = ((uint64_t)sec * 1000ULL) + (uint64_t)frac_ms;
            }
            break;
        case 0x85:
            p->st_num = asn1_uint(ptr, tl);
            break;
        case 0x86:
            p->sq_num = asn1_uint(ptr, tl);
            break;
        case 0x88:
            p->conf_rev = asn1_uint(ptr, tl);
            break;
        default:
            break;
        }
        ptr += tl;
    }
    return true;
}

static GOOSE_Event_t s_goose_event;
static char s_goose_target_str[128];
static uint32_t s_last_goose_print_tick = 0;
static uint32_t s_goose_suppressed_prints = 0;

/**
 * @brief Matches a parsed GOOSE frame against active SCD configuration control blocks.
 * @param cfg Pointer to active SCD configuration.
 * @param p Pointer to parsed GOOSE frame.
 * @param idx Output index in active GOOSE array.
 * @return Pointer to matched SCD_GOOSE_t or NULL if no match.
 */
static const SCD_GOOSE_t *find_scd_match(const SCD_Config_t *cfg, const ParsedGoose_t *p, int *idx)
{
    if (p->gocb_ref[0] != '\0')
    {
        for (uint16_t i = 0; i < cfg->numGoose; i++)
        {
            const SCD_GOOSE_t *g = &cfg->goose[i];
            char ref[160];
            const char *ln = g->logicalNode[0] ? g->logicalNode : "LLN0";
            snprintf(ref, sizeof(ref), "%s%s/%s$GO$%s", g->publisherIed, g->logicalDevice, ln, g->controlBlock);
            if (strcmp(p->gocb_ref, ref) == 0)
            {
                *idx = (int)i;
                return g;
            }
            snprintf(ref, sizeof(ref), "%s%s/%s.%s", g->publisherIed, g->logicalDevice, ln, g->controlBlock);
            if (strcmp(p->gocb_ref, ref) == 0)
            {
                *idx = (int)i;
                return g;
            }
            if (g->controlBlock[0] != '\0' && g->publisherIed[0] != '\0' &&
                strstr(p->gocb_ref, g->controlBlock) && strstr(p->gocb_ref, g->publisherIed))
            {
                *idx = (int)i;
                return g;
            }
        }
    }

    if (p->go_id[0] != '\0')
    {
        for (uint16_t i = 0; i < cfg->numGoose; i++)
        {
            const SCD_GOOSE_t *g = &cfg->goose[i];
            if (g->controlBlock[0] != '\0' && g->publisherIed[0] != '\0' &&
                strstr(p->go_id, g->controlBlock) && strstr(p->go_id, g->publisherIed))
            {
                *idx = (int)i;
                return g;
            }
        }
    }

    for (uint16_t i = 0; i < cfg->numGoose; i++)
    {
        if (cfg->goose[i].appId == p->app_id)
        {
            *idx = (int)i;
            return &cfg->goose[i];
        }
    }

    for (uint16_t i = 0; i < cfg->numGoose; i++)
    {
        if (memcmp(cfg->goose[i].mac, p->dst_mac, SCD_MAC_ADDR_LEN) == 0)
        {
            *idx = (int)i;
            return &cfg->goose[i];
        }
    }

    return NULL;
}

/**
 * @brief Emits a security event and logs anomalies to SD card.
 * @param e Pointer to security event structure.
 */
static void emit_event(const GOOSE_Event_t *e)
{
    if (e == NULL)
    {
        return;
    }

    if (e->type != GOOSE_EVENT_ACCEPT)
    {
        SystemConfig_t sys_cfg;
        SystemConfig_Get(&sys_cfg);
        uint32_t now = HAL_GetTick();
        bool print_to_console = (e->type != GOOSE_EVENT_APPID_MISMATCH &&
                                 e->type != GOOSE_EVENT_MAC_MISMATCH &&
                                 e->type != GOOSE_EVENT_VLAN_MISMATCH);
        if (print_to_console)
        {
            if ((now - s_last_goose_print_tick) >= sys_cfg.alerts.anomaly_print_interval_ms)
            {
                if (s_goose_suppressed_prints > 0)
                {
                    SysLog_Print(SYSLOG_LEVEL_DEBUG, "IDS", "GOOSE: %lu anomaly events suppressed in last %lu ms",
                                 (unsigned long)s_goose_suppressed_prints, (unsigned long)(now - s_last_goose_print_tick));
                    s_goose_suppressed_prints = 0;
                }
                s_last_goose_print_tick = now;

                if (e->severity >= SEC_SEV_HIGH)
                {
                    printf("[IDS] %s | %s | %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                           Goose_EventToString(e->type),
                           Security_SeverityToString(e->severity),
                           e->src_mac[0], e->src_mac[1], e->src_mac[2],
                           e->src_mac[3], e->src_mac[4], e->src_mac[5],
                           e->dst_mac[0], e->dst_mac[1], e->dst_mac[2],
                           e->dst_mac[3], e->dst_mac[4], e->dst_mac[5]);
                }
            }
            else
            {
                s_goose_suppressed_prints++;
            }
        }

        s_goose_target_str[0] = '\0';
        if (e->ied[0] != '\0' || e->cb[0] != '\0')
        {
            snprintf(s_goose_target_str, sizeof(s_goose_target_str), "%s/%s", e->ied, e->cb);
        }

        Security_AlertLog_t alert = {
            .timestamp_ms = e->timestamp_ms ? e->timestamp_ms : now,
            .frame_timestamp_ms = e->frame_timestamp_ms,
            .protocol = SEC_PROTO_GOOSE,
            .severity = e->severity,
            .event_type = Goose_EventToString(e->type),
            .src_mac = e->src_mac,
            .dst_mac = e->dst_mac,
            .src_ip = NULL,
            .dst_ip = NULL,
            .target = s_goose_target_str[0] ? s_goose_target_str : NULL,
            .app_id = e->app_id,
            .vlan_id = e->vlan_id,
            .conf_rev = e->conf_rev,
            .st_num = e->st_num,
            .sq_num = e->sq_num,
            .details = e->details,
            .recommendation = NULL};

        Security_LogAlertToSD(&alert);
    }
    else
    {
        SystemConfig_t sys_cfg;
        SystemConfig_Get(&sys_cfg);
        uint32_t now = HAL_GetTick();
        static uint32_t s_last_goose_normal_tick = 0;
        if ((now - s_last_goose_normal_tick) >= sys_cfg.alerts.normal_traffic_log_interval_ms || s_last_goose_normal_tick == 0)
        {
            s_last_goose_normal_tick = now;
            s_goose_target_str[0] = '\0';
            if (e->ied[0] != '\0' || e->cb[0] != '\0')
            {
                snprintf(s_goose_target_str, sizeof(s_goose_target_str), "%s/%s", e->ied, e->cb);
            }

            Security_AlertLog_t alert = {
                .timestamp_ms = e->timestamp_ms ? e->timestamp_ms : now,
                .frame_timestamp_ms = e->frame_timestamp_ms,
                .protocol = SEC_PROTO_GOOSE,
                .severity = SEC_SEV_INFO,
                .event_type = Goose_EventToString(e->type),
                .src_mac = e->src_mac,
                .dst_mac = e->dst_mac,
                .src_ip = NULL,
                .dst_ip = NULL,
                .target = s_goose_target_str[0] ? s_goose_target_str : NULL,
                .app_id = e->app_id,
                .vlan_id = e->vlan_id,
                .conf_rev = e->conf_rev,
                .st_num = e->st_num,
                .sq_num = e->sq_num,
                .details = "Normal GOOSE traffic validated against active SCD baseline",
                .recommendation = NULL};

            Security_LogAlertToSD(&alert);
        }
    }
}

/**
 * @brief Populates base fields of a security event.
 * @param e Event structure to populate.
 * @param p Parsed GOOSE frame.
 * @param g Matched SCD control block.
 */
static void fill_event_base(GOOSE_Event_t *e, const ParsedGoose_t *p, const SCD_GOOSE_t *g)
{
    memset(e, 0, sizeof(*e));
    e->type = GOOSE_EVENT_ACCEPT;
    e->severity = SEC_SEV_INFO;
    e->timestamp_ms = p->rx_ms;
    e->frame_timestamp_ms = p->frame_timestamp_ms;
    memcpy(e->src_mac, p->src_mac, SCD_MAC_ADDR_LEN);
    memcpy(e->dst_mac, p->dst_mac, SCD_MAC_ADDR_LEN);
    e->is_vlan_tagged = p->is_vlan_tagged;
    e->vlan_id = p->vlan_id;
    e->vlan_priority = p->vlan_priority;
    e->app_id = p->app_id;
    e->conf_rev = p->conf_rev;
    e->st_num = p->st_num;
    e->sq_num = p->sq_num;

    if (g != NULL)
    {
        strncpy(e->ied, g->publisherIed, sizeof(e->ied) - 1);
        strncpy(e->cb, g->controlBlock, sizeof(e->cb) - 1);
    }
}

/**
 * @brief Validates a GOOSE frame against active SCD configuration.
 * @param frame Pointer to raw received GOOSE frame.
 * @return Detection result event type.
 */
GOOSE_EventType_t Goose_IDS_Process(const Goose_Frame_t *frame)
{
    if (frame == NULL || frame->length == 0)
    {
        return GOOSE_EVENT_NONE;
    }

    uint32_t now_ms = (frame->rx_timestamp_ms > 0) ? frame->rx_timestamp_ms : HAL_GetTick();
    ParsedGoose_t p;

    if (!parse_frame(frame->data, frame->length, now_ms, &p))
    {
        fill_event_base(&s_goose_event, &p, NULL);
        s_goose_event.type = GOOSE_EVENT_MALFORMED_FRAME;
        s_goose_event.severity = SEC_SEV_HIGH;
        if (frame->length >= 12)
        {
            memcpy(s_goose_event.dst_mac, &frame->data[0], SCD_MAC_ADDR_LEN);
            memcpy(s_goose_event.src_mac, &frame->data[6], SCD_MAC_ADDR_LEN);
        }
        snprintf(s_goose_event.details, sizeof(s_goose_event.details), "Malformed frame (len=%u)", frame->length);
        emit_event(&s_goose_event);
        return GOOSE_EVENT_MALFORMED_FRAME;
    }

    SCD_Config_Lock();
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    SCD_ConfigState_t state = SCD_Config_GetState();

    if (cfg == NULL || state != SCD_CONFIG_STATE_READY || !cfg->isValid)
    {
        SCD_Config_Unlock();
        fill_event_base(&s_goose_event, &p, NULL);
        s_goose_event.type = GOOSE_EVENT_UNKNOWN_CONTROL_BLOCK;
        s_goose_event.severity = SEC_SEV_HIGH;
        snprintf(s_goose_event.details, sizeof(s_goose_event.details), "No active SCD configuration");
        emit_event(&s_goose_event);
        return GOOSE_EVENT_UNKNOWN_CONTROL_BLOCK;
    }

    if (cfg->configVersion != g_cfg_version)
    {
        memset(g_streams, 0, sizeof(g_streams));
        g_cfg_version = cfg->configVersion;
    }

    int idx = -1;
    const SCD_GOOSE_t *g = find_scd_match(cfg, &p, &idx);

    if (g == NULL || idx < 0 || idx >= SCD_MAX_GOOSE)
    {
        SCD_Config_Unlock();
        fill_event_base(&s_goose_event, &p, NULL);
        s_goose_event.type = GOOSE_EVENT_UNKNOWN_CONTROL_BLOCK;
        s_goose_event.severity = SEC_SEV_HIGH;
        snprintf(s_goose_event.details, sizeof(s_goose_event.details), "Unknown CB (ref='%.48s' appid=0x%04X)",
                 p.gocb_ref[0] ? p.gocb_ref : "-", p.app_id);
        emit_event(&s_goose_event);
        return GOOSE_EVENT_UNKNOWN_CONTROL_BLOCK;
    }

    fill_event_base(&s_goose_event, &p, g);
    GOOSE_EventType_t result = GOOSE_EVENT_ACCEPT;

    SystemConfig_t sys_cfg;
    SystemConfig_Get(&sys_cfg);

    bool baseline_mismatch = false;
    if (sys_cfg.goose.baseline_check_enabled)
    {
        if (memcmp(p.dst_mac, g->mac, SCD_MAC_ADDR_LEN) != 0)
        {
            s_goose_event.type = GOOSE_EVENT_MAC_MISMATCH;
            s_goose_event.severity = SEC_SEV_HIGH;
            snprintf(s_goose_event.details, sizeof(s_goose_event.details), "DST MAC %02X:%02X:%02X:%02X:%02X:%02X != %s",
                     p.dst_mac[0], p.dst_mac[1], p.dst_mac[2],
                     p.dst_mac[3], p.dst_mac[4], p.dst_mac[5], g->macStr);
            result = GOOSE_EVENT_MAC_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.app_id != g->appId)
        {
            s_goose_event.type = GOOSE_EVENT_APPID_MISMATCH;
            s_goose_event.severity = SEC_SEV_HIGH;
            snprintf(s_goose_event.details, sizeof(s_goose_event.details), "APPID 0x%04X != 0x%04X", p.app_id, g->appId);
            result = GOOSE_EVENT_APPID_MISMATCH;
            baseline_mismatch = true;
        }
        else if ((g->vlanId > 0 && !p.is_vlan_tagged) ||
                 (g->vlanId > 0 && p.vlan_id != g->vlanId) ||
                 (g->vlanId == 0 && p.is_vlan_tagged))
        {
            s_goose_event.type = GOOSE_EVENT_VLAN_MISMATCH;
            s_goose_event.severity = SEC_SEV_HIGH;
            snprintf(s_goose_event.details, sizeof(s_goose_event.details), "VLAN %u != %u (tagged=%d)",
                     p.vlan_id, g->vlanId, p.is_vlan_tagged);
            result = GOOSE_EVENT_VLAN_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.is_vlan_tagged && g->vlanId > 0 && p.vlan_priority != g->vlanPriority)
        {
            s_goose_event.type = GOOSE_EVENT_VLAN_PRIORITY_MISMATCH;
            s_goose_event.severity = SEC_SEV_WARNING;
            snprintf(s_goose_event.details, sizeof(s_goose_event.details), "VLAN priority %u != %u",
                     p.vlan_priority, g->vlanPriority);
            result = GOOSE_EVENT_VLAN_PRIORITY_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.conf_rev != g->confRev)
        {
            s_goose_event.type = GOOSE_EVENT_CONFREV_MISMATCH;
            s_goose_event.severity = SEC_SEV_HIGH;
            snprintf(s_goose_event.details, sizeof(s_goose_event.details), "confRev %lu != %lu",
                     (unsigned long)p.conf_rev, (unsigned long)g->confRev);
            result = GOOSE_EVENT_CONFREV_MISMATCH;
            baseline_mismatch = true;
        }
    }

    if (!baseline_mismatch)
    {
        StreamState_t *st = &g_streams[idx];
        uint32_t max_time = (g->maxTimeMs > 0) ? g->maxTimeMs : sys_cfg.goose.max_time_fallback_ms;
        uint32_t min_time = (g->minTimeMs > 0) ? g->minTimeMs : sys_cfg.goose.min_time_fallback_ms;
        uint32_t ttl_mult = (sys_cfg.goose.ttl_multiplier > 0) ? sys_cfg.goose.ttl_multiplier : 2;

        if (!st->initialized)
        {
            st->initialized = true;
            st->last_st_num = p.st_num;
            st->last_sq_num = p.sq_num;
            st->last_rx_ms = p.rx_ms;
            st->last_ttl_ms = (p.time_allowed_to_live > 0) ? p.time_allowed_to_live : (max_time * ttl_mult);
            result = GOOSE_EVENT_ACCEPT;
        }
        else
        {
            uint32_t delta = (p.rx_ms >= st->last_rx_ms)
                                 ? (p.rx_ms - st->last_rx_ms)
                                 : (0xFFFFFFFF - st->last_rx_ms + p.rx_ms + 1);

            uint32_t ttl_ms = (st->last_ttl_ms > 0)
                                  ? st->last_ttl_ms
                                  : ((p.time_allowed_to_live > 0)
                                         ? p.time_allowed_to_live
                                         : (max_time * ttl_mult));

            bool is_expired = (delta > ttl_ms);
            bool is_valid_restart = (is_expired && p.sq_num == 0);

            if (p.st_num > st->last_st_num)
            {
                result = GOOSE_EVENT_ACCEPT;
            }
            else if (p.st_num < st->last_st_num)
            {
                if (is_valid_restart || !sys_cfg.goose.state_check_enabled)
                {
                    result = GOOSE_EVENT_ACCEPT;
                }
                else
                {
                    s_goose_event.type = GOOSE_EVENT_STATE_ANOMALY;
                    s_goose_event.severity = SEC_SEV_HIGH;
                    snprintf(s_goose_event.details, sizeof(s_goose_event.details),
                             "stNum rollback %lu -> %lu",
                             (unsigned long)st->last_st_num, (unsigned long)p.st_num);
                    result = GOOSE_EVENT_STATE_ANOMALY;
                }
            }
            else
            {
                if (p.sq_num == st->last_sq_num)
                {
                    if (is_valid_restart || !sys_cfg.goose.state_check_enabled)
                    {
                        result = GOOSE_EVENT_ACCEPT;
                    }
                    else
                    {
                        s_goose_event.type = GOOSE_EVENT_STATE_ANOMALY;
                        s_goose_event.severity = SEC_SEV_WARNING;
                        snprintf(s_goose_event.details, sizeof(s_goose_event.details),
                                 "sqNum duplicate %lu",
                                 (unsigned long)p.sq_num);
                        result = GOOSE_EVENT_STATE_ANOMALY;
                    }
                }
                else if (p.sq_num < st->last_sq_num && !(st->last_sq_num > 0xFFFFFF00 && p.sq_num < 100))
                {
                    if (is_valid_restart || !sys_cfg.goose.state_check_enabled)
                    {
                        result = GOOSE_EVENT_ACCEPT;
                    }
                    else
                    {
                        s_goose_event.type = GOOSE_EVENT_STATE_ANOMALY;
                        s_goose_event.severity = SEC_SEV_WARNING;
                        snprintf(s_goose_event.details, sizeof(s_goose_event.details),
                                 "sqNum rollback %lu -> %lu",
                                 (unsigned long)st->last_sq_num, (unsigned long)p.sq_num);
                        result = GOOSE_EVENT_STATE_ANOMALY;
                    }
                }
                else
                {
                    if (sys_cfg.goose.timing_check_enabled && (delta + 1) < min_time)
                    {
                        s_goose_event.type = GOOSE_EVENT_TIMING_FAST;
                        s_goose_event.severity = SEC_SEV_WARNING;
                        snprintf(s_goose_event.details, sizeof(s_goose_event.details),
                                 "Fast: %lu ms < minTime %lu ms",
                                 (unsigned long)delta, (unsigned long)min_time);
                        result = GOOSE_EVENT_TIMING_FAST;
                    }
                    else if (sys_cfg.goose.timing_check_enabled && is_expired)
                    {
                        s_goose_event.type = GOOSE_EVENT_TIMING_SLOW;
                        s_goose_event.severity = SEC_SEV_WARNING;
                        snprintf(s_goose_event.details, sizeof(s_goose_event.details),
                                 "Slow: %lu ms > TTL %lu ms",
                                 (unsigned long)delta, (unsigned long)ttl_ms);
                        result = GOOSE_EVENT_TIMING_SLOW;
                    }
                    else
                    {
                        result = GOOSE_EVENT_ACCEPT;
                    }
                }
            }

            st->last_st_num = p.st_num;
            st->last_sq_num = p.sq_num;
            st->last_rx_ms = p.rx_ms;
            st->last_ttl_ms = (p.time_allowed_to_live > 0)
                                  ? p.time_allowed_to_live
                                  : (max_time * ttl_mult);
        }
    }

    SCD_Config_Unlock();
    emit_event(&s_goose_event);
    return result;
}

static Goose_Stats_t s_goose_stats = {0};

/**
 * @brief Copies the current GOOSE statistics to the provided structure.
 */
void Goose_GetStats(Goose_Stats_t *stats)
{
    if (stats != NULL)
    {
        *stats = s_goose_stats;
    }
}

/**
 * @brief Initializes the GOOSE frame memory pool and stream tracking state.
 */
void Goose_Init(void)
{
    Security_Init();
    if (GoosePoolHandle == NULL)
    {
        GoosePoolHandle = osPoolCreate(osPool(GoosePool));
    }
    memset(g_streams, 0, sizeof(g_streams));
    g_cfg_version = 0;
}

/**
 * @brief Copies raw packet data into a frame pool element and enqueues it for IDS processing.
 * @param p Pointer to lwIP packet buffer.
 */
void Goose_Enqueue(struct pbuf *p)
{
    if (p == NULL || GoosePoolHandle == NULL || p->tot_len > GOOSE_MAX_FRAME_SIZE)
    {
        return;
    }

    s_goose_stats.frames_received++;

    Goose_Frame_t *frame = (Goose_Frame_t *)osPoolAlloc(GoosePoolHandle);
    if (frame == NULL)
    {
        s_goose_stats.pool_alloc_failures++;
        return;
    }

    frame->rx_timestamp_ms = HAL_GetTick();
    frame->length = pbuf_copy_partial(p, frame->data, p->tot_len, 0);

    if (osMessagePut(GooseQueueHandle, (uint32_t)frame, 0) != osOK)
    {
        s_goose_stats.queue_sends_failed++;
        osPoolFree(GoosePoolHandle, frame);
    }
}

/**
 * @brief FreeRTOS task function dequeuing and processing incoming GOOSE frames.
 * @param argument Unused task parameter.
 */
void Goose_Task(void const *argument)
{
    (void)argument;

    for (;;)
    {
        if (GooseQueueHandle == NULL)
        {
            osDelay(10);
            continue;
        }

        osEvent evt = osMessageGet(GooseQueueHandle, osWaitForever);
        if (evt.status == osEventMessage)
        {
            Goose_Frame_t *frame = (Goose_Frame_t *)evt.value.v;
            if (frame != NULL)
            {
                s_goose_stats.frames_processed++;
                Goose_IDS_Process(frame);
                if (GoosePoolHandle != NULL)
                {
                    osPoolFree(GoosePoolHandle, frame);
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
 * @brief Converts GOOSE event type to string representation.
 * @param type Event type enum value.
 * @return Constant string description of the event.
 */
const char *Goose_EventToString(GOOSE_EventType_t type)
{
    switch (type)
    {
    case GOOSE_EVENT_ACCEPT:
        return "GOOSE_TRAFFIC_NORMAL";
    case GOOSE_EVENT_UNKNOWN_CONTROL_BLOCK:
        return "GOOSE_UNKNOWN_CONTROL_BLOCK";
    case GOOSE_EVENT_MAC_MISMATCH:
        return "GOOSE_MAC_MISMATCH";
    case GOOSE_EVENT_APPID_MISMATCH:
        return "GOOSE_APPID_MISMATCH";
    case GOOSE_EVENT_VLAN_MISMATCH:
        return "GOOSE_VLAN_MISMATCH";
    case GOOSE_EVENT_VLAN_PRIORITY_MISMATCH:
        return "GOOSE_VLAN_PRIORITY_MISMATCH";
    case GOOSE_EVENT_CONFREV_MISMATCH:
        return "GOOSE_CONFREV_MISMATCH";
    case GOOSE_EVENT_TIMING_FAST:
        return "GOOSE_TIMING_FAST";
    case GOOSE_EVENT_TIMING_SLOW:
        return "GOOSE_TIMING_SLOW";
    case GOOSE_EVENT_STATE_ANOMALY:
        return "GOOSE_STATE_ANOMALY";
    case GOOSE_EVENT_MALFORMED_FRAME:
        return "GOOSE_MALFORMED_FRAME";
    default:
        return "GOOSE_EVENT_NONE";
    }
}
#include "sv.h"
#include "main.h"
#include "system_config.h"
#include "system_logger.h"
#include "cmsis_os.h"
#include <string.h>
#include <stdio.h>

extern osMessageQId SVQueueHandle;

osPoolDef(SvPool, SV_FRAME_POOL_SIZE, Sv_Frame_t);
static osPoolId SvPoolHandle = NULL;

typedef struct
{
    bool initialized;
    uint32_t last_smp_cnt;
    uint32_t last_rx_ms;
} SvStreamState_t;

static SvStreamState_t g_sv_streams[SCD_MAX_SV];
static uint32_t g_sv_cfg_version = 0;

typedef struct
{
    uint8_t dst_mac[SCD_MAC_ADDR_LEN];
    uint8_t src_mac[SCD_MAC_ADDR_LEN];
    bool is_vlan_tagged;
    uint16_t vlan_id;
    uint8_t vlan_priority;
    uint16_t app_id;
    uint16_t apdu_length;
    uint16_t no_asdu;
    char sv_id[SCD_MAX_SVID_LEN];
    uint32_t smp_cnt;
    uint32_t conf_rev;
    uint64_t frame_timestamp_ms;
    uint32_t smp_synch;
    uint32_t smp_rate;
    bool has_smp_rate;
    uint32_t rx_ms;
} ParsedSv_t;

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
 * @brief Parses raw Ethernet frame into a structured Sampled Values representation.
 * @param data Raw Ethernet frame bytes.
 * @param len Frame length.
 * @param now_ms Frame arrival timestamp in milliseconds.
 * @param p Parsed SV output structure.
 * @return true on success, false if malformed.
 */
static bool parse_sv_frame(const uint8_t *data, uint16_t len, uint32_t now_ms, ParsedSv_t *p)
{
    if (data == NULL || len < 14 || p == NULL)
    {
        return false;
    }

    memset(p, 0, sizeof(*p));
    p->rx_ms = now_ms;
    p->no_asdu = 1;

    memcpy(p->dst_mac, &data[0], SCD_MAC_ADDR_LEN);
    memcpy(p->src_mac, &data[6], SCD_MAC_ADDR_LEN);
    uint16_t etype = (uint16_t)((data[12] << 8) | data[13]);

    uint16_t apdu_off;
    if (etype == 0x88BA)
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
        if (((data[16] << 8) | data[17]) != 0x88BA)
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
    if (pdu_len < 2 || pdu[0] != 0x60)
    {
        return false;
    }

    uint32_t sav_len;
    size_t sav_hdr_bytes;
    if (!asn1_decode_length(&pdu[1], pdu_len - 1, &sav_len, &sav_hdr_bytes))
    {
        return false;
    }

    const uint8_t *ptr = pdu + 1 + sav_hdr_bytes;
    const uint8_t *end = ptr + sav_len;
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

        if (tag == 0x80)
        {
            p->no_asdu = (uint16_t)asn1_uint(ptr, tl);
        }
        else if (tag == 0xA2)
        {
            const uint8_t *asdu_ptr = ptr;
            const uint8_t *asdu_end = ptr + tl;

            if (asdu_ptr + 2 <= asdu_end && *asdu_ptr == 0x30)
            {
                asdu_ptr++;
                uint32_t asdu_len;
                size_t asdu_lb;
                if (asn1_decode_length(asdu_ptr, (size_t)(asdu_end - asdu_ptr), &asdu_len, &asdu_lb))
                {
                    asdu_ptr += asdu_lb;
                    const uint8_t *elem_end = asdu_ptr + asdu_len;
                    if (elem_end > asdu_end)
                        elem_end = asdu_end;

                    while (asdu_ptr + 2 <= elem_end)
                    {
                        uint8_t atag = *asdu_ptr++;
                        uint32_t atl;
                        size_t alb;
                        if (!asn1_decode_length(asdu_ptr, (size_t)(elem_end - asdu_ptr), &atl, &alb))
                        {
                            break;
                        }
                        asdu_ptr += alb;
                        if (asdu_ptr + atl > elem_end)
                        {
                            break;
                        }

                        switch (atag)
                        {
                        case 0x80:
                            asn1_str(asdu_ptr, atl, p->sv_id, sizeof(p->sv_id));
                            break;
                        case 0x82:
                            p->smp_cnt = asn1_uint(asdu_ptr, atl);
                            break;
                        case 0x83:
                            p->conf_rev = asn1_uint(asdu_ptr, atl);
                            break;
                        case 0x84:
                            if (atl >= 4)
                            {
                                uint32_t sec = asn1_uint(asdu_ptr, 4);
                                uint32_t frac_ms = 0;
                                if (atl >= 7)
                                {
                                    uint32_t frac = (uint32_t)((asdu_ptr[4] << 16) | (asdu_ptr[5] << 8) | asdu_ptr[6]);
                                    frac_ms = (uint32_t)((((uint64_t)frac * 1000ULL) + 8388608ULL) / 16777216ULL);
                                }
                                p->frame_timestamp_ms = ((uint64_t)sec * 1000ULL) + (uint64_t)frac_ms;
                            }
                            break;
                        case 0x85:
                            p->smp_synch = asn1_uint(asdu_ptr, atl);
                            break;
                        case 0x86:
                            p->smp_rate = asn1_uint(asdu_ptr, atl);
                            p->has_smp_rate = true;
                            break;
                        default:
                            break;
                        }
                        asdu_ptr += atl;
                    }
                }
            }
        }
        ptr += tl;
    }

    return true;
}

static SV_Event_t s_sv_event;
static char s_sv_target_str[128];
static uint32_t s_last_sv_print_tick = 0;
static uint32_t s_sv_suppressed_prints = 0;

/**
 * @brief Matches a parsed SV frame against active SCD configuration control blocks.
 * @param cfg Pointer to active SCD configuration.
 * @param p Pointer to parsed SV frame.
 * @param idx Output index in active SV array.
 * @return Pointer to matched SCD_SV_t or NULL if no match.
 */
static const SCD_SV_t *find_sv_scd_match(const SCD_Config_t *cfg, const ParsedSv_t *p, int *idx)
{
    if (p->sv_id[0] != '\0')
    {
        for (uint16_t i = 0; i < cfg->numSv; i++)
        {
            const SCD_SV_t *s = &cfg->sv[i];
            if (strcmp(p->sv_id, s->svId) == 0)
            {
                *idx = (int)i;
                return s;
            }
            if (s->controlBlock[0] != '\0' && s->publisherIed[0] != '\0' &&
                strstr(p->sv_id, s->controlBlock) && strstr(p->sv_id, s->publisherIed))
            {
                *idx = (int)i;
                return s;
            }
        }
    }

    for (uint16_t i = 0; i < cfg->numSv; i++)
    {
        if (cfg->sv[i].appId == p->app_id)
        {
            *idx = (int)i;
            return &cfg->sv[i];
        }
    }

    for (uint16_t i = 0; i < cfg->numSv; i++)
    {
        if (memcmp(cfg->sv[i].mac, p->dst_mac, SCD_MAC_ADDR_LEN) == 0)
        {
            *idx = (int)i;
            return &cfg->sv[i];
        }
    }

    return NULL;
}

/**
 * @brief Emits an SV security event and logs anomalies to SD card.
 * @param e Pointer to security event structure.
 */
static void emit_sv_event(const SV_Event_t *e)
{
    if (e == NULL)
    {
        return;
    }

    if (e->type != SV_EVENT_ACCEPT)
    {
        SystemConfig_t sys_cfg;
        SystemConfig_Get(&sys_cfg);
        uint32_t now = HAL_GetTick();
        if ((now - s_last_sv_print_tick) >= sys_cfg.alerts.anomaly_print_interval_ms)
        {
            if (s_sv_suppressed_prints > 0)
            {
                SysLog_Print(SYSLOG_LEVEL_DEBUG, "IDS", "SV: %lu anomaly events suppressed in last %lu ms",
                             (unsigned long)s_sv_suppressed_prints, (unsigned long)(now - s_last_sv_print_tick));
                s_sv_suppressed_prints = 0;
            }
            (void)s_sv_suppressed_prints;
        }
        else
        {
            s_sv_suppressed_prints++;
        }

        s_sv_target_str[0] = '\0';
        if (e->ied[0] != '\0' || e->cb[0] != '\0')
        {
            snprintf(s_sv_target_str, sizeof(s_sv_target_str), "%s/%s", e->ied, e->cb);
        }
        else if (e->sv_id[0] != '\0')
        {
            strncpy(s_sv_target_str, e->sv_id, sizeof(s_sv_target_str) - 1);
            s_sv_target_str[sizeof(s_sv_target_str) - 1] = '\0';
        }

        Security_AlertLog_t alert = {
            .timestamp_ms = e->timestamp_ms ? e->timestamp_ms : now,
            .frame_timestamp_ms = e->frame_timestamp_ms,
            .protocol = SEC_PROTO_SV,
            .severity = e->severity,
            .event_type = Sv_EventToString(e->type),
            .src_mac = e->src_mac,
            .dst_mac = e->dst_mac,
            .src_ip = NULL,
            .dst_ip = NULL,
            .target = s_sv_target_str[0] ? s_sv_target_str : NULL,
            .app_id = e->app_id,
            .vlan_id = e->vlan_id,
            .conf_rev = e->conf_rev,
            .st_num = 0,
            .sq_num = e->smp_cnt,
            .details = e->details,
            .recommendation = NULL};

        Security_LogAlertToSD(&alert);
    }
    else
    {
        SystemConfig_t sys_cfg;
        SystemConfig_Get(&sys_cfg);
        uint32_t now = HAL_GetTick();
        static uint32_t s_last_sv_normal_tick = 0;
        if ((now - s_last_sv_normal_tick) >= sys_cfg.alerts.normal_traffic_log_interval_ms || s_last_sv_normal_tick == 0)
        {
            s_last_sv_normal_tick = now;

            s_sv_target_str[0] = '\0';
            if (e->ied[0] != '\0' || e->cb[0] != '\0')
            {
                snprintf(s_sv_target_str, sizeof(s_sv_target_str), "%s/%s", e->ied, e->cb);
            }
            else if (e->sv_id[0] != '\0')
            {
                strncpy(s_sv_target_str, e->sv_id, sizeof(s_sv_target_str) - 1);
                s_sv_target_str[sizeof(s_sv_target_str) - 1] = '\0';
            }

            Security_AlertLog_t alert = {
                .timestamp_ms = e->timestamp_ms ? e->timestamp_ms : now,
                .frame_timestamp_ms = e->frame_timestamp_ms,
                .protocol = SEC_PROTO_SV,
                .severity = SEC_SEV_INFO,
                .event_type = Sv_EventToString(e->type),
                .src_mac = e->src_mac,
                .dst_mac = e->dst_mac,
                .src_ip = NULL,
                .dst_ip = NULL,
                .target = s_sv_target_str[0] ? s_sv_target_str : NULL,
                .app_id = e->app_id,
                .vlan_id = e->vlan_id,
                .conf_rev = e->conf_rev,
                .st_num = 0,
                .sq_num = e->smp_cnt,
                .details = "Normal SV traffic validated against active SCD baseline",
                .recommendation = NULL};

            Security_LogAlertToSD(&alert);
        }
    }
}

/**
 * @brief Populates base fields of an SV security event.
 * @param e Event structure to populate.
 * @param p Parsed SV frame.
 * @param s Matched SCD SV control block.
 */
static void fill_sv_event_base(SV_Event_t *e, const ParsedSv_t *p, const SCD_SV_t *s)
{
    memset(e, 0, sizeof(*e));
    e->type = SV_EVENT_ACCEPT;
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
    e->no_asdu = p->no_asdu;
    e->smp_cnt = p->smp_cnt;
    e->smp_rate = p->smp_rate;
    strncpy(e->sv_id, p->sv_id, sizeof(e->sv_id) - 1);

    if (s != NULL)
    {
        strncpy(e->ied, s->publisherIed, sizeof(e->ied) - 1);
        strncpy(e->cb, s->controlBlock, sizeof(e->cb) - 1);
    }
}

/**
 * @brief Validates a Sampled Values frame against the active SCD configuration.
 * @param frame Pointer to the raw received SV frame.
 * @return Detection result event type.
 */
SV_EventType_t Sv_IDS_Process(const Sv_Frame_t *frame)
{
    if (frame == NULL || frame->length == 0)
    {
        return SV_EVENT_NONE;
    }

    uint32_t now_ms = (frame->rx_timestamp_ms > 0) ? frame->rx_timestamp_ms : HAL_GetTick();
    ParsedSv_t p;

    if (!parse_sv_frame(frame->data, frame->length, now_ms, &p))
    {
        fill_sv_event_base(&s_sv_event, &p, NULL);
        s_sv_event.type = SV_EVENT_MALFORMED_FRAME;
        s_sv_event.severity = SEC_SEV_HIGH;
        if (frame->length >= 12)
        {
            memcpy(s_sv_event.dst_mac, &frame->data[0], SCD_MAC_ADDR_LEN);
            memcpy(s_sv_event.src_mac, &frame->data[6], SCD_MAC_ADDR_LEN);
        }
        snprintf(s_sv_event.details, sizeof(s_sv_event.details), "Malformed SV frame (len=%u)", frame->length);
        emit_sv_event(&s_sv_event);
        return SV_EVENT_MALFORMED_FRAME;
    }

    SCD_Config_Lock();
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    SCD_ConfigState_t state = SCD_Config_GetState();

    if (cfg == NULL || state != SCD_CONFIG_STATE_READY || !cfg->isValid)
    {
        SCD_Config_Unlock();
        fill_sv_event_base(&s_sv_event, &p, NULL);
        s_sv_event.type = SV_EVENT_UNKNOWN_CONTROL_BLOCK;
        s_sv_event.severity = SEC_SEV_HIGH;
        snprintf(s_sv_event.details, sizeof(s_sv_event.details), "No active SCD configuration for SV");
        emit_sv_event(&s_sv_event);
        return SV_EVENT_UNKNOWN_CONTROL_BLOCK;
    }

    if (cfg->configVersion != g_sv_cfg_version)
    {
        memset(g_sv_streams, 0, sizeof(g_sv_streams));
        g_sv_cfg_version = cfg->configVersion;
    }

    int idx = -1;
    const SCD_SV_t *s = find_sv_scd_match(cfg, &p, &idx);

    if (s == NULL || idx < 0 || idx >= SCD_MAX_SV)
    {
        SCD_Config_Unlock();
        fill_sv_event_base(&s_sv_event, &p, NULL);
        s_sv_event.type = SV_EVENT_UNKNOWN_CONTROL_BLOCK;
        s_sv_event.severity = SEC_SEV_HIGH;
        snprintf(s_sv_event.details, sizeof(s_sv_event.details), "Unknown SV CB (svID='%.48s' appid=0x%04X)",
                 p.sv_id[0] ? p.sv_id : "-", p.app_id);
        emit_sv_event(&s_sv_event);
        return SV_EVENT_UNKNOWN_CONTROL_BLOCK;
    }

    fill_sv_event_base(&s_sv_event, &p, s);
    SV_EventType_t result = SV_EVENT_ACCEPT;

    SystemConfig_t sys_cfg;
    SystemConfig_Get(&sys_cfg);

    bool baseline_mismatch = false;
    if (sys_cfg.sv.baseline_check_enabled)
    {
        if (memcmp(p.dst_mac, s->mac, SCD_MAC_ADDR_LEN) != 0)
        {
            s_sv_event.type = SV_EVENT_MAC_MISMATCH;
            s_sv_event.severity = SEC_SEV_HIGH;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV DST MAC %02X:%02X:%02X:%02X:%02X:%02X != %s",
                     p.dst_mac[0], p.dst_mac[1], p.dst_mac[2],
                     p.dst_mac[3], p.dst_mac[4], p.dst_mac[5], s->macStr);
            result = SV_EVENT_MAC_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.app_id != s->appId)
        {
            s_sv_event.type = SV_EVENT_APPID_MISMATCH;
            s_sv_event.severity = SEC_SEV_HIGH;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV APPID 0x%04X != 0x%04X", p.app_id, s->appId);
            result = SV_EVENT_APPID_MISMATCH;
            baseline_mismatch = true;
        }
        else if ((s->vlanId > 0 && !p.is_vlan_tagged) ||
                 (s->vlanId > 0 && p.vlan_id != s->vlanId) ||
                 (s->vlanId == 0 && p.is_vlan_tagged))
        {
            s_sv_event.type = SV_EVENT_VLAN_MISMATCH;
            s_sv_event.severity = SEC_SEV_HIGH;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV VLAN %u != %u (tagged=%d)",
                     p.vlan_id, s->vlanId, p.is_vlan_tagged);
            result = SV_EVENT_VLAN_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.is_vlan_tagged && s->vlanId > 0 && p.vlan_priority != s->vlanPriority)
        {
            s_sv_event.type = SV_EVENT_VLAN_PRIORITY_MISMATCH;
            s_sv_event.severity = SEC_SEV_WARNING;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV VLAN priority %u != %u",
                     p.vlan_priority, s->vlanPriority);
            result = SV_EVENT_VLAN_PRIORITY_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.sv_id[0] != '\0' && s->svId[0] != '\0' && strcmp(p.sv_id, s->svId) != 0)
        {
            s_sv_event.type = SV_EVENT_SVID_MISMATCH;
            s_sv_event.severity = SEC_SEV_HIGH;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV svID '%.40s' != '%.40s'", p.sv_id, s->svId);
            result = SV_EVENT_SVID_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.conf_rev != s->confRev)
        {
            s_sv_event.type = SV_EVENT_CONFREV_MISMATCH;
            s_sv_event.severity = SEC_SEV_HIGH;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV confRev %lu != %lu",
                     (unsigned long)p.conf_rev, (unsigned long)s->confRev);
            result = SV_EVENT_CONFREV_MISMATCH;
            baseline_mismatch = true;
        }
        else if (s->nofASDU > 0 && p.no_asdu != s->nofASDU)
        {
            s_sv_event.type = SV_EVENT_NOFASDU_MISMATCH;
            s_sv_event.severity = SEC_SEV_HIGH;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV nofASDU %u != %u", p.no_asdu, s->nofASDU);
            result = SV_EVENT_NOFASDU_MISMATCH;
            baseline_mismatch = true;
        }
        else if (p.has_smp_rate && s->sampleRate > 0 && p.smp_rate != s->sampleRate)
        {
            s_sv_event.type = SV_EVENT_SAMPLERATE_MISMATCH;
            s_sv_event.severity = SEC_SEV_HIGH;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV sampleRate %lu != %lu",
                     (unsigned long)p.smp_rate, (unsigned long)s->sampleRate);
            result = SV_EVENT_SAMPLERATE_MISMATCH;
            baseline_mismatch = true;
        }
    }

    if (!baseline_mismatch)
    {
        SvStreamState_t *st = &g_sv_streams[idx];
        uint32_t smp_rate = (s->sampleRate > 0) ? s->sampleRate : sys_cfg.sv.sample_rate_fallback;
        uint32_t expected_step = (p.no_asdu > 0) ? (uint32_t)p.no_asdu : 1;
        uint32_t delta_rx_ms = (st->initialized && p.rx_ms >= st->last_rx_ms)
                                   ? (p.rx_ms - st->last_rx_ms)
                                   : (0xFFFFFFFF - st->last_rx_ms + p.rx_ms + 1);

        bool is_idle = (st->initialized && delta_rx_ms > sys_cfg.sv.idle_timeout_ms);
        bool is_valid_restart = (!st->initialized || (is_idle && p.smp_cnt == 0) || (is_idle && p.smp_cnt > st->last_smp_cnt));

        if (is_valid_restart || !sys_cfg.sv.smpcnt_check_enabled)
        {
            result = SV_EVENT_ACCEPT;
        }
        else if (p.smp_cnt == st->last_smp_cnt)
        {
            s_sv_event.type = SV_EVENT_SMPCNT_DUPLICATE;
            s_sv_event.severity = SEC_SEV_WARNING;
            snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV duplicate smpCnt %lu",
                     (unsigned long)p.smp_cnt);
            result = SV_EVENT_SMPCNT_DUPLICATE;
        }
        else
        {
            uint32_t forward_dist = (p.smp_cnt > st->last_smp_cnt)
                                        ? (p.smp_cnt - st->last_smp_cnt)
                                        : (smp_rate - st->last_smp_cnt + p.smp_cnt);

            uint32_t expected_cnt = (st->last_smp_cnt + expected_step) % smp_rate;

            if (forward_dist == expected_step)
            {
                result = SV_EVENT_ACCEPT;
            }
            else if (forward_dist > expected_step && forward_dist <= sys_cfg.sv.wrap_boundary_tolerance)
            {
                s_sv_event.type = SV_EVENT_SMPCNT_GAP;
                s_sv_event.severity = SEC_SEV_WARNING;
                snprintf(s_sv_event.details, sizeof(s_sv_event.details),
                         (p.smp_cnt < st->last_smp_cnt)
                             ? "SV smpCnt gap at wrap-around %lu -> %lu (expected %lu)"
                             : "SV smpCnt gap %lu -> %lu (expected %lu)",
                         (unsigned long)st->last_smp_cnt, (unsigned long)p.smp_cnt, (unsigned long)expected_cnt);
                result = SV_EVENT_SMPCNT_GAP;
            }
            else
            {
                s_sv_event.type = SV_EVENT_SMPCNT_ROLLBACK;
                s_sv_event.severity = SEC_SEV_HIGH;
                snprintf(s_sv_event.details, sizeof(s_sv_event.details), "SV smpCnt rollback %lu -> %lu (rate=%lu)",
                         (unsigned long)st->last_smp_cnt, (unsigned long)p.smp_cnt, (unsigned long)smp_rate);
                result = SV_EVENT_SMPCNT_ROLLBACK;
            }
        }

        st->initialized = true;
        st->last_smp_cnt = p.smp_cnt;
        st->last_rx_ms = p.rx_ms;
    }

    SCD_Config_Unlock();
    emit_sv_event(&s_sv_event);
    return result;
}

static Sv_Stats_t s_sv_stats = {0};

/**
 * @brief Copies the current SV statistics to the provided structure.
 */
void Sv_GetStats(Sv_Stats_t *stats)
{
    if (stats != NULL)
    {
        *stats = s_sv_stats;
    }
}

/**
 * @brief Initializes the SV frame memory pool and stream tracking state.
 */
void Sv_Init(void)
{
    Security_Init();
    if (SvPoolHandle == NULL)
    {
        SvPoolHandle = osPoolCreate(osPool(SvPool));
    }
    memset(g_sv_streams, 0, sizeof(g_sv_streams));
    g_sv_cfg_version = 0;
}

/**
 * @brief Copies raw packet data into a frame pool element and enqueues it for SV IDS processing.
 * @param p Pointer to lwIP packet buffer.
 */
void Sv_Enqueue(struct pbuf *p)
{
    if (p == NULL || SvPoolHandle == NULL || p->tot_len > SV_MAX_FRAME_SIZE)
    {
        return;
    }

    s_sv_stats.frames_received++;

    Sv_Frame_t *frame = (Sv_Frame_t *)osPoolAlloc(SvPoolHandle);
    if (frame == NULL)
    {
        s_sv_stats.pool_alloc_failures++;
        return;
    }

    frame->rx_timestamp_ms = HAL_GetTick();
    frame->length = pbuf_copy_partial(p, frame->data, p->tot_len, 0);

    if (osMessagePut(SVQueueHandle, (uint32_t)frame, 0) != osOK)
    {
        s_sv_stats.queue_sends_failed++;
        osPoolFree(SvPoolHandle, frame);
    }
}

/**
 * @brief FreeRTOS task function dequeuing and processing incoming SV frames.
 * @param argument Unused task parameter.
 */
void Sv_Task(void const *argument)
{
    (void)argument;

    for (;;)
    {
        if (SVQueueHandle == NULL)
        {
            osDelay(10);
            continue;
        }

        osEvent evt = osMessageGet(SVQueueHandle, osWaitForever);
        if (evt.status == osEventMessage)
        {
            Sv_Frame_t *frame = (Sv_Frame_t *)evt.value.v;
            if (frame != NULL)
            {
                s_sv_stats.frames_processed++;
                Sv_IDS_Process(frame);
                if (SvPoolHandle != NULL)
                {
                    osPoolFree(SvPoolHandle, frame);
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
 * @brief Converts SV event type to string representation.
 * @param type Event type enum value.
 * @return Constant string description of the event.
 */
const char *Sv_EventToString(SV_EventType_t type)
{
    switch (type)
    {
    case SV_EVENT_ACCEPT:
        return "SV_TRAFFIC_NORMAL";
    case SV_EVENT_UNKNOWN_CONTROL_BLOCK:
        return "SV_UNKNOWN_CONTROL_BLOCK";
    case SV_EVENT_MAC_MISMATCH:
        return "SV_MAC_MISMATCH";
    case SV_EVENT_APPID_MISMATCH:
        return "SV_APPID_MISMATCH";
    case SV_EVENT_VLAN_MISMATCH:
        return "SV_VLAN_MISMATCH";
    case SV_EVENT_VLAN_PRIORITY_MISMATCH:
        return "SV_VLAN_PRIORITY_MISMATCH";
    case SV_EVENT_CONFREV_MISMATCH:
        return "SV_CONFREV_MISMATCH";
    case SV_EVENT_SVID_MISMATCH:
        return "SV_SVID_MISMATCH";
    case SV_EVENT_NOFASDU_MISMATCH:
        return "SV_NOFASDU_MISMATCH";
    case SV_EVENT_SAMPLERATE_MISMATCH:
        return "SV_SAMPLERATE_MISMATCH";
    case SV_EVENT_SMPCNT_GAP:
        return "SV_SMPCNT_GAP";
    case SV_EVENT_SMPCNT_DUPLICATE:
        return "SV_SMPCNT_DUPLICATE";
    case SV_EVENT_SMPCNT_ROLLBACK:
        return "SV_SMPCNT_ROLLBACK";
    case SV_EVENT_MALFORMED_FRAME:
        return "SV_MALFORMED_FRAME";
    default:
        return "SV_EVENT_NONE";
    }
}

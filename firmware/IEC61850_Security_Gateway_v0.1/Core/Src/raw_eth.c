#include "raw_eth.h"
#include "goose.h"
#include "sv.h"
#include "mms.h"
#include "system_config.h"
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include "FreeRTOS.h"
#include "task.h"
#include "main.h"

#define RAW_ETH_TYPE_VLAN 0x8100
#define RAW_ETH_TYPE_GOOSE 0x88B8
#define RAW_ETH_TYPE_SV 0x88BA
#define RAW_ETH_TYPE_IPV4 0x0800

static PacketAccounting s_accounting;

void Accounting_Increment(AccountProtocol protocol, AccountField field)
{
    taskENTER_CRITICAL();
    if (s_accounting.values[protocol][field] != UINT32_MAX)
        s_accounting.values[protocol][field]++;
    else
        s_accounting.saturated = 1;
    if (field == ACCOUNT_PARSED)
        s_accounting.last_parsed_ms = HAL_GetTick();
    taskEXIT_CRITICAL();
}

void Accounting_Get(PacketAccounting *out)
{
    taskENTER_CRITICAL();
    *out = s_accounting;
    taskEXIT_CRITICAL();
}

/**
 * @brief Checks whether an IPv4 packet contains MMS traffic based on active configuration.
 */
static inline bool is_mms_packet(struct pbuf *p, uint16_t ip_offset)
{
    if (p == NULL || p->tot_len < ip_offset + 24)
    {
        return false;
    }

    SystemConfig_t sys_cfg;
    SystemConfig_Get(&sys_cfg);
    if (!sys_cfg.mms.inspection_enabled)
    {
        return false;
    }

    uint8_t ip_hdr[20];
    if (pbuf_copy_partial(p, ip_hdr, 20, ip_offset) != 20)
    {
        return false;
    }

    if ((ip_hdr[0] >> 4) != 4 || ip_hdr[9] != 6)
    {
        return false;
    }

    uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
    if (ihl < 20 || p->tot_len < ip_offset + ihl + 4)
    {
        return false;
    }

    uint8_t tcp_hdr[4];
    if (pbuf_copy_partial(p, tcp_hdr, 4, ip_offset + ihl) != 4)
    {
        return false;
    }

    uint16_t src_port = (uint16_t)((tcp_hdr[0] << 8) | tcp_hdr[1]);
    uint16_t dst_port = (uint16_t)((tcp_hdr[2] << 8) | tcp_hdr[3]);
    uint16_t mms_port = (sys_cfg.mms.tcp_port > 0) ? sys_cfg.mms.tcp_port : 102;

    return (src_port == mms_port || dst_port == mms_port);
}

/**
 * @brief Classifies an incoming raw Ethernet packet and dispatches to the appropriate protocol handler.
 * @param p Pointer to the lwIP packet buffer containing the raw Ethernet frame.
 * @return true if packet is a pure Layer-2 frame (SV or GOOSE) that should NOT be passed to lwIP;
 *         false if packet must continue through lwIP (IPv4/MMS, ARP, etc.).
 */
bool RawEth_Process(struct pbuf *p, uint64_t rx_ticks, bool rx_valid)
{
    if (p == NULL)
        return false;
    if (p->tot_len < 14)
    {
        Accounting_Increment(ACCOUNT_OTHER, ACCOUNT_RX);
        return false;
    }

    uint8_t hdr[14];
    if (pbuf_copy_partial(p, hdr, 14, 0) != 14)
    {
        Accounting_Increment(ACCOUNT_OTHER, ACCOUNT_RX);
        return false;
    }

    uint16_t etype = (uint16_t)((hdr[12] << 8) | hdr[13]);

    switch (etype)
    {
    case RAW_ETH_TYPE_GOOSE:
        Accounting_Increment(ACCOUNT_GOOSE, ACCOUNT_RX);
        Goose_Enqueue(p, rx_ticks, rx_valid);
        return true;

    case RAW_ETH_TYPE_SV:
        Accounting_Increment(ACCOUNT_SV, ACCOUNT_RX);
        Sv_Enqueue(p);
        return true;

    case RAW_ETH_TYPE_IPV4:
        if (is_mms_packet(p, 14))
        {
            Accounting_Increment(ACCOUNT_MMS, ACCOUNT_RX);
            Mms_Enqueue(p);
        }
        else
            Accounting_Increment(ACCOUNT_OTHER, ACCOUNT_RX);
        return false;

    case RAW_ETH_TYPE_VLAN:
        if (p->tot_len >= 18)
        {
            uint8_t inner[2];
            if (pbuf_copy_partial(p, inner, 2, 16) == 2)
            {
                uint16_t inner_type = (uint16_t)((inner[0] << 8) | inner[1]);
                if (inner_type == RAW_ETH_TYPE_GOOSE)
                {
                    Accounting_Increment(ACCOUNT_GOOSE, ACCOUNT_RX);
                    Goose_Enqueue(p, rx_ticks, rx_valid);
                    return true;
                }
                else if (inner_type == RAW_ETH_TYPE_SV)
                {
                    Accounting_Increment(ACCOUNT_SV, ACCOUNT_RX);
                    Sv_Enqueue(p);
                    return true;
                }
                else if (inner_type == RAW_ETH_TYPE_IPV4 && is_mms_packet(p, 18))
                {
                    Accounting_Increment(ACCOUNT_MMS, ACCOUNT_RX);
                    Mms_Enqueue(p);
                    return false;
                }
            }
        }
        Accounting_Increment(ACCOUNT_OTHER, ACCOUNT_RX);
        return false;

    default:
        Accounting_Increment(ACCOUNT_OTHER, ACCOUNT_RX);
        return false;
    }
}
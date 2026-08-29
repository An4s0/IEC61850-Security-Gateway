#include "raw_eth.h"
#include "goose.h"
#include "sv.h"
#include "mms.h"
#include <stdint.h>
#include <stdbool.h>

#define RAW_ETH_TYPE_VLAN 0x8100
#define RAW_ETH_TYPE_GOOSE 0x88B8
#define RAW_ETH_TYPE_SV 0x88BA
#define RAW_ETH_TYPE_IPV4 0x0800

/**
 * @brief Checks whether an IPv4 packet contains MMS traffic (TCP port 102).
 */
static inline bool is_mms_packet(struct pbuf *p, uint16_t ip_offset)
{
    if (p == NULL || p->tot_len < ip_offset + 24)
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

    return (src_port == 102 || dst_port == 102);
}

/**
 * @brief Classifies an incoming raw Ethernet packet and dispatches to the appropriate protocol handler.
 * @param p Pointer to the lwIP packet buffer containing the raw Ethernet frame.
 */
void RawEth_Process(struct pbuf *p)
{
    if (p == NULL || p->tot_len < 14)
    {
        return;
    }

    uint8_t hdr[14];
    if (pbuf_copy_partial(p, hdr, 14, 0) != 14)
    {
        return;
    }

    uint16_t etype = (uint16_t)((hdr[12] << 8) | hdr[13]);

    switch (etype)
    {
    case RAW_ETH_TYPE_GOOSE:
        Goose_Enqueue(p);
        break;

    case RAW_ETH_TYPE_SV:
        Sv_Enqueue(p);
        break;

    case RAW_ETH_TYPE_IPV4:
        if (is_mms_packet(p, 14))
        {
            Mms_Enqueue(p);
        }
        break;

    case RAW_ETH_TYPE_VLAN:
        if (p->tot_len >= 18)
        {
            uint8_t inner[2];
            if (pbuf_copy_partial(p, inner, 2, 16) == 2)
            {
                uint16_t inner_type = (uint16_t)((inner[0] << 8) | inner[1]);
                if (inner_type == RAW_ETH_TYPE_GOOSE)
                {
                    Goose_Enqueue(p);
                }
                else if (inner_type == RAW_ETH_TYPE_SV)
                {
                    Sv_Enqueue(p);
                }
                else if (inner_type == RAW_ETH_TYPE_IPV4 && is_mms_packet(p, 18))
                {
                    Mms_Enqueue(p);
                }
            }
        }
        break;

    default:
        break;
    }
}
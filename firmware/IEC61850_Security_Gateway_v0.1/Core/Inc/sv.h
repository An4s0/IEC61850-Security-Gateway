#ifndef SV_H
#define SV_H

#include "lwip/pbuf.h"
#include "scd_config.h"
#include "security.h"
#include <stdint.h>
#include <stdbool.h>

#define SV_MAX_FRAME_SIZE 512
#define SV_FRAME_POOL_SIZE 16

typedef struct
{
    uint16_t length;
    uint32_t rx_timestamp_ms;
    uint8_t data[SV_MAX_FRAME_SIZE];
} Sv_Frame_t;

typedef enum
{
    SV_EVENT_NONE = 0,
    SV_EVENT_ACCEPT,
    SV_EVENT_UNKNOWN_CONTROL_BLOCK,
    SV_EVENT_MAC_MISMATCH,
    SV_EVENT_APPID_MISMATCH,
    SV_EVENT_VLAN_MISMATCH,
    SV_EVENT_VLAN_PRIORITY_MISMATCH,
    SV_EVENT_CONFREV_MISMATCH,
    SV_EVENT_SVID_MISMATCH,
    SV_EVENT_NOFASDU_MISMATCH,
    SV_EVENT_SAMPLERATE_MISMATCH,
    SV_EVENT_SMPCNT_GAP,
    SV_EVENT_SMPCNT_DUPLICATE,
    SV_EVENT_SMPCNT_ROLLBACK,
    SV_EVENT_MALFORMED_FRAME
} SV_EventType_t;

typedef struct
{
    SV_EventType_t type;
    Security_Severity_t severity;
    uint32_t timestamp_ms;
    uint64_t frame_timestamp_ms;
    uint8_t src_mac[SCD_MAC_ADDR_LEN];
    uint8_t dst_mac[SCD_MAC_ADDR_LEN];
    uint16_t app_id;
    uint16_t vlan_id;
    uint8_t vlan_priority;
    bool is_vlan_tagged;
    char sv_id[SCD_MAX_SVID_LEN];
    uint32_t conf_rev;
    uint16_t no_asdu;
    uint32_t smp_cnt;
    uint32_t smp_rate;
    char ied[SCD_MAX_NAME_LEN];
    char cb[SCD_MAX_NAME_LEN];
    char details[128];
} SV_Event_t;

void Sv_Init(void);
void Sv_Enqueue(struct pbuf *p);
void Sv_Task(void const *argument);

SV_EventType_t Sv_IDS_Process(const Sv_Frame_t *frame);
const char *Sv_EventToString(SV_EventType_t type);

#endif /* SV_H */

#ifndef GOOSE_H
#define GOOSE_H

#include "lwip/pbuf.h"
#include "scd_config.h"
#include "security.h"
#include <stdint.h>
#include <stdbool.h>

#define GOOSE_MAX_FRAME_SIZE 512
#define GOOSE_FRAME_POOL_SIZE 16

typedef struct
{
    uint16_t length;
    uint32_t rx_timestamp_ms;
    uint64_t rx_timestamp_ticks;
    bool rx_timestamp_valid;
    uint8_t data[GOOSE_MAX_FRAME_SIZE];
} Goose_Frame_t;

typedef enum
{
    GOOSE_EVENT_NONE = 0,
    GOOSE_EVENT_ACCEPT,
    GOOSE_EVENT_UNKNOWN_CONTROL_BLOCK,
    GOOSE_EVENT_MAC_MISMATCH,
    GOOSE_EVENT_APPID_MISMATCH,
    GOOSE_EVENT_VLAN_MISMATCH,
    GOOSE_EVENT_VLAN_PRIORITY_MISMATCH,
    GOOSE_EVENT_CONFREV_MISMATCH,
    GOOSE_EVENT_TIMING_FAST,
    GOOSE_EVENT_TIMING_SLOW,
    GOOSE_EVENT_STATE_ANOMALY,
    GOOSE_EVENT_MALFORMED_FRAME
} GOOSE_EventType_t;

typedef struct
{
    GOOSE_EventType_t type;
    Security_Severity_t severity;
    uint32_t timestamp_ms;
    uint64_t frame_timestamp_ms;
    uint8_t src_mac[SCD_MAC_ADDR_LEN];
    uint8_t dst_mac[SCD_MAC_ADDR_LEN];
    uint16_t app_id;
    uint16_t vlan_id;
    uint8_t vlan_priority;
    bool is_vlan_tagged;
    uint32_t conf_rev;
    uint32_t st_num;
    uint32_t sq_num;
    char ied[SCD_MAX_NAME_LEN];
    char cb[SCD_MAX_NAME_LEN];
    char details[128];
} GOOSE_Event_t;

typedef struct
{
    uint32_t frames_received;
    uint32_t frames_processed;
    uint32_t pool_alloc_failures;
    uint32_t queue_sends_failed;
    uint32_t pool_peak_usage;
    uint32_t queue_high_water;
} Goose_Stats_t;

void Goose_Init(void);
void Goose_Enqueue(struct pbuf *p, uint64_t rx_ticks, bool rx_valid);
void Goose_Task(void const *argument);
void Goose_GetStats(Goose_Stats_t *stats);

GOOSE_EventType_t Goose_IDS_Process(const Goose_Frame_t *frame);

const char *Goose_EventToString(GOOSE_EventType_t type);

static inline uint64_t Goose_RxDelta(uint64_t now, uint64_t previous)
{
    return (now - previous) & UINT64_C(0x7fffffffffffffff);
}

static inline bool Goose_RxBeforeMs(uint64_t ticks, uint32_t hz, uint32_t ms)
{
    return hz != 0U && ticks < (((uint64_t)ms * hz) + 999U) / 1000U;
}

static inline bool Goose_RxAfterMs(uint64_t ticks, uint32_t hz, uint32_t ms)
{
    return hz != 0U && ticks > ((uint64_t)ms * hz) / 1000U;
}

static inline uint32_t Goose_RxElapsedMs(uint64_t ticks, uint32_t hz)
{
    if (!hz)
        return 0;
    uint64_t sec = ticks / hz;
    if (sec > UINT32_MAX / 1000U)
        return UINT32_MAX;
    uint64_t ms = sec * 1000U + (ticks % hz) * 1000U / hz;
    return ms > UINT32_MAX ? UINT32_MAX : (uint32_t)ms;
}

#endif /* GOOSE_H */
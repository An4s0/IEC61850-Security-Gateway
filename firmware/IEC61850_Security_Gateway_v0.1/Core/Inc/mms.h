#ifndef MMS_H
#define MMS_H

#include "lwip/pbuf.h"
#include "scd_config.h"
#include "security.h"
#include <stdint.h>
#include <stdbool.h>

#define MMS_MAX_FRAME_SIZE 512
#define MMS_FRAME_POOL_SIZE 16

typedef struct
{
    uint16_t length;
    uint32_t rx_timestamp_ms;
    uint8_t data[MMS_MAX_FRAME_SIZE];
} Mms_Frame_t;

typedef enum
{
    MMS_EVENT_NONE = 0,
    MMS_EVENT_ACCEPT,
    MMS_EVENT_UNKNOWN_ENDPOINT,
    MMS_EVENT_UNKNOWN_SOURCE,
    MMS_EVENT_UNKNOWN_DESTINATION,
    MMS_EVENT_UNEXPECTED_ENDPOINT,
    MMS_EVENT_UNAUTHORIZED_PORT,
    MMS_EVENT_UNAUTHORIZED_WRITE,
    MMS_EVENT_TSEL_MISMATCH,
    MMS_EVENT_CON_ANOMALY,
    MMS_EVENT_MALFORMED_FRAME
} MMS_EventType_t;

typedef struct
{
    MMS_EventType_t type;
    Security_Severity_t severity;
    uint32_t timestamp_ms;
    uint64_t frame_timestamp_ms;
    char src_ip[SCD_MAX_IP_LEN];
    char dst_ip[SCD_MAX_IP_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    char src_tsel[16];
    char dst_tsel[16];
    char ied[SCD_MAX_NAME_LEN];
    char ap[SCD_MAX_AP_NAME_LEN];
    char service[32];
    char details[128];
} MMS_Event_t;

void Mms_Init(void);
void Mms_Enqueue(struct pbuf *p);
void Mms_Task(void const *argument);

MMS_EventType_t Mms_IDS_Process(const Mms_Frame_t *frame);
const char *Mms_EventToString(MMS_EventType_t type);

#endif /* MMS_H */

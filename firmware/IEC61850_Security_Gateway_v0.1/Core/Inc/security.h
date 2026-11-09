#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include "ff.h"

#define SECURITY_ALERTS_FILE "0:/alerts/alerts.ndjson"

typedef enum
{
    SEC_SEV_INFO = 0,
    SEC_SEV_WARNING,
    SEC_SEV_HIGH,
    SEC_SEV_CRITICAL
} Security_Severity_t;

typedef enum
{
    SEC_PROTO_GOOSE = 0,
    SEC_PROTO_SV,
    SEC_PROTO_MMS
} Security_Protocol_t;

typedef struct
{
    uint32_t timestamp_ms;
    uint64_t frame_timestamp_ms;
    Security_Protocol_t protocol;
    Security_Severity_t severity;
    const char *event_type;
    const uint8_t *src_mac;
    const uint8_t *dst_mac;
    const char *src_ip;
    const char *dst_ip;
    const char *target;
    uint16_t app_id;
    uint16_t vlan_id;
    uint32_t conf_rev;
    uint32_t st_num;
    uint32_t sq_num;
    const char *details;
    const char *recommendation;
} Security_AlertLog_t;

typedef struct
{
    uint32_t alerts_generated;
    uint32_t alerts_written;
    uint32_t alerts_dropped;
    uint32_t storage_errors;
    uint32_t slots_in_use;
    uint32_t slots_high_water;
    uint32_t alerts_attempted;
    uint32_t persistence_retries;
    uint32_t alerts_dropped_buffer_full;
    uint32_t alerts_dropped_mutex_busy;
    uint32_t alerts_purged;
} Security_Stats_t;

void Security_Init(void);
void Security_SyncAlertCounter(void);
const char *Security_SeverityToString(Security_Severity_t sev);
const char *Security_ProtocolToString(Security_Protocol_t proto);
bool Security_LogAlertToSD(const Security_AlertLog_t *alert);
void Security_PeriodicFlush(void);
bool Security_ClearAlertsOnSD(void);
bool Security_HasPendingAlert(void);
uint32_t Security_PurgePendingAlerts(void);
uint32_t Security_GetAlertCount(void);
bool Security_IsReady(void);
void Security_GetStats(Security_Stats_t *stats);

bool Security_LockSD(uint32_t timeout_ms);
void Security_UnlockSD(void);
void Security_GetGlobalStats(uint32_t *total, uint32_t *goose, uint32_t *sv, uint32_t *mms);
void Security_GetGlobalSevStats(uint32_t *crit, uint32_t *high, uint32_t *warn, uint32_t *info);

#endif /* SECURITY_H */

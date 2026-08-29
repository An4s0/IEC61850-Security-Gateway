#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stdbool.h>

#define SECURITY_ALERTS_FILE "0:/alerts.json"

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

void Security_Init(void);
const char *Security_SeverityToString(Security_Severity_t sev);
const char *Security_ProtocolToString(Security_Protocol_t proto);
bool Security_LogAlertToSD(const Security_AlertLog_t *alert);
bool Security_ClearAlertsOnSD(void);
uint32_t Security_GetAlertCount(void);

#endif /* SECURITY_H */

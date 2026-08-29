#ifndef SCD_CONFIG_H
#define SCD_CONFIG_H

#include "cmsis_os.h"
#include <stdint.h>
#include <stdbool.h>

#define SCD_MAX_IEDS 16
#define SCD_MAX_GOOSE 32
#define SCD_MAX_SV 16
#define SCD_MAX_MMS 16
#define SCD_MAX_REPORTS_PER_MMS 8
#define SCD_MAX_GOOSE_SUBSCRIBERS 4
#define SCD_MAX_MEMBERS_COUNT 16

#define SCD_MAX_NAME_LEN 32
#define SCD_MAX_AP_NAME_LEN 16
#define SCD_MAX_NET_NAME_LEN 16
#define SCD_MAX_IP_LEN 16
#define SCD_MAX_SVID_LEN 64
#define SCD_MAC_ADDR_LEN 6
#define SCD_MAC_STR_LEN 18

#define SCD_CONFIG_FILE_PATH "0:/substation.json"

typedef enum
{
    SCD_CONFIG_STATE_NONE = 0,
    SCD_CONFIG_STATE_LOADING,
    SCD_CONFIG_STATE_READY,
    SCD_CONFIG_STATE_ERROR
} SCD_ConfigState_t;

typedef enum
{
    SCD_CONFIG_CMD_LOAD_STARTUP = 1,
    SCD_CONFIG_CMD_RELOAD = 2
} SCD_ConfigCommand_t;

typedef struct
{
    char fileName[64];
    char id[SCD_MAX_NAME_LEN];
    char version[16];
} SCD_Header_t;

typedef struct
{
    char id[SCD_MAX_NAME_LEN];
    char manufacturer[SCD_MAX_NAME_LEN];
    char type[SCD_MAX_NAME_LEN];
    char voltageLevel[16];
    char bay[16];
    char apName[SCD_MAX_AP_NAME_LEN];
    char network[SCD_MAX_NET_NAME_LEN];
    char ip[SCD_MAX_IP_LEN];
    uint8_t mac[SCD_MAC_ADDR_LEN];
    char macStr[SCD_MAC_STR_LEN];
} SCD_IED_t;

typedef struct
{
    char publisherIed[SCD_MAX_NAME_LEN];
    char logicalDevice[SCD_MAX_NAME_LEN];
    char logicalNode[SCD_MAX_NAME_LEN];
    char controlBlock[SCD_MAX_NAME_LEN];
    char network[SCD_MAX_NET_NAME_LEN];
    uint8_t mac[SCD_MAC_ADDR_LEN];
    char macStr[SCD_MAC_STR_LEN];
    uint16_t appId;
    uint16_t vlanId;
    uint8_t vlanPriority;
    uint32_t confRev;
    char datasetName[SCD_MAX_NAME_LEN];
    uint8_t numMembers;
    char members[SCD_MAX_MEMBERS_COUNT][SCD_MAX_NAME_LEN];
    uint8_t numSubscribers;
    char subscribers[SCD_MAX_GOOSE_SUBSCRIBERS][SCD_MAX_NAME_LEN];
    uint32_t minTimeMs;
    uint32_t maxTimeMs;
} SCD_GOOSE_t;

typedef struct
{
    char publisherIed[SCD_MAX_NAME_LEN];
    char logicalDevice[SCD_MAX_NAME_LEN];
    char logicalNode[SCD_MAX_NAME_LEN];
    char controlBlock[SCD_MAX_NAME_LEN];
    char network[SCD_MAX_NET_NAME_LEN];
    uint8_t mac[SCD_MAC_ADDR_LEN];
    char macStr[SCD_MAC_STR_LEN];
    uint16_t appId;
    uint16_t vlanId;
    uint8_t vlanPriority;
    char svId[SCD_MAX_SVID_LEN];
    uint32_t sampleRate;
    uint16_t nofASDU;
    uint32_t confRev;
    char datasetName[SCD_MAX_NAME_LEN];
    uint8_t numMembers;
    char members[SCD_MAX_MEMBERS_COUNT][SCD_MAX_NAME_LEN];
} SCD_SV_t;

typedef struct
{
    uint8_t dchg;
    uint8_t qchg;
    uint8_t dupd;
    uint8_t period;
    uint8_t gi;
} SCD_MMS_TriggerOptions_t;

typedef struct
{
    char logicalDevice[SCD_MAX_NAME_LEN];
    char logicalNode[SCD_MAX_NAME_LEN];
    char name[SCD_MAX_NAME_LEN];
    char dataset[SCD_MAX_NAME_LEN];
    uint8_t buffered;
    uint32_t confRev;
    uint32_t intgPd;
    SCD_MMS_TriggerOptions_t triggerOptions;
} SCD_MMS_Report_t;

typedef struct
{
    char ied[SCD_MAX_NAME_LEN];
    char accessPoint[SCD_MAX_AP_NAME_LEN];
    char ip[SCD_MAX_IP_LEN];
    uint8_t numReports;
    SCD_MMS_Report_t reports[SCD_MAX_REPORTS_PER_MMS];
} SCD_MMS_t;

typedef struct
{
    SCD_Header_t header;
    uint16_t numIeds;
    SCD_IED_t ieds[SCD_MAX_IEDS];
    uint16_t numGoose;
    SCD_GOOSE_t goose[SCD_MAX_GOOSE];
    uint16_t numSv;
    SCD_SV_t sv[SCD_MAX_SV];
    uint16_t numMms;
    SCD_MMS_t mms[SCD_MAX_MMS];
    uint32_t loadTimestamp;
    uint32_t configVersion;
    uint8_t isValid;
} SCD_Config_t;

void SCD_Config_Init(void);
void SCD_Config_Task(void const *argument);
void SCD_Config_RequestLoadStartup(void);
void SCD_Config_RequestReload(void);

SCD_ConfigState_t SCD_Config_GetState(void);
const SCD_Config_t *SCD_Config_GetActive(void);
uint32_t SCD_Config_GetVersion(void);

void SCD_Config_Lock(void);
void SCD_Config_Unlock(void);

const SCD_IED_t *SCD_Config_FindIEDByName(const char *ied_name);
const SCD_IED_t *SCD_Config_FindIEDByIP(const char *ip_str);
const SCD_IED_t *SCD_Config_FindIEDByMAC(const uint8_t *mac);

const SCD_GOOSE_t *SCD_Config_FindGOOSE(uint16_t app_id, const uint8_t *mac);
const SCD_GOOSE_t *SCD_Config_FindGOOSEByControlBlock(const char *ied, const char *cb);

const SCD_SV_t *SCD_Config_FindSV(uint16_t app_id, const uint8_t *mac);
const SCD_SV_t *SCD_Config_FindSVBySvId(const char *sv_id);

const SCD_MMS_t *SCD_Config_FindMMSByIP(const char *ip_str);
const SCD_MMS_t *SCD_Config_FindMMSByIED(const char *ied_name);

#endif /* SCD_CONFIG_H */

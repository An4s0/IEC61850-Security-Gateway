#ifndef SCD_CONFIG_H
#define SCD_CONFIG_H

#include "cmsis_os.h"
#include <stdint.h>
#include <stdbool.h>

#define IDS_MAX_IEDS 256
#define IDS_MAX_GOOSE 128
#define IDS_MAX_SV 64
#define IDS_MAX_MMS 256

#define SCD_MAX_IEDS IDS_MAX_IEDS
#define SCD_MAX_GOOSE IDS_MAX_GOOSE
#define SCD_MAX_SV IDS_MAX_SV
#define SCD_MAX_MMS IDS_MAX_MMS

#define SCD_MAX_NAME_LEN 32
#define SCD_MAX_AP_NAME_LEN 16
#define SCD_MAX_IP_LEN 16
#define SCD_MAX_SVID_LEN 64
#define SCD_MAC_ADDR_LEN 6
#define SCD_MAC_STR_LEN 18

#define SCD_CONFIG_FILE_PATH "0:/substation/substation.json"
#define IDS_CONFIG_BIN_PATH "0:/config/ids_config.bin"
#define IDS_CONFIG_BAK_PATH "0:/config/ids_config.bak"
#define IDS_CONFIG_NEW_PATH "0:/config/ids_config.new"

#define IDS_CONFIG_BIN_MAGIC 0x49445343 /* "IDSC" (IDS Configuration) */
#define IDS_CONFIG_BIN_VERSION 1

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

/* Binary Header on SDMMC (128 bytes, packed) */
typedef struct __attribute__((packed))
{
    uint32_t magic;          /* 0x49445343 */
    uint16_t format_version; /* 1 */
    uint16_t header_len;     /* 128 */
    uint32_t file_size;      /* Total binary file size in bytes */
    uint32_t crc32;          /* IEEE 802.3 CRC32 of payload following header */
    uint32_t config_version; /* Monotonically increasing configuration version */
    uint32_t timestamp;      /* Load/creation timestamp */
    uint16_t num_goose;      /* Number of GOOSE records */
    uint16_t num_sv;         /* Number of SV records */
    uint16_t num_mms;        /* Number of MMS records */
    uint16_t num_ieds;       /* Number of IED records */
    char substation_id[32];  /* Substation name / ID */
    char file_name[48];      /* Source SCD file name */
    char version[16];        /* Version string */
} ids_bin_header_t;

typedef struct
{
    char fileName[64];
    char id[SCD_MAX_NAME_LEN];
    char version[16];
} SCD_Header_t;

/* Compact IED Record (64 bytes, packed) */
typedef struct __attribute__((packed))
{
    char id[SCD_MAX_NAME_LEN];
    char apName[SCD_MAX_AP_NAME_LEN];
    char ip[SCD_MAX_IP_LEN];
} SCD_IED_t;

/* Compact GOOSE Record (168 bytes, packed) */
typedef struct __attribute__((packed))
{
    char publisherIed[SCD_MAX_NAME_LEN];
    char logicalDevice[SCD_MAX_NAME_LEN];
    char logicalNode[SCD_MAX_NAME_LEN];
    char controlBlock[SCD_MAX_NAME_LEN];
    uint8_t mac[SCD_MAC_ADDR_LEN];
    char macStr[SCD_MAC_STR_LEN];
    uint16_t appId;
    uint16_t vlanId;
    uint8_t vlanPriority;
    uint8_t reserved;
    uint32_t confRev;
    uint32_t minTimeMs;
    uint32_t maxTimeMs;
} SCD_GOOSE_t;

/* Compact SV Record (232 bytes, packed) */
typedef struct __attribute__((packed))
{
    char publisherIed[SCD_MAX_NAME_LEN];
    char logicalDevice[SCD_MAX_NAME_LEN];
    char logicalNode[SCD_MAX_NAME_LEN];
    char controlBlock[SCD_MAX_NAME_LEN];
    uint8_t mac[SCD_MAC_ADDR_LEN];
    char macStr[SCD_MAC_STR_LEN];
    uint16_t appId;
    uint16_t vlanId;
    uint8_t vlanPriority;
    uint8_t reserved;
    char svId[SCD_MAX_SVID_LEN];
    uint32_t sampleRate;
    uint16_t nofASDU;
    uint16_t reserved2;
    uint32_t confRev;
} SCD_SV_t;

/* Compact MMS Server Record (64 bytes, packed) */
typedef struct __attribute__((packed))
{
    char ied[SCD_MAX_NAME_LEN];
    char accessPoint[SCD_MAX_AP_NAME_LEN];
    char ip[SCD_MAX_IP_LEN];
} SCD_MMS_t;

typedef struct
{
    SCD_Header_t header;
    uint32_t loadTimestamp;
    uint32_t configVersion;
    uint8_t isValid;
    uint16_t numIeds;
    uint16_t numGoose;
    uint16_t numSv;
    uint16_t numMms;
    SCD_IED_t *ieds;
    SCD_GOOSE_t *goose;
    SCD_SV_t *sv;
    SCD_MMS_t *mms;
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

const SCD_GOOSE_t *SCD_Config_FindGOOSE(uint16_t app_id, const uint8_t *mac);
const SCD_GOOSE_t *SCD_Config_FindGOOSEByControlBlock(const char *ied, const char *cb);

const SCD_SV_t *SCD_Config_FindSV(uint16_t app_id, const uint8_t *mac);
const SCD_SV_t *SCD_Config_FindSVBySvId(const char *sv_id);

const SCD_MMS_t *SCD_Config_FindMMSByIP(const char *ip_str);
const SCD_MMS_t *SCD_Config_FindMMSByIED(const char *ied_name);

void SCD_Config_GetMemoryUsage(uint32_t *total_bytes, uint32_t *active_bytes);

#endif /* SCD_CONFIG_H */

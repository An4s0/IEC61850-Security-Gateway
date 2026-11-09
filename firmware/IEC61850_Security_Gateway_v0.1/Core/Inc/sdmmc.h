/**
 * Pin mapping (SDMMC1, AF12):
 *   PC8  -> SDMMC1_D0
 *   PC9  -> SDMMC1_D1
 *   PC10 -> SDMMC1_D2
 *   PC11 -> SDMMC1_D3
 *   PC12 -> SDMMC1_CK
 *   PD2  -> SDMMC1_CMD
 *   PG2  -> SDMMC_DET (Card Detect, active-low with pull-up)
 */

#ifndef __SDMMC_H
#define __SDMMC_H

#include "stm32f7xx_hal.h"
#include <stdint.h>
#include <stdbool.h>

#define SDMMC_OK 0
#define SDMMC_ERR_TIMEOUT 1
#define SDMMC_ERR_CMD_CRC 2
#define SDMMC_ERR_DATA_CRC 3
#define SDMMC_ERR_CMD_TIMEOUT 4
#define SDMMC_ERR_DATA_TIMEOUT 5
#define SDMMC_ERR_TX_UNDERRUN 6
#define SDMMC_ERR_RX_OVERRUN 7
#define SDMMC_ERR_UNSUPPORTED 8
#define SDMMC_ERR_BUSY 9
#define SDMMC_ERR_GENERAL 10
#define SDMMC_ERR_WRITE_FAIL 11

typedef struct
{
    uint32_t read_failures;
    uint32_t write_failures;
    uint32_t write_retries;
    uint32_t write_recovered;
    uint32_t timeouts;
    uint32_t max_write_ms;
    uint32_t card_ready_timeouts;
    uint32_t max_irq_off_us;
} SDMMC_Diagnostics_t;

#define SD_CMD0_GO_IDLE_STATE 0
#define SD_CMD2_ALL_SEND_CID 2
#define SD_CMD3_SEND_RELATIVE_ADDR 3
#define SD_CMD6_SWITCH_FUNC 6
#define SD_CMD7_SELECT_CARD 7
#define SD_CMD8_SEND_IF_COND 8
#define SD_CMD9_SEND_CSD 9
#define SD_CMD10_SEND_CID 10
#define SD_CMD12_STOP_TRANSMISSION 12
#define SD_CMD13_SEND_STATUS 13
#define SD_CMD16_SET_BLOCKLEN 16
#define SD_CMD17_READ_SINGLE_BLOCK 17
#define SD_CMD18_READ_MULTIPLE_BLOCK 18
#define SD_CMD24_WRITE_BLOCK 24
#define SD_CMD25_WRITE_MULTIPLE_BLOCK 25
#define SD_CMD55_APP_CMD 55
#define SD_CMD58_READ_OCR 58

#define SD_ACMD6_SET_BUS_WIDTH 6
#define SD_ACMD41_SD_SEND_OP_COND 41
#define SD_ACMD51_SEND_SCR 51

#define SDMMC_RESP_NONE 0x00U
#define SDMMC_RESP_SHORT 0x01U
#define SDMMC_RESP_LONG 0x03U

typedef enum
{
    SD_CARD_UNKNOWN = 0,
    SD_CARD_V1,    /* SD v1.x Standard Capacity */
    SD_CARD_V2_SC, /* SD v2.0 Standard Capacity */
    SD_CARD_V2_HC, /* SD v2.0 High Capacity (SDHC/SDXC) */
} SD_CardType_t;

typedef struct
{
    SD_CardType_t CardType;
    uint32_t RCA;        /* Relative Card Address */
    uint32_t OCR;        /* Operation Conditions Register */
    uint32_t CID[4];     /* Card Identification (128-bit) */
    uint32_t CSD[4];     /* Card Specific Data (128-bit) */
    uint64_t Capacity;   /* Card capacity in bytes */
    uint32_t BlockSize;  /* Block size in bytes */
    uint32_t BlockCount; /* Number of blocks */
    uint8_t BusWidth;    /* Current bus width: 1 or 4 */
} SD_CardInfo_t;

#define SDMMC_DET_GPIO GPIOG
#define SDMMC_DET_PIN GPIO_PIN_2

void SDMMC_CardDetect_Init(void);
bool SDMMC_IsCardInserted(void);
void SDMMC_GPIO_Init(void);
void SDMMC_PeripheralInit(void);
void SDMMC_SetClockDiv(uint8_t div);
int SDMMC_SendCmd(uint8_t cmd, uint32_t arg, uint8_t respType);
int SDMMC_CardInit(SD_CardInfo_t *info);
int SDMMC_SetBusWidth4(SD_CardInfo_t *info);
int SDMMC_SetBusWidth1(SD_CardInfo_t *info);
int SDMMC_GetCardStatus(SD_CardInfo_t *info, uint32_t *status);
int SDMMC_ReadCSD(SD_CardInfo_t *info);
int SDMMC_ReadCID(SD_CardInfo_t *info);
void SDMMC_ParseCSD(SD_CardInfo_t *info);
int SDMMC_ReadBlock(SD_CardInfo_t *info, uint32_t block, uint8_t *buf);
int SDMMC_ReadBlocks(SD_CardInfo_t *info, uint32_t block, uint8_t *buf, uint32_t count);
int SDMMC_WriteBlock(SD_CardInfo_t *info, uint32_t block, const uint8_t *buf);
int SDMMC_WriteBlocks(SD_CardInfo_t *info, uint32_t block, const uint8_t *buf, uint32_t count);
const char *SDMMC_ErrorString(int err);
uint32_t SDMMC_GetLastStatus(void);
void SDMMC_GetDiagnostics(SDMMC_Diagnostics_t *out);

#endif /* __SDMMC_H */

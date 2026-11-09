#include "sdmmc.h"
#include "runtime_stats.h"
#include "cmsis_os.h"
#include <string.h>

static volatile uint32_t s_last_sta = 0;
volatile uint32_t g_last_read_count = 0;
static SDMMC_Diagnostics_t s_diagnostics;

static void sdmmc_increment(uint32_t *value)
{
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    if (*value != UINT32_MAX)
        (*value)++;
    __set_PRIMASK(primask);
}

void SDMMC_GetDiagnostics(SDMMC_Diagnostics_t *out)
{
    if (out == NULL)
        return;
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    *out = s_diagnostics;
    __set_PRIMASK(primask);
}

/**
 * @brief Records the longest observed interrupt-disabled FIFO burst, in microseconds.
 */
static void sdmmc_record_irq_off(uint32_t start, uint32_t end)
{
    uint32_t elapsed = end - start;
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    if (elapsed > s_diagnostics.max_irq_off_us)
    {
        s_diagnostics.max_irq_off_us = elapsed;
    }
    __set_PRIMASK(primask);
}

/**
 * @brief Delays execution using the RTOS scheduler or a busy-wait loop.
 */
static void sdmmc_delay_ms(uint32_t ms)
{
    if (xTaskGetSchedulerState() == taskSCHEDULER_RUNNING)
    {
        osDelay(ms);
    }
    else
    {
        for (uint32_t i = 0; i < ms; i++)
        {
            for (volatile uint32_t c = 0; c < (SystemCoreClock / 4000); c++)
            {
                __NOP();
            }
        }
    }
}

/**
 * @brief Clear all SDMMC1 status flags
 */
static void sdmmc_clear_flags(void)
{
    SDMMC1->ICR = 0x00C007FFU;
}

/**
 * @brief Wait for command completion (sent or response received)
 * @param respType: SDMMC_RESP_NONE, SDMMC_RESP_SHORT, SDMMC_RESP_LONG
 * @return SDMMC_OK or error code
 */
static int sdmmc_wait_cmd(uint8_t respType)
{
    uint32_t start = HAL_GetTick();
    uint32_t sta;

    if (respType == SDMMC_RESP_NONE)
    {
        while ((HAL_GetTick() - start) < 200)
        {
            sta = SDMMC1->STA;
            if (sta & SDMMC_STA_CTIMEOUT)
            {
                SDMMC1->ICR = SDMMC_STA_CTIMEOUT;
                s_last_sta = sta;
                return SDMMC_ERR_CMD_TIMEOUT;
            }
            if (sta & SDMMC_STA_CMDSENT)
            {
                SDMMC1->ICR = SDMMC_STA_CMDSENT;
                s_last_sta = sta;
                return SDMMC_OK;
            }
        }
    }
    else
    {
        while ((HAL_GetTick() - start) < 200)
        {
            sta = SDMMC1->STA;
            if (sta & SDMMC_STA_CTIMEOUT)
            {
                SDMMC1->ICR = SDMMC_STA_CTIMEOUT;
                s_last_sta = sta;
                return SDMMC_ERR_CMD_TIMEOUT;
            }
            if (sta & SDMMC_STA_CCRCFAIL)
            {
                SDMMC1->ICR = SDMMC_STA_CCRCFAIL;
                s_last_sta = sta;
                return SDMMC_ERR_CMD_CRC;
            }
            if (sta & SDMMC_STA_CMDREND)
            {
                SDMMC1->ICR = SDMMC_STA_CMDREND;
                s_last_sta = sta;
                return SDMMC_OK;
            }
        }
    }

    s_last_sta = SDMMC1->STA;
    return SDMMC_ERR_TIMEOUT;
}

const char *SDMMC_ErrorString(int err)
{
    switch (err)
    {
    case SDMMC_OK:
        return "OK";
    case SDMMC_ERR_TIMEOUT:
        return "Timeout (polling)";
    case SDMMC_ERR_CMD_CRC:
        return "Command CRC fail";
    case SDMMC_ERR_DATA_CRC:
        return "Data CRC fail";
    case SDMMC_ERR_CMD_TIMEOUT:
        return "Command timeout (no response)";
    case SDMMC_ERR_DATA_TIMEOUT:
        return "Data timeout";
    case SDMMC_ERR_TX_UNDERRUN:
        return "TX FIFO underrun";
    case SDMMC_ERR_RX_OVERRUN:
        return "RX FIFO overrun";
    case SDMMC_ERR_UNSUPPORTED:
        return "Unsupported card";
    case SDMMC_ERR_BUSY:
        return "Card busy";
    case SDMMC_ERR_GENERAL:
        return "General error";
    case SDMMC_ERR_WRITE_FAIL:
        return "Write failed";
    default:
        return "Unknown error";
    }
}

/**
 * @brief Returns the last recorded SDMMC status register value.
 */
uint32_t SDMMC_GetLastStatus(void)
{
    return s_last_sta;
}

/**
 * @brief Initializes the GPIO pins and clock settings required for SDMMC1.
 */
void SDMMC_GPIO_Init(void)
{
    RCC->APB2ENR |= RCC_APB2ENR_SYSCFGEN;
    HAL_EnableCompensationCell();
    while ((SYSCFG->CMPCR & SYSCFG_CMPCR_READY) == 0)
        ;

    RCC->APB2ENR |= (1UL << 11);
    RCC->DCKCFGR2 &= ~(1UL << 28);
    RCC->DCKCFGR2 &= ~(1UL << 27);
    SDMMC1->POWER = 0x03;

    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOD_CLK_ENABLE();

    GPIOC->AFR[1] &= ~((0xFUL << (0 * 4)) | (0xFUL << (1 * 4)) | (0xFUL << (2 * 4)) | (0xFUL << (3 * 4)) | (0xFUL << (4 * 4)));
    GPIOC->AFR[1] |= ((12UL << (0 * 4)) | (12UL << (1 * 4)) | (12UL << (2 * 4)) | (12UL << (3 * 4)) | (12UL << (4 * 4)));

    GPIOD->AFR[0] &= ~(0xFUL << (2 * 4));
    GPIOD->AFR[0] |= (12UL << (2 * 4));

    GPIOC->OTYPER &= ~((1UL << 8) | (1UL << 9) | (1UL << 10) | (1UL << 11) | (1UL << 12));
    GPIOD->OTYPER &= ~(1UL << 2);

    GPIOC->OSPEEDR &= ~((3UL << (8 * 2)) | (3UL << (9 * 2)) | (3UL << (10 * 2)) | (3UL << (11 * 2)) | (3UL << (12 * 2)));
    GPIOC->OSPEEDR |= (3UL << (12 * 2));

    GPIOD->OSPEEDR &= ~(3UL << (2 * 2));

    GPIOC->PUPDR &= ~((3UL << (8 * 2)) | (3UL << (9 * 2)) | (3UL << (10 * 2)) | (3UL << (11 * 2)) | (3UL << (12 * 2)));
    GPIOC->PUPDR |= ((1UL << (8 * 2)) | (1UL << (9 * 2)) | (1UL << (10 * 2)) | (1UL << (11 * 2)));

    GPIOD->PUPDR &= ~(3UL << (2 * 2));
    GPIOD->PUPDR |= (1UL << (2 * 2));

    GPIOC->MODER &= ~((3UL << (8 * 2)) | (3UL << (9 * 2)) | (3UL << (10 * 2)) | (3UL << (11 * 2)) | (3UL << (12 * 2)));
    GPIOC->MODER |= ((2UL << (8 * 2)) | (2UL << (9 * 2)) | (2UL << (10 * 2)) | (2UL << (11 * 2)) | (2UL << (12 * 2)));

    GPIOD->MODER &= ~(3UL << (2 * 2));
    GPIOD->MODER |= (2UL << (2 * 2));
}

/**
 * @brief Initializes the SD card detection GPIO pin.
 */
void SDMMC_CardDetect_Init(void)
{
    __HAL_RCC_GPIOG_CLK_ENABLE();
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    GPIO_InitStruct.Pin = SDMMC_DET_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    HAL_GPIO_Init(SDMMC_DET_GPIO, &GPIO_InitStruct);
    sdmmc_delay_ms(5);
}

/**
 * @brief Checks whether an SD card is inserted.
 */
bool SDMMC_IsCardInserted(void)
{
    return (HAL_GPIO_ReadPin(SDMMC_DET_GPIO, SDMMC_DET_PIN) == GPIO_PIN_RESET);
}

/**
 * @brief Initializes the SDMMC1 peripheral and clears pending status flags.
 */
void SDMMC_PeripheralInit(void)
{
    RCC->APB2ENR |= (1UL << 11);
    volatile uint32_t dummy = RCC->APB2ENR;
    (void)dummy;

    RCC->DCKCFGR2 &= ~(1UL << 28);
    RCC->DCKCFGR2 &= ~(1UL << 27);

    SDMMC1->POWER = 0x03;
    sdmmc_delay_ms(5);

    SDMMC1->CLKCR = (118U << 0) | (1U << 8);
    sdmmc_delay_ms(10);

    sdmmc_clear_flags();
}

/**
 * @brief Sets the SDMMC1 clock divider.
 */
void SDMMC_SetClockDiv(uint8_t div)
{
    uint32_t clkcr = SDMMC1->CLKCR;
    clkcr &= ~(0xFFU);
    clkcr |= (uint32_t)div;
    SDMMC1->CLKCR = clkcr;
}

/**
 * @brief Sends an SDMMC command and waits for its response.
 */
int SDMMC_SendCmd(uint8_t cmd, uint32_t arg, uint8_t respType)
{
    sdmmc_clear_flags();
    SDMMC1->ARG = arg;

    uint32_t cmd_val = ((uint32_t)cmd & 0x3FU) | ((uint32_t)(respType & 0x03U) << 6) | (1U << 10);

    SDMMC1->CMD = cmd_val;
    return sdmmc_wait_cmd(respType);
}

/**
 * @brief Initializes the SD card and configures its operating parameters.
 */
int SDMMC_CardInit(SD_CardInfo_t *info)
{
    int ret;
    uint32_t response;

    memset(info, 0, sizeof(SD_CardInfo_t));
    info->BlockSize = 512;
    info->BusWidth = 1;

    sdmmc_delay_ms(10);

    ret = SDMMC_SendCmd(SD_CMD0_GO_IDLE_STATE, 0x00000000, SDMMC_RESP_NONE);
    if (ret != SDMMC_OK)
        return ret;
    sdmmc_delay_ms(5);

    SDMMC_SendCmd(SD_CMD0_GO_IDLE_STATE, 0x00000000, SDMMC_RESP_NONE);
    sdmmc_delay_ms(5);

    int cmd8_ok = 0;
    for (int retry = 0; retry < 5; retry++)
    {
        ret = SDMMC_SendCmd(SD_CMD8_SEND_IF_COND, 0x000001AAU, SDMMC_RESP_SHORT);
        if (ret == SDMMC_OK)
        {
            response = SDMMC1->RESP1;
            if ((response & 0x1FFU) == 0x1AAU)
            {
                cmd8_ok = 1;
                info->CardType = SD_CARD_V2_SC;
                break;
            }
        }
        sdmmc_delay_ms(5);
    }

    if (!cmd8_ok)
    {
        if (ret == SDMMC_ERR_CMD_TIMEOUT)
        {
            info->CardType = SD_CARD_V1;
            SDMMC_SendCmd(SD_CMD0_GO_IDLE_STATE, 0x00000000, SDMMC_RESP_NONE);
            sdmmc_delay_ms(5);
        }
        else
        {
            return ret;
        }
    }

    uint32_t acmd41_arg = 0x00FF8000U;
    if (info->CardType != SD_CARD_V1)
        acmd41_arg |= 0x40000000U;

    uint32_t start_tick = HAL_GetTick();
    while (1)
    {
        ret = SDMMC_SendCmd(SD_CMD55_APP_CMD, 0x00000000U, SDMMC_RESP_SHORT);
        if (ret != SDMMC_OK)
            return ret;

        ret = SDMMC_SendCmd(SD_ACMD41_SD_SEND_OP_COND, acmd41_arg, SDMMC_RESP_SHORT);
        if (ret != SDMMC_OK && ret != SDMMC_ERR_CMD_CRC)
            return ret;

        response = SDMMC1->RESP1;
        if (response & 0x80000000U)
        {
            info->OCR = response;
            if ((info->CardType != SD_CARD_V1) && (response & 0x40000000U))
                info->CardType = SD_CARD_V2_HC;
            break;
        }

        if ((HAL_GetTick() - start_tick) > 2000)
            return SDMMC_ERR_TIMEOUT;

        sdmmc_delay_ms(10);
    }

    ret = SDMMC_SendCmd(SD_CMD2_ALL_SEND_CID, 0x00000000U, SDMMC_RESP_LONG);
    if (ret != SDMMC_OK)
        return ret;

    info->CID[0] = SDMMC1->RESP1;
    info->CID[1] = SDMMC1->RESP2;
    info->CID[2] = SDMMC1->RESP3;
    info->CID[3] = SDMMC1->RESP4;

    ret = SDMMC_SendCmd(SD_CMD3_SEND_RELATIVE_ADDR, 0x00000000U, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    info->RCA = (SDMMC1->RESP1 >> 16) & 0xFFFFU;

    ret = SDMMC_ReadCSD(info);
    if (ret != SDMMC_OK)
        return ret;

    SDMMC_ParseCSD(info);

    ret = SDMMC_SendCmd(SD_CMD7_SELECT_CARD, info->RCA << 16, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    ret = SDMMC_SendCmd(SD_CMD16_SET_BLOCKLEN, 512U, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    SDMMC_SetBusWidth4(info);

    SDMMC_SetClockDiv(2);
    sdmmc_delay_ms(2);

    SDMMC1->CLKCR &= ~SDMMC_CLKCR_HWFC_EN;

    return SDMMC_OK;
}

/**
 * @brief Reads the Card-Specific Data (CSD) register from the SD card.
 */
int SDMMC_ReadCSD(SD_CardInfo_t *info)
{
    int ret = SDMMC_SendCmd(SD_CMD9_SEND_CSD, info->RCA << 16, SDMMC_RESP_LONG);
    if (ret != SDMMC_OK)
        return ret;

    info->CSD[0] = SDMMC1->RESP1;
    info->CSD[1] = SDMMC1->RESP2;
    info->CSD[2] = SDMMC1->RESP3;
    info->CSD[3] = SDMMC1->RESP4;

    return SDMMC_OK;
}

/**
 * @brief Reads the Card Identification (CID) register from the SD card.
 */
int SDMMC_ReadCID(SD_CardInfo_t *info)
{
    int ret = SDMMC_SendCmd(SD_CMD10_SEND_CID, info->RCA << 16, SDMMC_RESP_LONG);
    if (ret != SDMMC_OK)
        return ret;

    info->CID[0] = SDMMC1->RESP1;
    info->CID[1] = SDMMC1->RESP2;
    info->CID[2] = SDMMC1->RESP3;
    info->CID[3] = SDMMC1->RESP4;

    return SDMMC_OK;
}

/**
 * @brief Parses the CSD register to determine the card capacity and block count.
 */
void SDMMC_ParseCSD(SD_CardInfo_t *info)
{
    uint8_t csd_structure = (info->CSD[0] >> 30) & 0x03U;

    if (csd_structure == 1)
    {
        uint32_t c_size = ((info->CSD[1] & 0x3FU) << 16) | ((info->CSD[2] >> 16) & 0xFFFFU);
        info->Capacity = (uint64_t)(c_size + 1) * 512ULL * 1024ULL;
        info->BlockSize = 512;
        info->BlockCount = (uint32_t)(info->Capacity / 512ULL);
    }
    else
    {
        uint32_t c_size = ((info->CSD[1] & 0x03FFU) << 2) | ((info->CSD[2] >> 30) & 0x03U);
        uint32_t c_size_mult = (info->CSD[2] >> 15) & 0x07U;
        uint32_t read_bl_len = (info->CSD[1] >> 16) & 0x0FU;

        uint32_t mult = 1U << (c_size_mult + 2);
        uint32_t block_nr = (c_size + 1) * mult;
        uint32_t block_len = 1U << read_bl_len;

        info->Capacity = (uint64_t)block_nr * (uint64_t)block_len;
        info->BlockSize = 512;
        info->BlockCount = (uint32_t)(info->Capacity / 512ULL);
    }
}

/**
 * @brief Configures the SD card and SDMMC peripheral for four-bit bus operation.
 */
int SDMMC_SetBusWidth4(SD_CardInfo_t *info)
{
    int ret;

    ret = SDMMC_SendCmd(SD_CMD55_APP_CMD, info->RCA << 16, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    ret = SDMMC_SendCmd(SD_ACMD6_SET_BUS_WIDTH, 0x00000002U, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    uint32_t clkcr = SDMMC1->CLKCR;
    clkcr &= ~SDMMC_CLKCR_WIDBUS;
    clkcr |= (1U << 11);
    SDMMC1->CLKCR = clkcr;

    info->BusWidth = 4;
    sdmmc_delay_ms(2);

    return SDMMC_OK;
}

/**
 * @brief Configures the SD card and SDMMC peripheral for one-bit bus operation.
 */
int SDMMC_SetBusWidth1(SD_CardInfo_t *info)
{
    int ret;

    ret = SDMMC_SendCmd(SD_CMD55_APP_CMD, info->RCA << 16, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    ret = SDMMC_SendCmd(SD_ACMD6_SET_BUS_WIDTH, 0x00000000U, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    uint32_t clkcr = SDMMC1->CLKCR;
    clkcr &= ~SDMMC_CLKCR_WIDBUS;
    SDMMC1->CLKCR = clkcr;

    info->BusWidth = 1;
    sdmmc_delay_ms(2);

    return SDMMC_OK;
}

/**
 * @brief Retrieves the current status of the SD card.
 */
int SDMMC_GetCardStatus(SD_CardInfo_t *info, uint32_t *status)
{
    int ret = SDMMC_SendCmd(SD_CMD13_SEND_STATUS, info->RCA << 16, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;
    *status = SDMMC1->RESP1;
    return SDMMC_OK;
}

/**
 * @brief Waits until the SD card enters the transfer state or the timeout expires.
 */
static int sdmmc_wait_card_ready(SD_CardInfo_t *info, uint32_t timeout_ms)
{
    uint32_t start = HAL_GetTick();
    uint32_t status;
    while (1)
    {
        int ret = SDMMC_GetCardStatus(info, &status);
        if (ret == SDMMC_OK)
        {
            uint8_t card_state = (status >> 9) & 0x0FU;
            if (card_state == 4)
                return SDMMC_OK;
            if (card_state == 6 || card_state == 5)
            {
                SDMMC_SendCmd(SD_CMD12_STOP_TRANSMISSION, 0, SDMMC_RESP_SHORT);
            }
        }
        else if (ret != SDMMC_ERR_CMD_TIMEOUT)
        {
            return ret;
        }

        if ((HAL_GetTick() - start) > timeout_ms)
            return (ret == SDMMC_OK) ? SDMMC_ERR_BUSY : ret;

        sdmmc_delay_ms(1);
    }
}

/**
 * @brief Reads a single 512-byte block from the SD card.
 */
static int sdmmc_read_block_single(SD_CardInfo_t *info, uint32_t block, uint8_t *buf)
{
    int ret;
    uint32_t addr;
    uint32_t sta;

    if (info->CardType == SD_CARD_V2_HC)
        addr = block;
    else
        addr = block * 512U;

    ret = sdmmc_wait_card_ready(info, 1000);
    if (ret != SDMMC_OK)
    {
        sdmmc_increment(&s_diagnostics.card_ready_timeouts);
        return ret;
    }

    sdmmc_clear_flags();

    SDMMC1->DTIMER = 0x01000000U;
    SDMMC1->DLEN = 512U;
    SDMMC1->DCTRL = (9U << 4) | (1U << 1) | (1U << 0);

    ret = SDMMC_SendCmd(SD_CMD17_READ_SINGLE_BLOCK, addr, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
        return ret;

    uint32_t count = 0;
    uint32_t *buf32 = (uint32_t *)buf;
    uint32_t start_tick = HAL_GetTick();

    while (count < 128)
    {
        sta = SDMMC1->STA;

        if (sta & SDMMC_STA_RXFIFOHF)
        {
            for (int i = 0; i < 8 && count < 128; i++)
            {
                buf32[count++] = SDMMC1->FIFO;
            }
        }

        if (sta & (SDMMC_STA_DTIMEOUT | SDMMC_STA_RXOVERR | SDMMC_STA_DCRCFAIL))
        {
            s_last_sta = sta;
            sdmmc_clear_flags();
            SDMMC1->DCTRL = 0;

            if (sta & SDMMC_STA_DTIMEOUT)
                return SDMMC_ERR_DATA_TIMEOUT;
            if (sta & SDMMC_STA_RXOVERR)
                return SDMMC_ERR_RX_OVERRUN;
            return SDMMC_ERR_DATA_CRC;
        }

        if (sta & SDMMC_STA_DATAEND)
            break;

        if ((HAL_GetTick() - start_tick) > 4000U)
        {
            s_last_sta = sta;
            sdmmc_clear_flags();
            SDMMC1->DCTRL = 0;
            return SDMMC_ERR_TIMEOUT;
        }
    }

    while ((SDMMC1->STA & SDMMC_STA_RXDAVL) && count < 128)
    {
        buf32[count++] = SDMMC1->FIFO;
    }
    g_last_read_count = count;

    while (1)
    {
        sta = SDMMC1->STA;
        if (sta & (SDMMC_STA_DATAEND | SDMMC_STA_DCRCFAIL | SDMMC_STA_DTIMEOUT | SDMMC_STA_RXOVERR))
        {
            s_last_sta = sta;
            if (sta & SDMMC_STA_DTIMEOUT)
                break;
            if (sta & SDMMC_STA_DCRCFAIL)
                break;
            if (sta & SDMMC_STA_RXOVERR)
                break;
            break;
        }
        if ((HAL_GetTick() - start_tick) > 4000U)
        {
            s_last_sta = sta;
            sdmmc_clear_flags();
            SDMMC1->DCTRL = 0;
            return SDMMC_ERR_TIMEOUT;
        }
    }

    s_last_sta = SDMMC1->STA;
    sdmmc_clear_flags();
    SDMMC1->DCTRL = 0;

    if (sta & SDMMC_STA_DTIMEOUT)
        return SDMMC_ERR_DATA_TIMEOUT;
    if (sta & SDMMC_STA_DCRCFAIL)
        return SDMMC_ERR_DATA_CRC;
    if (sta & SDMMC_STA_RXOVERR)
        return SDMMC_ERR_RX_OVERRUN;

    if (count < 128)
        return SDMMC_ERR_GENERAL;

    sdmmc_delay_ms(2);
    return SDMMC_OK;
}

/**
 * @brief Reads a single block with retries on failure.
 */
int SDMMC_ReadBlock(SD_CardInfo_t *info, uint32_t block, uint8_t *buf)
{
    int ret = SDMMC_OK;
    for (int retry = 0; retry < 3; retry++)
    {
        ret = sdmmc_read_block_single(info, block, buf);
        if (ret == SDMMC_OK)
            return SDMMC_OK;

        if (ret == SDMMC_ERR_TIMEOUT || ret == SDMMC_ERR_CMD_TIMEOUT || ret == SDMMC_ERR_DATA_TIMEOUT)
            sdmmc_increment(&s_diagnostics.timeouts);

        SDMMC1->DCTRL = 0;
        sdmmc_clear_flags();
        sdmmc_delay_ms(5);
        sdmmc_wait_card_ready(info, 500);
    }
    sdmmc_increment(&s_diagnostics.read_failures);
    return ret;
}

/**
 * @brief Reads multiple consecutive blocks from the SD card.
 */

int SDMMC_ReadBlocks(SD_CardInfo_t *info, uint32_t block, uint8_t *buf, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
    {
        int ret = SDMMC_ReadBlock(info, block + i, buf + (i * 512));
        if (ret != SDMMC_OK)
            return ret;
    }
    return SDMMC_OK;
}

/**
 * @brief Writes a single 512-byte block to the SD card.
 */
static int sdmmc_write_block_single(SD_CardInfo_t *info, uint32_t block, const uint8_t *buf)
{
    int ret;
    uint32_t addr;
    uint32_t sta;

    if (info->CardType == SD_CARD_V2_HC)
        addr = block;
    else
        addr = block * 512U;

    ret = sdmmc_wait_card_ready(info, 1000);
    if (ret != SDMMC_OK)
    {
        sdmmc_increment(&s_diagnostics.card_ready_timeouts);
        return ret;
    }

    sdmmc_clear_flags();

    SDMMC1->DTIMER = 0x01000000U;
    SDMMC1->DLEN = 512U;
    SDMMC1->DCTRL = (9U << 4) | (0U << 1) | (1U << 0);

    ret = SDMMC_SendCmd(SD_CMD24_WRITE_BLOCK, addr, SDMMC_RESP_SHORT);
    if (ret != SDMMC_OK)
    {
        SDMMC1->DCTRL = 0;
        sdmmc_clear_flags();
        return ret;
    }

    if (SDMMC1->RESP1 & 0xFDFFE008U)
    {
        SDMMC1->DCTRL = 0;
        sdmmc_clear_flags();
        return SDMMC_ERR_WRITE_FAIL;
    }

    const uint32_t *buf32 = (const uint32_t *)buf;
    uint32_t count = 0;
    uint32_t start_tick = HAL_GetTick();

    while (count < 128)
    {
        sta = SDMMC1->STA;
        if (sta & (SDMMC_STA_TXUNDERR | SDMMC_STA_DCRCFAIL | SDMMC_STA_DTIMEOUT))
            break;

        if ((HAL_GetTick() - start_tick) > 4000U)
            break;

        if (sta & (SDMMC_STA_TXFIFOHE | SDMMC_STA_TXFIFOE))
        {
            uint32_t primask = __get_PRIMASK();
            __disable_irq();
            uint32_t burst_start = RunTimeStats_GetCount();
            for (int i = 0; i < 8 && count < 128; i++)
            {
                SDMMC1->FIFO = buf32[count++];
            }
            sdmmc_record_irq_off(burst_start, RunTimeStats_GetCount());
            __set_PRIMASK(primask);
        }
    }

    while (!(SDMMC1->STA & (SDMMC_STA_DATAEND | SDMMC_STA_DBCKEND | SDMMC_STA_DCRCFAIL | SDMMC_STA_DTIMEOUT | SDMMC_STA_TXUNDERR)))
    {
        if ((HAL_GetTick() - start_tick) > 4000)
            break;
    }

    sta = SDMMC1->STA;
    s_last_sta = sta;
    sdmmc_clear_flags();
    SDMMC1->DCTRL = 0;

    if (sta & SDMMC_STA_DTIMEOUT)
        return SDMMC_ERR_DATA_TIMEOUT;
    if (sta & SDMMC_STA_DCRCFAIL)
        return SDMMC_ERR_DATA_CRC;
    if (sta & SDMMC_STA_TXUNDERR)
        return SDMMC_ERR_TX_UNDERRUN;
    if (count != 128)
        return SDMMC_ERR_TIMEOUT;
    if (!(sta & (SDMMC_STA_DBCKEND | SDMMC_STA_DATAEND)))
        return SDMMC_ERR_TIMEOUT;

    ret = sdmmc_wait_card_ready(info, 5000);
    if (ret != SDMMC_OK)
    {
        sdmmc_increment(&s_diagnostics.card_ready_timeouts);
        return SDMMC_ERR_WRITE_FAIL;
    }

    sdmmc_delay_ms(1);
    return SDMMC_OK;
}

/**
 * @brief Writes a single block with retries on failure.
 */
int SDMMC_WriteBlock(SD_CardInfo_t *info, uint32_t block, const uint8_t *buf)
{
    int ret = SDMMC_OK;
    uint32_t start = HAL_GetTick();
    for (int retry = 0; retry < 3; retry++)
    {
        if (retry != 0)
            sdmmc_increment(&s_diagnostics.write_retries);
        ret = sdmmc_write_block_single(info, block, buf);
        if (ret == SDMMC_OK)
        {
            if (retry != 0)
                sdmmc_increment(&s_diagnostics.write_recovered);
            break;
        }

        if (ret == SDMMC_ERR_TIMEOUT || ret == SDMMC_ERR_CMD_TIMEOUT || ret == SDMMC_ERR_DATA_TIMEOUT)
            sdmmc_increment(&s_diagnostics.timeouts);

        SDMMC1->DCTRL = 0;
        sdmmc_clear_flags();
        sdmmc_delay_ms(5);
        sdmmc_wait_card_ready(info, 500);
    }
    if (ret != SDMMC_OK)
        sdmmc_increment(&s_diagnostics.write_failures);
    uint32_t elapsed = HAL_GetTick() - start;
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    if (elapsed > s_diagnostics.max_write_ms)
        s_diagnostics.max_write_ms = elapsed;
    __set_PRIMASK(primask);
    return ret;
}

/**
 * @brief Writes multiple consecutive blocks to the SD card.
 */
int SDMMC_WriteBlocks(SD_CardInfo_t *info, uint32_t block, const uint8_t *buf, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
    {
        int ret = SDMMC_WriteBlock(info, block + i, buf + (i * 512));
        if (ret != SDMMC_OK)
            return ret;
    }
    return SDMMC_OK;
}

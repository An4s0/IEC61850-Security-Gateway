/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file    user_diskio.c
 * @brief   FatFs diskio driver implementation for SDMMC1 using proven
 *          register-level SDMMC driver (4-bit mode, alignment-safe).
 ******************************************************************************
 */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "ff_gen_drv.h"
#include "user_diskio.h"
#include "main.h"
#include "sdmmc.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* MMC card type flags */
#define CT_MMC   0x01
#define CT_SD1   0x02
#define CT_SD2   0x04
#define CT_SDC   (CT_SD1 | CT_SD2)
#define CT_BLOCK 0x08

/* Private variables ---------------------------------------------------------*/
static volatile DSTATUS Stat = STA_NOINIT;
static SD_CardInfo_t s_sd_card_info;

/* Prototype of diskio functions */
DSTATUS USER_initialize (BYTE pdrv);
DSTATUS USER_status (BYTE pdrv);
DRESULT USER_read (BYTE pdrv, BYTE *buff, DWORD sector, UINT count);
#if _USE_WRITE == 1
DRESULT USER_write (BYTE pdrv, const BYTE *buff, DWORD sector, UINT count);
#endif /* _USE_WRITE == 1 */
#if _USE_IOCTL == 1
DRESULT USER_ioctl (BYTE pdrv, BYTE cmd, void *buff);
#endif /* _USE_IOCTL == 1 */

Diskio_drvTypeDef USER_Driver =
{
  USER_initialize,
  USER_status,
  USER_read,
#if _USE_WRITE == 1
  USER_write,
#endif /* _USE_WRITE == 1 */
#if _USE_IOCTL == 1
  USER_ioctl,
#endif /* _USE_IOCTL == 1 */
};

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initializes a Drive over SDMMC1 in 4-bit mode
  * @param  pdrv: Physical drive number (0..)
  * @retval DSTATUS: Operation status
  */
DSTATUS USER_initialize(BYTE pdrv)
{
  if (pdrv != 0)
  {
    return STA_NOINIT;
  }

  /* If card is already initialized and responsive, keep it */
  if (!(Stat & STA_NOINIT) && s_sd_card_info.RCA != 0)
  {
    uint32_t card_status;
    if (SDMMC_GetCardStatus(&s_sd_card_info, &card_status) == SDMMC_OK)
    {
      return Stat;
    }
  }

  /* Initialize SDMMC GPIO pins and peripheral clock */
  SDMMC_GPIO_Init();
  SDMMC_PeripheralInit();

  /* Perform full card initialization sequence */
  int ret = SDMMC_CardInit(&s_sd_card_info);
  if (ret != SDMMC_OK)
  {
    Stat = STA_NOINIT;
    return Stat;
  }

  /* Try to switch to 4-bit bus mode (preferred for throughput) */
  ret = SDMMC_SetBusWidth4(&s_sd_card_info);
  if (ret != SDMMC_OK)
  {
    SDMMC_SetBusWidth1(&s_sd_card_info);
  }

  /* Switch to normal operational clock: div=2 (12MHz) */
  SDMMC_SetClockDiv(2);

  Stat &= ~STA_NOINIT;
  return Stat;
}

/**
  * @brief  Gets Disk Status
  * @param  pdrv: Physical drive number (0..)
  * @retval DSTATUS: Operation status
  */
DSTATUS USER_status(BYTE pdrv)
{
  if (pdrv != 0)
  {
    return STA_NOINIT;
  }

  return Stat;
}

/**
  * @brief  Reads Sector(s) from SD card over SDMMC1
  * @param  pdrv: Physical drive number (0..)
  * @param  *buff: Data buffer to store read data
  * @param  sector: Sector address (LBA)
  * @param  count: Number of sectors to read
  * @retval DRESULT: Operation result
  */
DRESULT USER_read(BYTE pdrv, BYTE *buff, DWORD sector, UINT count)
{
  if (pdrv != 0 || buff == NULL || count == 0)
  {
    return RES_PARERR;
  }

  if (Stat & STA_NOINIT)
  {
    if (USER_initialize(pdrv) & STA_NOINIT)
    {
      return RES_NOTRDY;
    }
  }

  for (UINT i = 0; i < count; i++)
  {
    uint8_t *dst = buff + (i * 512);

    /* Guard against unaligned buffer pointers */
    if (((uintptr_t)dst & 3) == 0)
    {
      int ret = SDMMC_ReadBlock(&s_sd_card_info, (uint32_t)(sector + i), dst);
      if (ret != SDMMC_OK)
      {
        return RES_ERROR;
      }
    }
    else
    {
      uint32_t temp_buf[128];
      int ret = SDMMC_ReadBlock(&s_sd_card_info, (uint32_t)(sector + i), (uint8_t *)temp_buf);
      if (ret != SDMMC_OK)
      {
        return RES_ERROR;
      }
      memcpy(dst, temp_buf, 512);
    }
  }

  return RES_OK;
}

/**
  * @brief  Writes Sector(s) to SD card over SDMMC1
  * @param  pdrv: Physical drive number (0..)
  * @param  *buff: Data to be written
  * @param  sector: Sector address (LBA)
  * @param  count: Number of sectors to write
  * @retval DRESULT: Operation result
  */
#if _USE_WRITE == 1
DRESULT USER_write(BYTE pdrv, const BYTE *buff, DWORD sector, UINT count)
{
  if (pdrv != 0 || buff == NULL || count == 0)
  {
    return RES_PARERR;
  }

  if (Stat & STA_NOINIT)
  {
    if (USER_initialize(pdrv) & STA_NOINIT)
    {
      return RES_NOTRDY;
    }
  }

  for (UINT i = 0; i < count; i++)
  {
    const uint8_t *src = buff + (i * 512);

    /* Guard against unaligned buffer pointers */
    if (((uintptr_t)src & 3) == 0)
    {
      int ret = SDMMC_WriteBlock(&s_sd_card_info, (uint32_t)(sector + i), src);
      if (ret != SDMMC_OK)
      {
        return RES_ERROR;
      }
    }
    else
    {
      uint32_t temp_buf[128];
      memcpy(temp_buf, src, 512);
      int ret = SDMMC_WriteBlock(&s_sd_card_info, (uint32_t)(sector + i), (const uint8_t *)temp_buf);
      if (ret != SDMMC_OK)
      {
        return RES_ERROR;
      }
    }
  }

  return RES_OK;
}
#endif /* _USE_WRITE == 1 */

/**
  * @brief  I/O control operation
  * @param  pdrv: Physical drive number (0..)
  * @param  cmd: Control code
  * @param  *buff: Buffer to send/receive control data
  * @retval DRESULT: Operation result
  */
#if _USE_IOCTL == 1
DRESULT USER_ioctl(BYTE pdrv, BYTE cmd, void *buff)
{
  if (pdrv != 0)
  {
    return RES_PARERR;
  }

  if (Stat & STA_NOINIT)
  {
    if (USER_initialize(pdrv) & STA_NOINIT)
    {
      return RES_NOTRDY;
    }
  }

  switch (cmd)
  {
  case CTRL_SYNC:
    return RES_OK;

  case GET_SECTOR_COUNT:
    if (buff == NULL)
    {
      return RES_PARERR;
    }
    *(DWORD *)buff = s_sd_card_info.BlockCount;
    return RES_OK;

  case GET_SECTOR_SIZE:
    if (buff == NULL)
    {
      return RES_PARERR;
    }
    *(WORD *)buff = 512;
    return RES_OK;

  case GET_BLOCK_SIZE:
    if (buff == NULL)
    {
      return RES_PARERR;
    }
    *(DWORD *)buff = 1;
    return RES_OK;

  case CTRL_TRIM:
    return RES_OK;

  case MMC_GET_TYPE:
    if (buff == NULL)
    {
      return RES_PARERR;
    }
    *(BYTE *)buff = (s_sd_card_info.CardType == SD_CARD_V2_HC) ? (CT_SD2 | CT_BLOCK) : CT_SD2;
    return RES_OK;

  case MMC_GET_CSD:
    if (buff == NULL)
    {
      return RES_PARERR;
    }
    memcpy(buff, s_sd_card_info.CSD, 16);
    return RES_OK;

  case MMC_GET_CID:
    if (buff == NULL)
    {
      return RES_PARERR;
    }
    memcpy(buff, s_sd_card_info.CID, 16);
    return RES_OK;

  default:
    return RES_PARERR;
  }
}
#endif /* _USE_IOCTL == 1 */

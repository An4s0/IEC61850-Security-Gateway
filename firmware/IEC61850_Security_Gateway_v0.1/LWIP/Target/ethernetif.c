/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * File Name          : ethernetif.c
 * Description        : This file provides code for the configuration
 *                      of the ethernetif.c MiddleWare.
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "lwip/opt.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"
#include "ethernetif.h"
#include "lan8742.h"
#include <string.h>
#include "cmsis_os.h"
#include "lwip/tcpip.h"

/* Within 'USER CODE' section, code will be kept by default at each generation */
/* USER CODE BEGIN 0 */
#include "raw_eth.h"
#include "runtime_stats.h"
#include "http_api.h"
#include "health_monitor.h"
#include "system_logger.h"

/* USER CODE END 0 */

/* Private define ------------------------------------------------------------*/
/* The time to block waiting for input. */
#define TIME_WAITING_FOR_INPUT (HEALTH_BEAT_PERIOD_MS)
/* Time to block waiting for transmissions to finish */
#define ETHIF_TX_TIMEOUT (2000U)
/* USER CODE BEGIN OS_THREAD_STACK_SIZE_WITH_RTOS */
/* Stack size of the interface thread */
#define INTERFACE_THREAD_STACK_SIZE (350)
/* USER CODE END OS_THREAD_STACK_SIZE_WITH_RTOS */
/* Network interface name */
#define IFNAME0 's'
#define IFNAME1 't'

/* ETH Setting  */
#define ETH_DMA_TRANSMIT_TIMEOUT (20U)
#define ETH_TX_BUFFER_MAX ((ETH_TX_DESC_CNT) * 2U)

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

/* Private variables ---------------------------------------------------------*/
/*
@Note: This interface is implemented to operate in zero-copy mode only:
        - Rx Buffers will be allocated from LwIP stack Rx memory pool,
          then passed to ETH HAL driver.
        - Tx Buffers will be allocated from LwIP stack memory heap,
          then passed to ETH HAL driver.

@Notes:
  1.a. ETH DMA Rx descriptors must be contiguous, the default count is 4,
       to customize it please redefine ETH_RX_DESC_CNT in ETH GUI (Rx Descriptor Length)
       so that updated value will be generated in stm32xxxx_hal_conf.h
  1.b. ETH DMA Tx descriptors must be contiguous, the default count is 4,
       to customize it please redefine ETH_TX_DESC_CNT in ETH GUI (Tx Descriptor Length)
       so that updated value will be generated in stm32xxxx_hal_conf.h

  2.a. Rx Buffers number must be between ETH_RX_DESC_CNT and 2*ETH_RX_DESC_CNT
  2.b. Rx Buffers must have the same size: ETH_RX_BUF_SIZE, this value must
       passed to ETH DMA in the init field (heth.Init.RxBuffLen)
  2.c  The RX Ruffers addresses and sizes must be properly defined to be aligned
       to L1-CACHE line size (32 bytes).
*/

/* Data Type Definitions */
typedef enum
{
  RX_ALLOC_OK = 0x00,
  RX_ALLOC_ERROR = 0x01
} RxAllocStatusTypeDef;

typedef struct
{
  struct pbuf_custom pbuf_custom;
  uint8_t buff[(ETH_RX_BUF_SIZE + 31) & ~31] __ALIGNED(32);
} RxBuff_t;

/* Memory Pool Declaration */
#define ETH_RX_BUFFER_CNT 12U
LWIP_MEMPOOL_DECLARE(RX_POOL, ETH_RX_BUFFER_CNT, sizeof(RxBuff_t), "Zero-copy RX PBUF pool");

/* Variable Definitions */
static uint8_t RxAllocStatus;

#if defined(__ICCARM__) /*!< IAR Compiler */

#pragma location = 0x2007c000
ETH_DMADescTypeDef DMARxDscrTab[ETH_RX_DESC_CNT]; /* Ethernet Rx DMA Descriptors */
#pragma location = 0x2007c0a0
ETH_DMADescTypeDef DMATxDscrTab[ETH_TX_DESC_CNT]; /* Ethernet Tx DMA Descriptors */

#elif defined(__CC_ARM) /* MDK ARM Compiler */

__attribute__((at(0x2007c000))) ETH_DMADescTypeDef DMARxDscrTab[ETH_RX_DESC_CNT]; /* Ethernet Rx DMA Descriptors */
__attribute__((at(0x2007c0a0))) ETH_DMADescTypeDef DMATxDscrTab[ETH_TX_DESC_CNT]; /* Ethernet Tx DMA Descriptors */

#elif defined(__GNUC__) /* GNU Compiler */

ETH_DMADescTypeDef DMARxDscrTab[ETH_RX_DESC_CNT] __attribute__((section(".RxDescripSection"))); /* Ethernet Rx DMA Descriptors */
ETH_DMADescTypeDef DMATxDscrTab[ETH_TX_DESC_CNT] __attribute__((section(".TxDescripSection"))); /* Ethernet Tx DMA Descriptors */

#endif

/* USER CODE BEGIN 2 */
static volatile Ethernet_Diagnostics_t s_eth_diagnostics;

#define ETH_DIAG_INC(field)                    \
  do                                           \
  {                                            \
    if (s_eth_diagnostics.field != UINT32_MAX) \
      s_eth_diagnostics.field++;               \
  } while (0)

static uint32_t EthDiag_IcmpChecksum(const uint8_t *frame, uint32_t ip_total_len)
{
  const uint8_t *icmp = frame + 14U + 20U;
  uint32_t nbytes;
  uint32_t sum = 0U;

  if (ip_total_len <= 20U)
  {
    return 0xFFFFU;
  }
  nbytes = ip_total_len - 20U;

  while (nbytes > 1U)
  {
    sum += ((uint32_t)icmp[0] << 8) | (uint32_t)icmp[1];
    icmp += 2;
    nbytes -= 2U;
  }
  if (nbytes != 0U)
  {
    sum += (uint32_t)icmp[0] << 8;
  }
  while ((sum >> 16) != 0U)
  {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return (~sum) & 0xFFFFU;
}

#define ETH_MAC_RX_FIFO_SIZE 1024U

/*
 * Returns the frame size declared by the frame's own protocol header, or 0 when
 * the frame carries no length that can be trusted.
 *
 * Sources used, all inside the bytes the DMA already delivered:
 *   IPv4   - total length field
 *   IPv6   - payload length field (+40 byte header)
 *   GOOSE  0x88B8 / SV 0x88BA - the second 16-bit field of the IEC 61850
 *            header. This firmware and its simulator use it as the total
 *            message length (header included, parser: pdu_len = length - 8);
 *            the standards-compliant variant that excludes the 8-byte header is
 *            accepted as well, because both are checked against the descriptor
 *            length and only an exact one-byte match is ever used.
 */
static uint32_t EthRx_DeclaredFrameLength(const uint8_t *hdr, uint32_t avail, uint32_t tot_len)
{
  uint32_t off = 14U;
  uint32_t etype;

  if (avail < 18U)
  {
    return 0U;
  }

  etype = ((uint32_t)hdr[12] << 8) | (uint32_t)hdr[13];
  if ((etype == 0x8100U) || (etype == 0x88A8U))
  {
    if (avail < 22U)
    {
      return 0U;
    }
    off = 18U;
    etype = ((uint32_t)hdr[16] << 8) | (uint32_t)hdr[17];
  }

  if (etype == 0x0800U)
  {
    if ((avail < (off + 4U)) || ((hdr[off] >> 4) != 4U))
    {
      return 0U;
    }
    return off + (((uint32_t)hdr[off + 2] << 8) | (uint32_t)hdr[off + 3]);
  }

  if (etype == 0x86DDU)
  {
    if (avail < (off + 6U))
    {
      return 0U;
    }
    return off + 40U + (((uint32_t)hdr[off + 4] << 8) | (uint32_t)hdr[off + 5]);
  }

  if ((etype == 0x88B8U) || (etype == 0x88BAU))
  {
    uint32_t msg_len;

    if (avail < (off + 8U))
    {
      return 0U;
    }
    msg_len = ((uint32_t)hdr[off + 2] << 8) | (uint32_t)hdr[off + 3];
    if (msg_len < 8U)
    {
      return 0U;
    }
    if ((off + msg_len) == (tot_len + 1U))
    {
      return off + msg_len;
    }
    if ((off + 8U + msg_len) == (tot_len + 1U))
    {
      return off + 8U + msg_len;
    }
  }

  return 0U;
}

static uint32_t EthDma_CorrectRxLength(struct pbuf *p)
{
  uint8_t hdr[54];
  uint32_t avail;
  uint32_t declared;

  if ((p == NULL) || (p->next != NULL))
  {
    return 0U;
  }

  avail = pbuf_copy_partial(p, hdr, sizeof(hdr), 0U);
  declared = EthRx_DeclaredFrameLength(hdr, avail, p->tot_len);
  if (declared == 0U)
  {
    if (p->tot_len > ETH_MAC_RX_FIFO_SIZE)
    {
      ETH_DIAG_INC(rx_len_unverifiable);
    }
    return 0U;
  }

  if ((declared == (p->tot_len + 1U)) && (declared <= (uint32_t)ETH_RX_BUF_SIZE))
  {
    p->len++;
    p->tot_len++;
    return 1U;
  }
  return 0U;
}

/*
 * DMA-reachable RAM on STM32F767ZI: SRAM1 0x20020000-0x2007BFFF and
 * SRAM2 0x2007C000-0x2007FFFF. DTCM (0x20000000-0x2001FFFF) is not reachable
 * by the Ethernet DMA, and the linker RAM region starts inside DTCM.
 */
#define ETH_DMA_RAM_START 0x20020000UL
#define ETH_DMA_RAM_END 0x20080000UL

static bool EthDma_IsAccessible(uint32_t addr, uint32_t size)
{
  if (size == 0U || addr < ETH_DMA_RAM_START)
  {
    return false;
  }
  return (addr + size - 1U) < ETH_DMA_RAM_END;
}

extern uint8_t memp_memory_RX_POOL_base[];

#define RX_LAT_BUCKETS 4
static const uint32_t s_rx_lat_bucket_us[RX_LAT_BUCKETS] = {100U, 500U, 1000U, 5000U};

typedef struct
{
  uint32_t min;
  uint32_t max;
  uint64_t sum;
  uint32_t count;
  uint32_t over[RX_LAT_BUCKETS];
} rx_latency_t;

static volatile uint32_t s_rx_isr_cnt;
static volatile uint8_t s_rx_isr_valid;
static rx_latency_t s_rx_irq_to_task;
static rx_latency_t s_rx_process;

static void rx_latency_record(rx_latency_t *acc, uint32_t us)
{
  if (acc->count == 0U || us < acc->min)
  {
    acc->min = us;
  }
  if (us > acc->max)
  {
    acc->max = us;
  }
  acc->sum += us;
  if (acc->count != UINT32_MAX)
  {
    acc->count++;
  }
  for (uint32_t i = 0U; i < RX_LAT_BUCKETS; i++)
  {
    if (us > s_rx_lat_bucket_us[i] && acc->over[i] != UINT32_MAX)
    {
      acc->over[i]++;
    }
  }
}

/* USER CODE END 2 */

osSemaphoreId RxPktSemaphore = NULL; /* Semaphore to signal incoming packets */
osSemaphoreId TxPktSemaphore = NULL; /* Semaphore to signal transmit packet complete */

/* Global Ethernet handle */
ETH_HandleTypeDef heth;

/**
 * @brief Selects RX FIFO threshold mode (RSF = 0) so frames larger than the
 *        1024-byte MAC RX FIFO can be received.
 *        The DMA receive path must be stopped (DMAOMR.ST = 0).
 */
static void EthDma_SelectRxThresholdMode(void)
{
  CLEAR_BIT(heth.Instance->DMAOMR, ETH_DMAOMR_RSF);
}

ETH_TxPacketConfig TxConfig;
extern struct netif gnetif;
static volatile uint8_t s_eth_good_pkt_received = 0;
/* Local, unsynchronised MAC timestamp counter; one count per HCLK cycle. */
static bool s_rx_clock_ready = false;

/* Private function prototypes -----------------------------------------------*/
static void ethernetif_input(void const *argument);
static void RMII_Thread(void const *argument);
int32_t ETH_PHY_IO_Init(void);
int32_t ETH_PHY_IO_DeInit(void);
int32_t ETH_PHY_IO_ReadReg(uint32_t DevAddr, uint32_t RegAddr, uint32_t *pRegVal);
int32_t ETH_PHY_IO_WriteReg(uint32_t DevAddr, uint32_t RegAddr, uint32_t RegVal);
int32_t ETH_PHY_IO_GetTick(void);

lan8742_Object_t LAN8742;
lan8742_IOCtx_t LAN8742_IOCtx = {ETH_PHY_IO_Init,
                                 ETH_PHY_IO_DeInit,
                                 ETH_PHY_IO_WriteReg,
                                 ETH_PHY_IO_ReadReg,
                                 ETH_PHY_IO_GetTick};

/* USER CODE BEGIN 3 */

/* USER CODE END 3 */

/* Private functions ---------------------------------------------------------*/
void pbuf_free_custom(struct pbuf *p);

/**
 * @brief  Ethernet Rx Transfer completed callback
 * @param  handlerEth: ETH handler
 * @retval None
 */
void HAL_ETH_RxCpltCallback(ETH_HandleTypeDef *handlerEth)
{
  /* Timestamp in the ISR so the scheduled wake-up latency can be measured. */
  s_rx_isr_cnt = RunTimeStats_GetCount();
  s_rx_isr_valid = 1U;
  osSemaphoreRelease(RxPktSemaphore);
}
/**
 * @brief  Ethernet Tx Transfer completed callback
 * @param  handlerEth: ETH handler
 * @retval None
 */
void HAL_ETH_TxCpltCallback(ETH_HandleTypeDef *handlerEth)
{
  osSemaphoreRelease(TxPktSemaphore);
}
/**
 * @brief  Ethernet DMA transfer error callback
 * @param  handlerEth: ETH handler
 * @retval None
 */
void HAL_ETH_ErrorCallback(ETH_HandleTypeDef *handlerEth)
{
  ETH_DIAG_INC(dma_error_callbacks);
  /* Latch the raw DMA status so a drop can be attributed (RU / RWT / FBI / AIS
   * etc.) instead of being silently swallowed. DMASR bits are cleared by the
   * HAL before it calls this callback, so the value is read defensively. */
  s_eth_diagnostics.dmasr = (uint32_t)handlerEth->Instance->DMASR;
  if ((HAL_ETH_GetDMAError(handlerEth) & ETH_DMASR_RBUS) == ETH_DMASR_RBUS)
  {
    ETH_DIAG_INC(rx_buffer_unavailable);
    osSemaphoreRelease(RxPktSemaphore);
  }
}

/* USER CODE BEGIN 4 */
void Ethernet_GetDiagnostics(Ethernet_Diagnostics_t *out)
{
  if (out == NULL)
  {
    return;
  }
  taskENTER_CRITICAL();
  *out = s_eth_diagnostics;
  out->rx_irq_to_task_min_us = s_rx_irq_to_task.count ? s_rx_irq_to_task.min : 0U;
  out->rx_irq_to_task_max_us = s_rx_irq_to_task.max;
  out->rx_irq_to_task_avg_us = s_rx_irq_to_task.count
                                   ? (uint32_t)(s_rx_irq_to_task.sum / s_rx_irq_to_task.count)
                                   : 0U;
  out->rx_irq_to_task_samples = s_rx_irq_to_task.count;
  out->rx_irq_to_task_over_1ms = s_rx_irq_to_task.over[2];
  out->rx_process_min_us = s_rx_process.count ? s_rx_process.min : 0U;
  out->rx_process_max_us = s_rx_process.max;
  out->rx_process_avg_us = s_rx_process.count
                               ? (uint32_t)(s_rx_process.sum / s_rx_process.count)
                               : 0U;
  out->rx_process_samples = s_rx_process.count;
  out->rx_process_over_1ms = s_rx_process.over[2];
  taskEXIT_CRITICAL();
}

static bool RawEth_Input(struct pbuf *p, uint64_t rx_ticks, bool rx_valid)
{
  if (p == NULL)
  {
    return false;
  }

  return RawEth_Process(p, rx_ticks, rx_valid);
}

/* USER CODE END 4 */

/*******************************************************************************
                       LL Driver Interface ( LwIP stack --> ETH)
*******************************************************************************/
/**
 * @brief In this function, the hardware should be initialized.
 * Called from ethernetif_init().
 *
 * @param netif the already initialized lwip network interface structure
 *        for this ethernetif
 */
static void low_level_init(struct netif *netif)
{
  HAL_StatusTypeDef hal_eth_init_status = HAL_OK;
  /* Start ETH HAL Init */

  static uint8_t s_mac_addr[6] = {0x00, 0x80, 0xE1, 0x00, 0x00, 0x00};
  heth.Instance = ETH;
  heth.Init.MACAddr = s_mac_addr;
  heth.Init.MediaInterface = HAL_ETH_RMII_MODE;
  heth.Init.TxDesc = DMATxDscrTab;
  heth.Init.RxDesc = DMARxDscrTab;
  heth.Init.RxBuffLen = 1536;

  /* USER CODE BEGIN MACADDRESS */

  /* USER CODE END MACADDRESS */

  hal_eth_init_status = HAL_ETH_Init(&heth);

  /* The HAL uses enhanced descriptors. Binary rollover with STSSI=1
   * makes the MAC's high/low timestamp a 63-bit HCLK cycle counter. */
  if (hal_eth_init_status == HAL_OK && (heth.Instance->DMABMR & ETH_DMABMR_EDE))
  {
    SET_BIT(heth.Instance->MACIMR, ETH_MACIMR_TSTIM);
    heth.Instance->PTPTSCR = ETH_PTPTSCR_TSE | ETH_PTPTSCR_TSSARFE;
    heth.Instance->PTPSSIR = 1U;
    heth.Instance->PTPTSHUR = 0U;
    heth.Instance->PTPTSLUR = 0U;
    SET_BIT(heth.Instance->PTPTSCR, ETH_PTPTSCR_TSSTI);
    uint32_t timeout = 1000000U;
    while ((heth.Instance->PTPTSCR & ETH_PTPTSCR_TSSTI) && --timeout)
    {
    }
    if (timeout != 0U)
    {
      uint32_t initial = heth.Instance->PTPTSLR;
      uint32_t running_timeout = 1000000U;
      while (heth.Instance->PTPTSLR == initial && --running_timeout)
      {
      }
      s_rx_clock_ready = running_timeout != 0U;
    }
  }

  /* USER CODE BEGIN ETH_MAC_FILTER */
  ETH_MACFilterConfigTypeDef FilterConfig = {0};

  FilterConfig.PromiscuousMode = ENABLE;
  FilterConfig.ReceiveAllMode = ENABLE;

  if (HAL_ETH_SetMACFilterConfig(&heth, &FilterConfig) != HAL_OK)
  {
    Error_Handler();
  }

  /* USER CODE END ETH_MAC_FILTER */

  memset(&TxConfig, 0, sizeof(ETH_TxPacketConfig));
  TxConfig.Attributes = ETH_TX_PACKETS_FEATURES_CSUM | ETH_TX_PACKETS_FEATURES_CRCPAD;
  TxConfig.ChecksumCtrl = ETH_CHECKSUM_IPHDR_PAYLOAD_INSERT_PHDR_CALC;
  TxConfig.CRCPadCtrl = ETH_CRC_PAD_INSERT;

  /* End ETH HAL Init */

  /* Initialize the RX POOL */
  LWIP_MEMPOOL_INIT(RX_POOL);

  /* USER CODE BEGIN DMA_REGION_CHECK */
  /*
   * DMA reachability guard.
   *
   * The Cortex-M7 places its 128 KB DTCM at 0x20000000-0x2001FFFF. Ethernet DMA
   * cannot access DTCM, while the linker `RAM` region starts there, so any
   * static DMA buffer that happens to be linked into the first 128 KB of .bss
   * would receive nothing and corrupt silently. Ethernet RX/TX are the only DMA
   * users in this firmware (SDMMC is polled FIFO, not DMA) and D-Cache is
   * disabled, so the only requirement is placement in SRAM1/SRAM2.
   */
  {
    uintptr_t rx_pool = (uintptr_t)memp_memory_RX_POOL_base;

    if (!EthDma_IsAccessible((uint32_t)DMARxDscrTab, sizeof(DMARxDscrTab)) ||
        !EthDma_IsAccessible((uint32_t)DMATxDscrTab, sizeof(DMATxDscrTab)) ||
        !EthDma_IsAccessible((uint32_t)rx_pool, ETH_RX_BUFFER_CNT * sizeof(RxBuff_t)))
    {
      s_eth_diagnostics.dma_region_violations++;
      SysLog_Print(SYSLOG_LEVEL_ERROR, "ETH",
                   "DMA buffer outside SRAM1/SRAM2 (rxdesc=%08lx txdesc=%08lx pool=%08lx)",
                   (unsigned long)(uintptr_t)DMARxDscrTab,
                   (unsigned long)(uintptr_t)DMATxDscrTab,
                   (unsigned long)rx_pool);
    }
  }
  /* USER CODE END DMA_REGION_CHECK */

#if LWIP_ARP || LWIP_ETHERNET

  /* set MAC hardware address length */
  netif->hwaddr_len = ETH_HWADDR_LEN;

  /* set MAC hardware address */
  netif->hwaddr[0] = heth.Init.MACAddr[0];
  netif->hwaddr[1] = heth.Init.MACAddr[1];
  netif->hwaddr[2] = heth.Init.MACAddr[2];
  netif->hwaddr[3] = heth.Init.MACAddr[3];
  netif->hwaddr[4] = heth.Init.MACAddr[4];
  netif->hwaddr[5] = heth.Init.MACAddr[5];

  /* maximum transfer unit */
  netif->mtu = ETH_MAX_PAYLOAD;

/* Accept broadcast address and ARP traffic */
/* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
#if LWIP_ARP
  netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
#else
  netif->flags |= NETIF_FLAG_BROADCAST;
#endif /* LWIP_ARP */

  /* create a binary semaphore used for informing ethernetif of frame reception */
  osSemaphoreDef(RxSem);
  RxPktSemaphore = osSemaphoreCreate(osSemaphore(RxSem), 1);

  /* create a binary semaphore used for informing ethernetif of frame transmission */
  osSemaphoreDef(TxSem);
  TxPktSemaphore = osSemaphoreCreate(osSemaphore(TxSem), 1);

  /* Decrease the semaphore's initial count from 1 to 0 */
  osSemaphoreWait(RxPktSemaphore, 0);
  osSemaphoreWait(TxPktSemaphore, 0);

  /* create the task that handles the ETH_MAC */
  /* USER CODE BEGIN OS_THREAD_DEF_CREATE_CMSIS_RTOS_V1 */
  osThreadDef(EthIf, ethernetif_input, osPriorityRealtime, 0, INTERFACE_THREAD_STACK_SIZE);
  osThreadCreate(osThread(EthIf), netif);
  /* USER CODE END OS_THREAD_DEF_CREATE_CMSIS_RTOS_V1 */

  /* USER CODE BEGIN PHY_PRE_CONFIG */

  /* USER CODE END PHY_PRE_CONFIG */
  /* Set PHY IO functions */
  LAN8742_RegisterBusIO(&LAN8742, &LAN8742_IOCtx);

  /* Initialize the LAN8742 ETH PHY */
  if (LAN8742_Init(&LAN8742) != LAN8742_STATUS_OK)
  {
    netif_set_link_down(netif);
    return;
  }

  if (hal_eth_init_status == HAL_OK)
  {
    /* Start ETH DMA and interrupts once cleanly at initialization */
    EthDma_SelectRxThresholdMode();
    HAL_ETH_Start_IT(&heth);
    netif_set_link_down(netif);
  }
  else
  {
    Error_Handler();
  }
#endif /* LWIP_ARP || LWIP_ETHERNET */

  /* USER CODE BEGIN LOW_LEVEL_INIT */
  LAN8742_StartAutoNego(&LAN8742);
  /* USER CODE END LOW_LEVEL_INIT */

  if (HAL_GetREVID() == 0x1000)
  {
    /*
  This thread will keep resetting the RMII interface until good frames are received
*/
    osThreadDef(RMII_Watchdog, RMII_Thread, osPriorityRealtime, 0, configMINIMAL_STACK_SIZE);
    osThreadCreate(osThread(RMII_Watchdog), NULL);
  }
}

/**
 * @brief This function should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @param p the MAC packet to send (e.g. IP packet including MAC addresses and type)
 * @return ERR_OK if the packet could be sent
 *         an err_t value if the packet couldn't be sent
 *
 * @note Returning ERR_MEM here if a DMA queue of your MAC is full can lead to
 *       strange results. You might consider waiting for space in the DMA queue
 *       to become available since the stack doesn't retry to send a packet
 *       dropped because of memory failure (except for the TCP timers).
 */

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
  err_t errval;
  struct pbuf *q;
  uint32_t i = 0;
  ETH_BufferTypeDef Txbuffer[ETH_TX_DESC_CNT] = {0};

  /* Proactively release completed TX packets to free their pbufs */
  HAL_ETH_ReleaseTxPacket(&heth);

  memset(Txbuffer, 0, ETH_TX_DESC_CNT * sizeof(ETH_BufferTypeDef));

  for (q = p; q != NULL; q = q->next)
  {
    if (i >= ETH_TX_DESC_CNT)
      return ERR_IF;

    Txbuffer[i].buffer = q->payload;
    Txbuffer[i].len = q->len;

    if (i > 0)
    {
      Txbuffer[i - 1].next = &Txbuffer[i];
    }

    if (q->next == NULL)
    {
      Txbuffer[i].next = NULL;
    }

    i++;
  }

  TxConfig.Length = p->tot_len;
  TxConfig.TxBuffer = Txbuffer;
  TxConfig.pData = p;

  /* Transmit accounting (diagnostic): records the largest frame handed to the
   * driver and whether the transmission was accepted. */
  if (p->tot_len > s_eth_diagnostics.tx_max_len)
  {
    s_eth_diagnostics.tx_max_len = p->tot_len;
  }
  if (s_eth_diagnostics.tx_frames != UINT32_MAX)
  {
    s_eth_diagnostics.tx_frames++;
  }

  pbuf_ref(p);

  do
  {
    if (HAL_ETH_Transmit_IT(&heth, &TxConfig) == HAL_OK)
    {
      errval = ERR_OK;
    }
    else
    {
      if (HAL_ETH_GetError(&heth) & HAL_ETH_ERROR_BUSY)
      {
        /* Wait for descriptors to become available */
        if (osSemaphoreWait(TxPktSemaphore, ETHIF_TX_TIMEOUT) != osOK)
        {
          /* Timeout waiting for TX completion - do NOT loop indefinitely */
          HAL_ETH_ReleaseTxPacket(&heth);
          pbuf_free(p);
          return ERR_IF;
        }
        HAL_ETH_ReleaseTxPacket(&heth);
        errval = ERR_BUF;
      }
      else
      {
        /* Other error */
        pbuf_free(p);
        errval = ERR_IF;
      }
    }
  } while (errval == ERR_BUF);

  if (errval != ERR_OK)
  {
    if (s_eth_diagnostics.tx_failures != UINT32_MAX)
    {
      s_eth_diagnostics.tx_failures++;
    }
    s_eth_diagnostics.tx_last_err = (uint32_t)errval;
  }

  return errval;
}

/**
 * @brief Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return a pbuf filled with the received packet (including MAC header)
 *         NULL on memory error
 */
static struct pbuf *low_level_input(struct netif *netif)
{
  struct pbuf *p = NULL;

  HAL_ETH_ReadData(&heth, (void **)&p);
  if (p != NULL)
  {
    ETH_DIAG_INC(delivered);
    s_eth_good_pkt_received = 1;
  }

  return p;
}

/**
 * @brief This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface. Then the type of the received packet is determined and
 * the appropriate input function is called.
 *
 * @param netif the lwip network interface structure for this ethernetif
 */
static void ethernetif_input(void const *argument)
{
  struct pbuf *p = NULL;
  struct netif *netif = (struct netif *)argument;

  for (;;)
  {
    if (osSemaphoreWait(RxPktSemaphore, TIME_WAITING_FOR_INPUT) == osOK)
    {
      uint32_t t_start = RunTimeStats_GetCount();
      if (s_rx_isr_valid)
      {
        s_rx_isr_valid = 0U;
        rx_latency_record(&s_rx_irq_to_task, t_start - s_rx_isr_cnt);
      }
      do
      {
        p = low_level_input(netif);
        if (p != NULL)
        {
          uint32_t raw_len = p->tot_len;
          bool corrected = (EthDma_CorrectRxLength(p) != 0U);
          if (corrected)
          {
            ETH_DIAG_INC(rx_len_corrected);
          }
          /* Record descriptor length against corrected length for every large
           * frame, whatever its EtherType, so the correction can be verified
           * for GOOSE, SV and raw traffic that has no IP header. */
          if (raw_len > ETH_MAC_RX_FIFO_SIZE)
          {
            s_eth_diagnostics.rx_last_raw_len = raw_len;
            s_eth_diagnostics.rx_last_fixed_len = p->tot_len;
            if ((p->next == NULL) && (p->tot_len >= 4U))
            {
              const uint8_t *fr = (const uint8_t *)p->payload;
              s_eth_diagnostics.rx_last_tail =
                  ((uint32_t)fr[p->tot_len - 4U] << 24) |
                  ((uint32_t)fr[p->tot_len - 3U] << 16) |
                  ((uint32_t)fr[p->tot_len - 2U] << 8) |
                  (uint32_t)fr[p->tot_len - 1U];
            }
          }
          /* Length accounting: a large frame that arrives truncated here would
           * explain a silent LwIP drop without any error counter moving. */
          uint32_t flen = p->tot_len;
          if (flen > s_eth_diagnostics.rx_max_frame_len)
          {
            s_eth_diagnostics.rx_max_frame_len = flen;
          }
          if (flen >= 1024U)
          {
            ETH_DIAG_INC(rx_frames_ge_1024);
          }
          if (flen >= 1400U)
          {
            ETH_DIAG_INC(rx_frames_ge_1400);
          }
          /* Controlled probe, applied to every ICMP echo request so the same
           * measurement exists for small and large frames: record the pbuf
           * length the driver delivered against the length the IP header
           * declares. Any shortfall here is a driver/descriptor problem; a
           * match means LwIP, not the MAC/DMA, discarded the frame. */
          {
            uint8_t hdr[40];
            if ((flen >= sizeof(hdr)) &&
                (pbuf_copy_partial(p, hdr, sizeof(hdr), 0) == sizeof(hdr)) &&
                (hdr[12] == 0x08U) && (hdr[13] == 0x00U) &&
                (hdr[23] == 1U) && (hdr[34] == 8U))
            {
              s_eth_diagnostics.rx_last_tot_len = flen;
              s_eth_diagnostics.rx_last_etype = 0x0800U;
              s_eth_diagnostics.rx_last_ip_total_len =
                  ((uint32_t)hdr[16] << 8) | hdr[17];
              s_eth_diagnostics.rx_probe_ihl = (uint32_t)(hdr[14] & 0x0FU);
              s_eth_diagnostics.rx_probe_icmp_type = hdr[34];
              s_eth_diagnostics.rx_probe_icmp_sum =
                  ((uint32_t)hdr[36] << 8) | hdr[37];
              s_eth_diagnostics.rx_probe_dmasr = heth.Instance->DMASR;
              /* The byte the descriptor did not count: is it the real last byte
               * of the frame, or a stale byte left by the previous frame? */
              if (p->next == NULL)
              {
                const uint8_t *frame = (const uint8_t *)p->payload;
                if (flen < 1536U)
                {
                  s_eth_diagnostics.rx_probe_beyond = frame[flen];
                  s_eth_diagnostics.rx_probe_last = frame[flen - 1U];
                }
              }
              /* Is the whole message physically in the DMA buffer even when
               * the reported length is short? */
              if ((p->next == NULL) && (s_eth_diagnostics.rx_probe_ihl == 5U) &&
                  (p->len >= (14U + s_eth_diagnostics.rx_last_ip_total_len)))
              {
                s_eth_diagnostics.rx_probe_icmp_verify =
                    EthDiag_IcmpChecksum((const uint8_t *)p->payload,
                                         s_eth_diagnostics.rx_last_ip_total_len);
              }
              ETH_DIAG_INC(rx_probe_count);
            }
          }
          /* USER CODE BEGIN RawEth Input */
          /* HAL_ETH_ReadData copied the last descriptor's timestamp before
           * rebuilding it; attach it to this exact returned pbuf. */
          uint32_t hi = heth.RxDescList.TimeStamp.TimeStampHigh;
          uint32_t lo = heth.RxDescList.TimeStamp.TimeStampLow;
          bool valid = s_rx_clock_ready && !(hi == UINT32_MAX && lo == UINT32_MAX) && !(lo & 0x80000000U);
          uint64_t ticks = ((uint64_t)hi << 31) | lo;
          if (RawEth_Input(p, ticks, valid))
          {
            pbuf_free(p);
          }
          else
            /* USER CODE END RawEth Input */
            if (netif->input(p, netif) != ERR_OK)
            {
              ETH_DIAG_INC(lwip_input_failures);
              pbuf_free(p);
            }
        }
      } while (p != NULL);
      rx_latency_record(&s_rx_process, RunTimeStats_GetCount() - t_start);
    }
    /* Progress report for the health gate: reached on every wake-up and on
     * every bounded-wait timeout, but never while stuck inside the drain loop. */
    HealthMonitor_Beat(HEALTH_TASK_ETH_RX);
  }
}

#if !LWIP_ARP
/**
 * This function has to be completed by user in case of ARP OFF.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if ...
 */
static err_t low_level_output_arp_off(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr)
{
  err_t errval;
  errval = ERR_OK;

  /* USER CODE BEGIN 5 */

  /* USER CODE END 5 */

  return errval;
}
#endif /* LWIP_ARP */

/**
 * @brief Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 * This function should be passed as a parameter to netif_add().
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 *         any other err_t on error
 */
err_t ethernetif_init(struct netif *netif)
{
  LWIP_ASSERT("netif != NULL", (netif != NULL));

#if LWIP_NETIF_HOSTNAME
  /* Initialize interface hostname */
  netif->hostname = "lwip";
#endif /* LWIP_NETIF_HOSTNAME */

  /*
   * Initialize the snmp variables and counters inside the struct netif.
   * The last argument should be replaced with your link speed, in units
   * of bits per second.
   */
  // MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, LINK_SPEED_OF_YOUR_NETIF_IN_BPS);

  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
  /* We directly use etharp_output() here to save a function call.
   * You can instead declare your own function an call etharp_output()
   * from it if you have to do some checks before sending (e.g. if link
   * is available...) */

#if LWIP_IPV4
#if LWIP_ARP || LWIP_ETHERNET
#if LWIP_ARP
  netif->output = etharp_output;
#else
  /* The user should write its own code in low_level_output_arp_off function */
  netif->output = low_level_output_arp_off;
#endif /* LWIP_ARP */
#endif /* LWIP_ARP || LWIP_ETHERNET */
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */

  netif->linkoutput = low_level_output;

  /* initialize the hardware */
  low_level_init(netif);

  return ERR_OK;
}

/**
 * @brief  Custom Rx pbuf free callback
 * @param  pbuf: pbuf to be freed
 * @retval None
 */
void pbuf_free_custom(struct pbuf *p)
{
  struct pbuf_custom *custom_pbuf = (struct pbuf_custom *)p;
  LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);

  /* If the Rx Buffer Pool was exhausted, signal the ethernetif_input task to
   * call HAL_ETH_GetRxDataBuffer to rebuild the Rx descriptors. */

  if (RxAllocStatus == RX_ALLOC_ERROR)
  {
    RxAllocStatus = RX_ALLOC_OK;
    osSemaphoreRelease(RxPktSemaphore);
  }
}

/* USER CODE BEGIN 6 */

/**
 * @brief  Returns the current time in milliseconds
 *         when LWIP_TIMERS == 1 and NO_SYS == 1
 * @param  None
 * @retval Current Time value
 */
u32_t sys_now(void)
{
  return HAL_GetTick();
}

/* USER CODE END 6 */

/**
 * @brief  Initializes the ETH MSP.
 * @param  ethHandle: ETH handle
 * @retval None
 */

void HAL_ETH_MspInit(ETH_HandleTypeDef *ethHandle)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  if (ethHandle->Instance == ETH)
  {
    /* USER CODE BEGIN ETH_MspInit 0 */

    /* USER CODE END ETH_MspInit 0 */
    /* Enable Peripheral clock */
    __HAL_RCC_ETH_CLK_ENABLE();

    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOG_CLK_ENABLE();
    /**ETH GPIO Configuration
PC1     ------> ETH_MDC
PA1     ------> ETH_REF_CLK
PA2     ------> ETH_MDIO
PA7     ------> ETH_CRS_DV
PC4     ------> ETH_RXD0
PC5     ------> ETH_RXD1
PB13     ------> ETH_TXD1
PG11     ------> ETH_TX_EN
PG13     ------> ETH_TXD0
*/
    GPIO_InitStruct.Pin = GPIO_PIN_1 | GPIO_PIN_4 | GPIO_PIN_5;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF11_ETH;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_7;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF11_ETH;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF11_ETH;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_11 | GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF11_ETH;
    HAL_GPIO_Init(GPIOG, &GPIO_InitStruct);

    /* Peripheral interrupt init */
    HAL_NVIC_SetPriority(ETH_IRQn, 5, 0);
    HAL_NVIC_EnableIRQ(ETH_IRQn);
    /* USER CODE BEGIN ETH_MspInit 1 */

    /* USER CODE END ETH_MspInit 1 */
  }
}

void HAL_ETH_MspDeInit(ETH_HandleTypeDef *ethHandle)
{
  if (ethHandle->Instance == ETH)
  {
    /* USER CODE BEGIN ETH_MspDeInit 0 */

    /* USER CODE END ETH_MspDeInit 0 */
    /* Peripheral clock disable */
    __HAL_RCC_ETH_CLK_DISABLE();

    /**ETH GPIO Configuration
PC1     ------> ETH_MDC
PA1     ------> ETH_REF_CLK
PA2     ------> ETH_MDIO
PA7     ------> ETH_CRS_DV
PC4     ------> ETH_RXD0
PC5     ------> ETH_RXD1
PB13     ------> ETH_TXD1
PG11     ------> ETH_TX_EN
PG13     ------> ETH_TXD0
*/
    HAL_GPIO_DeInit(GPIOC, GPIO_PIN_1 | GPIO_PIN_4 | GPIO_PIN_5);

    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_7);

    HAL_GPIO_DeInit(GPIOB, GPIO_PIN_13);

    HAL_GPIO_DeInit(GPIOG, GPIO_PIN_11 | GPIO_PIN_13);

    /* Peripheral interrupt Deinit*/
    HAL_NVIC_DisableIRQ(ETH_IRQn);

    /* USER CODE BEGIN ETH_MspDeInit 1 */

    /* USER CODE END ETH_MspDeInit 1 */
  }
}

/*******************************************************************************
                       PHI IO Functions
*******************************************************************************/
/**
 * @brief  Initializes the MDIO interface GPIO and clocks.
 * @param  None
 * @retval 0 if OK, -1 if ERROR
 */
int32_t ETH_PHY_IO_Init(void)
{
  /* We assume that MDIO GPIO configuration is already done
   in the ETH_MspInit() else it should be done here
*/

  /* Configure the MDIO Clock */
  HAL_ETH_SetMDIOClockRange(&heth);

  return 0;
}

/**
 * @brief  De-Initializes the MDIO interface .
 * @param  None
 * @retval 0 if OK, -1 if ERROR
 */
int32_t ETH_PHY_IO_DeInit(void)
{
  return 0;
}

/**
 * @brief  Read a PHY register through the MDIO interface.
 * @param  DevAddr: PHY port address
 * @param  RegAddr: PHY register address
 * @param  pRegVal: pointer to hold the register value
 * @retval 0 if OK -1 if Error
 */
int32_t ETH_PHY_IO_ReadReg(uint32_t DevAddr, uint32_t RegAddr, uint32_t *pRegVal)
{
  if (HAL_ETH_ReadPHYRegister(&heth, DevAddr, RegAddr, pRegVal) != HAL_OK)
  {
    return -1;
  }

  return 0;
}

/**
 * @brief  Write a value to a PHY register through the MDIO interface.
 * @param  DevAddr: PHY port address
 * @param  RegAddr: PHY register address
 * @param  RegVal: Value to be written
 * @retval 0 if OK -1 if Error
 */
int32_t ETH_PHY_IO_WriteReg(uint32_t DevAddr, uint32_t RegAddr, uint32_t RegVal)
{
  if (HAL_ETH_WritePHYRegister(&heth, DevAddr, RegAddr, RegVal) != HAL_OK)
  {
    return -1;
  }

  return 0;
}

/**
 * @brief  Get the time in millisecons used for internal PHY driver process.
 * @retval Time value
 */
int32_t ETH_PHY_IO_GetTick(void)
{
  return HAL_GetTick();
}

/**
 * @brief  Check the ETH link state then update ETH driver and netif link accordingly.
 * @retval None
 */

void ethernet_link_thread(void const *argument)
{
  int32_t PHYLinkState = 0;
  int32_t last_phy_state = LAN8742_STATUS_LINK_DOWN;

  struct netif *netif = (struct netif *)argument;
  /* USER CODE BEGIN ETH link init */

  /* USER CODE END ETH link init */

  for (;;)
  {
    PHYLinkState = LAN8742_GetLinkState(&LAN8742);

    if (PHYLinkState <= LAN8742_STATUS_LINK_DOWN || PHYLinkState < 0)
    {
      if (netif_is_link_up(netif))
      {
        LOCK_TCPIP_CORE();
        netif_set_link_down(netif);
        UNLOCK_TCPIP_CORE();
        last_phy_state = LAN8742_STATUS_LINK_DOWN;
        SysLog_Print(SYSLOG_LEVEL_INFO, "ETH", "Link DOWN");
      }
    }
    else if (PHYLinkState >= LAN8742_STATUS_100MBITS_FULLDUPLEX &&
             PHYLinkState <= LAN8742_STATUS_10MBITS_HALFDUPLEX)
    {
      if (!netif_is_link_up(netif) || PHYLinkState != last_phy_state)
      {
        uint32_t duplex = ETH_FULLDUPLEX_MODE;
        uint32_t speed = ETH_SPEED_100M;
        const char *speed_str = "100M";
        const char *duplex_str = "FD";

        switch (PHYLinkState)
        {
        case LAN8742_STATUS_100MBITS_FULLDUPLEX:
          duplex = ETH_FULLDUPLEX_MODE;
          speed = ETH_SPEED_100M;
          speed_str = "100 Mbps";
          duplex_str = "Full-Duplex";
          break;
        case LAN8742_STATUS_100MBITS_HALFDUPLEX:
          duplex = ETH_HALFDUPLEX_MODE;
          speed = ETH_SPEED_100M;
          speed_str = "100 Mbps";
          duplex_str = "Half-Duplex";
          break;
        case LAN8742_STATUS_10MBITS_FULLDUPLEX:
          duplex = ETH_FULLDUPLEX_MODE;
          speed = ETH_SPEED_10M;
          speed_str = "10 Mbps";
          duplex_str = "Full-Duplex";
          break;
        case LAN8742_STATUS_10MBITS_HALFDUPLEX:
          duplex = ETH_HALFDUPLEX_MODE;
          speed = ETH_SPEED_10M;
          speed_str = "10 Mbps";
          duplex_str = "Half-Duplex";
          break;
        }

        /* Update MACCR speed and duplex safely per RM0410 (change allowed only when TE and RE are reset) */
        uint32_t maccr = heth.Instance->MACCR;
        uint32_t was_enabled = maccr & (ETH_MACCR_TE | ETH_MACCR_RE);
        if (was_enabled)
        {
          heth.Instance->MACCR &= ~(ETH_MACCR_TE | ETH_MACCR_RE);
          for (volatile int d = 0; d < 1000; d++)
          {
            __NOP();
          }
        }

        if (duplex == ETH_FULLDUPLEX_MODE)
        {
          heth.Instance->MACCR |= ETH_MACCR_DM;
        }
        else
        {
          heth.Instance->MACCR &= ~ETH_MACCR_DM;
        }

        if (speed == ETH_SPEED_100M)
        {
          heth.Instance->MACCR |= ETH_MACCR_FES;
        }
        else
        {
          heth.Instance->MACCR &= ~ETH_MACCR_FES;
        }

        if (was_enabled)
        {
          heth.Instance->MACCR |= was_enabled;
        }

        /* Ensure ETH DMA is running */
        if (heth.gState != HAL_ETH_STATE_STARTED)
        {
          EthDma_SelectRxThresholdMode();
          HAL_ETH_Start_IT(&heth);
        }

        LOCK_TCPIP_CORE();
        /* Ensure interface is administratively UP and IP preserved */
        if (!netif_is_up(netif))
        {
          netif_set_up(netif);
        }
        netif_set_link_up(netif);
        etharp_gratuitous(netif);
        HTTP_API_EnsureListening();
        UNLOCK_TCPIP_CORE();

        last_phy_state = PHYLinkState;
        SysLog_Print(SYSLOG_LEVEL_INFO, "ETH", "Link UP: %s, %s (IP=%s)",
                     speed_str, duplex_str,
                     ip4addr_ntoa(netif_ip4_addr(netif)));
      }
    }

    /* USER CODE BEGIN ETH link Thread core code for User BSP */

    /* USER CODE END ETH link Thread core code for User BSP */

    osDelay(200);
  }
}

void HAL_ETH_RxAllocateCallback(uint8_t **buff)
{
  /* USER CODE BEGIN HAL ETH RxAllocateCallback */
  struct pbuf_custom *p = LWIP_MEMPOOL_ALLOC(RX_POOL);
  if (p)
  {
    /* Get the buff from the struct pbuf address. */
    *buff = (uint8_t *)p + offsetof(RxBuff_t, buff);
    p->custom_free_function = pbuf_free_custom;
    /* Initialize the struct pbuf.
     * This must be performed whenever a buffer's allocated because it may be
     * changed by lwIP or the app, e.g., pbuf_free decrements ref. */
    pbuf_alloced_custom(PBUF_RAW, 0, PBUF_REF, p, *buff, ETH_RX_BUF_SIZE);
    RxAllocStatus = RX_ALLOC_OK;
  }
  else
  {
    ETH_DIAG_INC(rx_alloc_failures);
    RxAllocStatus = RX_ALLOC_ERROR;
    *buff = NULL;
  }
  /* USER CODE END HAL ETH RxAllocateCallback */
}

void HAL_ETH_RxLinkCallback(void **pStart, void **pEnd, uint8_t *buff, uint16_t Length)
{
  /* USER CODE BEGIN HAL ETH RxLinkCallback */

  struct pbuf **ppStart = (struct pbuf **)pStart;
  struct pbuf **ppEnd = (struct pbuf **)pEnd;
  struct pbuf *p = NULL;

  /* Get the struct pbuf from the buff address. */
  p = (struct pbuf *)(buff - offsetof(RxBuff_t, buff));
  p->next = NULL;
  p->tot_len = 0;
  p->len = Length;

  /* Chain the buffer. */
  if (!*ppStart)
  {
    /* The first buffer of the packet. */
    *ppStart = p;
  }
  else
  {
    /* Chain the buffer to the end of the packet. */
    (*ppEnd)->next = p;
  }
  *ppEnd = p;

  /* Update the total length of all the buffers of the chain. Each pbuf in the chain should have its tot_len
   * set to its own length, plus the length of all the following pbufs in the chain. */
  for (p = *ppStart; p != NULL; p = p->next)
  {
    p->tot_len += Length;
  }

  /* Invalidate data cache because Rx DMA's writing to physical memory makes it stale.
   *
   * D-Cache state: DISABLED in this firmware (only SCB_EnableICache() is called
   * in main()), so this is currently a no-op and no TX-side clean is required.
   * If D-Cache is ever enabled, this call alone is NOT sufficient: TX buffers
   * must be cleaned before HAL_ETH_TransmitFrame and the descriptors must be
   * cleaned/invalidated too. Do not enable D-Cache without completing that work. */
  SCB_InvalidateDCache_by_Addr((uint32_t *)buff, Length);

  /* USER CODE END HAL ETH RxLinkCallback */
}

void HAL_ETH_TxFreeCallback(uint32_t *buff)
{
  /* USER CODE BEGIN HAL ETH TxFreeCallback */

  pbuf_free((struct pbuf *)buff);

  /* USER CODE END HAL ETH TxFreeCallback */
}

/* USER CODE BEGIN 8 */

/* USER CODE END 8 */

void RMII_Thread(void const *argument)
{
  (void)argument;
  uint8_t reset_attempts = 0;

  for (;;)
  {
    /* If any good packet has been received (broadcast, multicast, or unicast), RMII clock phase is valid */
    if (s_eth_good_pkt_received || heth.Instance->MMCRGUFCR > 0U)
    {
      /* RMII is working properly: terminate watchdog thread */
      osThreadTerminate(NULL);
    }
    else if (netif_is_link_up(&gnetif) && heth.Instance->MMCRFCECR > 10U && reset_attempts < 3)
    {
      reset_attempts++;
      /* ETH received CRC errors while link is physically UP, toggle RMII phase */
      SYSCFG->PMC &= ~SYSCFG_PMC_MII_RMII_SEL;
      osDelay(10);
      SYSCFG->PMC |= SYSCFG_PMC_MII_RMII_SEL;

      heth.Instance->MMCCR |= ETH_MMCCR_CR;
      osDelay(500);
    }
    else if (reset_attempts >= 3)
    {
      /* Stop resetting after 3 attempts to avoid destabilizing link */
      osThreadTerminate(NULL);
    }
    else
    {
      osDelay(200);
    }
  }
}

/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * File Name          : ethernetif.h
 * Description        : This file provides initialization code for LWIP
 *                      middleWare.
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

#ifndef __ETHERNETIF_H__
#define __ETHERNETIF_H__
#include "lwip/err.h"
#include "lwip/netif.h"
#include "cmsis_os.h"

/* Within 'USER CODE' section, code will be kept by default at each generation */
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* Exported functions ------------------------------------------------------- */
err_t ethernetif_init(struct netif *netif);

void ethernet_link_thread(void const *argument);

void Error_Handler(void);
u32_t sys_jiffies(void);
u32_t sys_now(void);

/* USER CODE BEGIN 1 */
typedef struct
{
  uint32_t delivered;
  uint32_t rx_alloc_failures;
  uint32_t dma_error_callbacks;
  uint32_t rx_buffer_unavailable;
  uint32_t lwip_input_failures;
  uint32_t dma_region_violations;

  uint32_t rx_irq_to_task_min_us;
  uint32_t rx_irq_to_task_avg_us;
  uint32_t rx_irq_to_task_max_us;
  uint32_t rx_irq_to_task_samples;
  uint32_t rx_irq_to_task_over_1ms;
  uint32_t rx_process_min_us;
  uint32_t rx_process_avg_us;
  uint32_t rx_process_max_us;
  uint32_t rx_process_samples;
  uint32_t rx_process_over_1ms;

  uint32_t dmasr;

  uint32_t rx_max_frame_len;
  uint32_t rx_len_corrected;
  uint32_t rx_len_unverifiable;
  uint32_t rx_last_raw_len;
  uint32_t rx_last_fixed_len;
  uint32_t rx_last_tail;
  uint32_t rx_frames_ge_1024;
  uint32_t rx_frames_ge_1400;

  uint32_t tx_frames;
  uint32_t tx_max_len;
  uint32_t tx_failures;
  uint32_t tx_last_err;

  uint32_t rx_last_tot_len;
  uint32_t rx_last_ip_total_len;
  uint32_t rx_last_etype;
  uint32_t rx_probe_ihl;
  uint32_t rx_probe_icmp_type;
  uint32_t rx_probe_icmp_sum;
  uint32_t rx_probe_icmp_verify;
  uint32_t rx_probe_dmasr;
  uint32_t rx_probe_last;
  uint32_t rx_probe_beyond;
  uint32_t rx_probe_count;
} Ethernet_Diagnostics_t;

void Ethernet_GetDiagnostics(Ethernet_Diagnostics_t *out);

/* USER CODE END 1 */
#endif

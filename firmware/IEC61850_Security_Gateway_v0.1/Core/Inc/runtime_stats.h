#ifndef RUNTIME_STATS_H
#define RUNTIME_STATS_H

#include <stdint.h>

/*
 * FreeRTOS run-time counter source.
 *
 * TIM2 is used because:
 *   - TIM6 is the HAL time base (1 kHz interrupt) and SysTick is the RTOS tick,
 *   - TIM7 is only 16 bits and was observed to disturb the Ethernet link at
 *     start-up on this board,
 *   - TIM2 is 32-bit and runs free without any interrupt, NVIC entry or
 *     scheduler interaction.
 *
 * The counter is clocked at RUNTIME_STATS_COUNTER_HZ and wraps every ~71.6
 * minutes. All consumers must use unsigned 32-bit subtraction of deltas and
 * never compare absolute values.
 */

#define RUNTIME_STATS_COUNTER_HZ 1000000U

void RunTimeStats_Init(void);
uint32_t RunTimeStats_GetCount(void);

#endif /* RUNTIME_STATS_H */

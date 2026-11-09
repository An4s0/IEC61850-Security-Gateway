#include "runtime_stats.h"
#include "stm32f7xx_hal.h"

/*
 * TIM2 is a 32-bit general-purpose timer on STM32F7 (TIM6/TIM7 are 16-bit),
 * it is unused elsewhere in this firmware, and it runs free without any
 * interrupt or NVIC vector, so it cannot perturb Ethernet or scheduling.
 */
static uint8_t s_initialized = 0;

void RunTimeStats_Init(void)
{
    if (s_initialized)
    {
        return;
    }

    __HAL_RCC_TIM2_CLK_ENABLE();

    uint32_t pclk1 = HAL_RCC_GetPCLK1Freq();
    uint32_t hclk = HAL_RCC_GetHCLKFreq();
    /* The APB1 timer clock is 2x PCLK1 unless the APB1 prescaler is 1. */
    uint32_t tim_clk = (pclk1 == hclk) ? pclk1 : (pclk1 * 2U);

    uint32_t psc = tim_clk / RUNTIME_STATS_COUNTER_HZ;
    if (psc == 0U)
    {
        psc = 1U;
    }
    if (psc > 0x10000U)
    {
        psc = 0x10000U;
    }

    TIM2->CR1 = 0U;
    TIM2->PSC = psc - 1U;
    TIM2->ARR = 0xFFFFFFFFU;
    TIM2->CNT = 0U;
    TIM2->EGR = TIM_EGR_UG;
    TIM2->SR = 0U;
    TIM2->CR1 = TIM_CR1_CEN;

    s_initialized = 1;
}

uint32_t RunTimeStats_GetCount(void)
{
    if (!s_initialized)
    {
        RunTimeStats_Init();
    }
    return TIM2->CNT;
}

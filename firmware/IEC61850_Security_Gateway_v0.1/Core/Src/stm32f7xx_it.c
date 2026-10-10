/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    stm32f7xx_it.c
  * @brief   Interrupt Service Routines.
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
#include "stm32f7xx_it.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include "FreeRTOS.h"
#include "task.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/
extern ETH_HandleTypeDef heth;
extern TIM_HandleTypeDef htim6;

/* USER CODE BEGIN EV */

/* USER CODE END EV */

/******************************************************************************/
/*           Cortex-M7 Processor Interruption and Exception Handlers          */
/******************************************************************************/
/**
  * @brief This function handles Non maskable interrupt.
  */
void NMI_Handler(void)
{
  /* USER CODE BEGIN NonMaskableInt_IRQn 0 */

  /* USER CODE END NonMaskableInt_IRQn 0 */
  /* USER CODE BEGIN NonMaskableInt_IRQn 1 */
   while (1)
  {
  }
  /* USER CODE END NonMaskableInt_IRQn 1 */
}

/* USER CODE BEGIN 0 */
/**
 * @brief Prints the stacked register frame and SCB fault registers via UART.
 *        Called from fault handlers with a pointer to the exception stack frame.
 */
static __attribute__((used)) void fault_print_registers(uint32_t *fault_stack)
{
    /* SCB fault status registers */
    volatile uint32_t cfsr  = SCB->CFSR;   /* Configurable Fault Status */
    volatile uint32_t hfsr  = SCB->HFSR;   /* Hard Fault Status */
    volatile uint32_t mmfar = SCB->MMFAR;  /* MemManage Fault Address */
    volatile uint32_t bfar  = SCB->BFAR;   /* Bus Fault Address */

    /* Stacked register frame: R0,R1,R2,R3,R12,LR,PC,xPSR */
    uint32_t r0   = fault_stack[0];
    uint32_t r1   = fault_stack[1];
    uint32_t r2   = fault_stack[2];
    uint32_t r3   = fault_stack[3];
    uint32_t r12  = fault_stack[4];
    uint32_t lr   = fault_stack[5];
    uint32_t pc   = fault_stack[6];
    uint32_t xpsr = fault_stack[7];

    printf("\r\n*** FAULT ***\r\n");
    printf("CFSR  = 0x%08lX\r\n", (unsigned long)cfsr);
    printf("HFSR  = 0x%08lX\r\n", (unsigned long)hfsr);
    printf("MMFAR = 0x%08lX\r\n", (unsigned long)mmfar);
    printf("BFAR  = 0x%08lX\r\n", (unsigned long)bfar);
    printf("R0    = 0x%08lX\r\n", (unsigned long)r0);
    printf("R1    = 0x%08lX\r\n", (unsigned long)r1);
    printf("R2    = 0x%08lX\r\n", (unsigned long)r2);
    printf("R3    = 0x%08lX\r\n", (unsigned long)r3);
    printf("R12   = 0x%08lX\r\n", (unsigned long)r12);
    printf("LR    = 0x%08lX\r\n", (unsigned long)lr);
    printf("PC    = 0x%08lX\r\n", (unsigned long)pc);
    printf("xPSR  = 0x%08lX\r\n", (unsigned long)xpsr);

    /* Decode CFSR sub-fields */
    if (cfsr & 0x000000FFU) {
        printf("[MemManage] MMFSR = 0x%02lX", (unsigned long)(cfsr & 0xFFU));
        if (cfsr & (1U<<7)) printf(" MMARVALID(MMFAR=0x%08lX)", (unsigned long)mmfar);
        if (cfsr & (1U<<4)) printf(" MSTKERR");
        if (cfsr & (1U<<3)) printf(" MUNSTKERR");
        if (cfsr & (1U<<1)) printf(" DACCVIOL");
        if (cfsr & (1U<<0)) printf(" IACCVIOL");
        printf("\r\n");
    }
    if (cfsr & 0x0000FF00U) {
        printf("[BusFault] BFSR = 0x%02lX", (unsigned long)((cfsr >> 8) & 0xFFU));
        if (cfsr & (1U<<15)) printf(" BFARVALID(BFAR=0x%08lX)", (unsigned long)bfar);
        if (cfsr & (1U<<12)) printf(" STKERR");
        if (cfsr & (1U<<11)) printf(" UNSTKERR");
        if (cfsr & (1U<<10)) printf(" IMPRECISERR");
        if (cfsr & (1U<<9))  printf(" PRECISERR");
        if (cfsr & (1U<<8))  printf(" IBUSERR");
        printf("\r\n");
    }
    if (cfsr & 0xFFFF0000U) {
        printf("[UsageFault] UFSR = 0x%04lX", (unsigned long)((cfsr >> 16) & 0xFFFFU));
        if (cfsr & (1U<<25)) printf(" DIVBYZERO");
        if (cfsr & (1U<<24)) printf(" UNALIGNED");
        if (cfsr & (1U<<19)) printf(" NOCP");
        if (cfsr & (1U<<18)) printf(" INVPC");
        if (cfsr & (1U<<17)) printf(" INVSTATE");
        if (cfsr & (1U<<16)) printf(" UNDEFINSTR");
        printf("\r\n");
    }
    printf("Faulting PC: 0x%08lX\r\n", (unsigned long)pc);
    printf("*** HALTED ***\r\n");
}
/* USER CODE END 0 */

/**
  * @brief Hard fault trampoline — captures MSP or PSP stack pointer then prints registers.
  */
__attribute__((naked))
void HardFault_Handler(void)
{
  __asm volatile (
      "tst   lr, #4        \n"
      "ite   eq             \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "b     fault_print_registers \n"
  );
  /* fault_print_registers never returns; loop added to keep compiler happy */
  while (1) {}
}

/**
  * @brief MemManage fault trampoline.
  */
__attribute__((naked))
void MemManage_Handler(void)
{
  __asm volatile (
      "tst   lr, #4        \n"
      "ite   eq             \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "b     fault_print_registers \n"
  );
  while (1) {}
}

/**
  * @brief Bus fault trampoline.
  */
__attribute__((naked))
void BusFault_Handler(void)
{
  __asm volatile (
      "tst   lr, #4        \n"
      "ite   eq             \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "b     fault_print_registers \n"
  );
  while (1) {}
}

/**
  * @brief Usage fault trampoline.
  */
__attribute__((naked))
void UsageFault_Handler(void)
{
  __asm volatile (
      "tst   lr, #4        \n"
      "ite   eq             \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "b     fault_print_registers \n"
  );
  while (1) {}
}

/**
  * @brief This function handles Debug monitor.
  */
void DebugMon_Handler(void)
{
  /* USER CODE BEGIN DebugMonitor_IRQn 0 */

  /* USER CODE END DebugMonitor_IRQn 0 */
  /* USER CODE BEGIN DebugMonitor_IRQn 1 */

  /* USER CODE END DebugMonitor_IRQn 1 */
}

/******************************************************************************/
/* STM32F7xx Peripheral Interrupt Handlers                                    */
/* Add here the Interrupt Handlers for the used peripherals.                  */
/* For the available peripheral interrupt handler names,                      */
/* please refer to the startup file (startup_stm32f7xx.s).                    */
/******************************************************************************/

/**
  * @brief This function handles TIM6 global interrupt, DAC1 and DAC2 underrun error interrupts.
  */
void TIM6_DAC_IRQHandler(void)
{
  /* USER CODE BEGIN TIM6_DAC_IRQn 0 */

  /* USER CODE END TIM6_DAC_IRQn 0 */
  HAL_TIM_IRQHandler(&htim6);
  /* USER CODE BEGIN TIM6_DAC_IRQn 1 */

  /* USER CODE END TIM6_DAC_IRQn 1 */
}

/**
  * @brief This function handles Ethernet global interrupt.
  */
void ETH_IRQHandler(void)
{
  /* USER CODE BEGIN ETH_IRQn 0 */

  /* USER CODE END ETH_IRQn 0 */
  HAL_ETH_IRQHandler(&heth);
  /* USER CODE BEGIN ETH_IRQn 1 */

  /* USER CODE END ETH_IRQn 1 */
}

/* USER CODE BEGIN 1 */
/**
 * @brief FreeRTOS stack-overflow hook. Prints the offending task name then halts.
 */
void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
    (void)xTask;
    printf("\r\n*** STACK OVERFLOW in task: %s ***\r\n", pcTaskName);
    taskDISABLE_INTERRUPTS();
    for (;;) {}
}
/* USER CODE END 1 */

/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
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
#include "cmsis_os.h"
#include "fatfs.h"
#include "lwip.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "lwip/apps/httpd.h"
#include "raw_eth.h"
#include "goose.h"
#include "sv.h"
#include "mms.h"
#include "http_api.h"
#include "scd_storage.h"
#include "scd_config.h"
#include "security.h"
#include "sdmmc.h"
#include "system_config.h"
#include "system_logger.h"
#include "storage_service.h"
#include "sys_diag.h"
#include "lwip/tcpip.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

SD_HandleTypeDef hsd1;

UART_HandleTypeDef huart3;

osThreadId defaultTaskHandle;
osThreadId GooseTaskHandle;
osThreadId SCD_StorageTaskHandle;
osThreadId SCD_ConfigTaskHandle;
osThreadId SVTaskHandle;
osThreadId MMSTaskHandle;
osMessageQId GooseQueueHandle;
osMessageQId SCD_StorageQueueHandle;
osMessageQId SCD_ConfigQueueHandle;
osMessageQId SVQueueHandle;
osMessageQId MMSQueueHandle;
/* USER CODE BEGIN PV */
extern struct netif gnetif;
extern ETH_HandleTypeDef heth;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MPU_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART3_UART_Init(void);
void MX_SDMMC1_SD_Init(void);
void StartDefaultTask(void const *argument);
void StartGooseTask(void const *argument);
void StartSCD_StorageTask(void const *argument);
void StartSCD_ConfigTask(void const *argument);
void StartSVTask(void const *argument);
void StartMMSTask(void const *argument);

/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
 * @brief  The application entry point.
 * @retval int
 */
int main(void)
{

  /* USER CODE BEGIN 1 */
  /* Enable Cortex-M7 Instruction Cache for full 216 MHz Flash execution */
  SCB_EnableICache();
  /* USER CODE END 1 */

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */
  SysDiag_Init();
  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART3_UART_Init();
  MX_FATFS_Init();
  MX_SDMMC1_SD_Init();
  /* USER CODE BEGIN 2 */
  f_mount(&USERFatFS, USERPath, 0);
  /* USER CODE END 2 */

  /* USER CODE BEGIN RTOS_MUTEX */
  /* add mutexes, ... */
  /* USER CODE END RTOS_MUTEX */

  /* USER CODE BEGIN RTOS_SEMAPHORES */
  /* add semaphores, ... */
  /* USER CODE END RTOS_SEMAPHORES */

  /* USER CODE BEGIN RTOS_TIMERS */
  /* start timers, add new ones, ... */
  /* USER CODE END RTOS_TIMERS */

  /* Create the queue(s) */
  /* definition and creation of GooseQueue */
  osMessageQDef(GooseQueue, 16, uint32_t);
  GooseQueueHandle = osMessageCreate(osMessageQ(GooseQueue), NULL);

  /* definition and creation of SCD_StorageQueue */
  osMessageQDef(SCD_StorageQueue, 8, uint32_t);
  SCD_StorageQueueHandle = osMessageCreate(osMessageQ(SCD_StorageQueue), NULL);

  /* definition and creation of SCD_ConfigQueue */
  osMessageQDef(SCD_ConfigQueue, 4, uint32_t);
  SCD_ConfigQueueHandle = osMessageCreate(osMessageQ(SCD_ConfigQueue), NULL);

  /* definition and creation of SVQueue */
  osMessageQDef(SVQueue, 32, uint32_t);
  SVQueueHandle = osMessageCreate(osMessageQ(SVQueue), NULL);

  /* definition and creation of MMSQueue */
  osMessageQDef(MMSQueue, 16, uint32_t);
  MMSQueueHandle = osMessageCreate(osMessageQ(MMSQueue), NULL);

  /* USER CODE BEGIN RTOS_QUEUES */
  /* add queues, ... */
  /* USER CODE END RTOS_QUEUES */

  /* Create the thread(s) */
  /* definition and creation of defaultTask */
  osThreadDef(defaultTask, StartDefaultTask, osPriorityNormal, 0, 1024);
  defaultTaskHandle = osThreadCreate(osThread(defaultTask), NULL);

  /* definition and creation of GooseTask */
  osThreadDef(GooseTask, StartGooseTask, osPriorityHigh, 0, 1024);
  GooseTaskHandle = osThreadCreate(osThread(GooseTask), NULL);

  /* definition and creation of SCD_StorageTask */
  osThreadDef(SCD_StorageTask, StartSCD_StorageTask, osPriorityAboveNormal, 0, 1024);
  SCD_StorageTaskHandle = osThreadCreate(osThread(SCD_StorageTask), NULL);

  /* definition and creation of SCD_ConfigTask */
  osThreadDef(SCD_ConfigTask, StartSCD_ConfigTask, osPriorityNormal, 0, 2048);
  SCD_ConfigTaskHandle = osThreadCreate(osThread(SCD_ConfigTask), NULL);

  /* definition and creation of SVTask */
  osThreadDef(SVTask, StartSVTask, osPriorityHigh, 0, 2048);
  SVTaskHandle = osThreadCreate(osThread(SVTask), NULL);

  /* definition and creation of MMSTask */
  osThreadDef(MMSTask, StartMMSTask, osPriorityHigh, 0, 2048);
  MMSTaskHandle = osThreadCreate(osThread(MMSTask), NULL);

  /* USER CODE BEGIN RTOS_THREADS */
  Goose_Init();
  Sv_Init();
  Mms_Init();
  /* USER CODE END RTOS_THREADS */

  /* Start scheduler */
  osKernelStart();

  /* We should never get here as control is now taken by the scheduler */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
 * @brief System Clock Configuration
 * @retval None
 */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
   */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
   * in the RCC_OscInitTypeDef structure.
   */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 216;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 9;
  RCC_OscInitStruct.PLL.PLLR = 2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Activate the Over-Drive mode
   */
  if (HAL_PWREx_EnableOverDrive() != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
   */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_7) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
 * @brief SDMMC1 Initialization Function
 * @param None
 * @retval None
 */
void MX_SDMMC1_SD_Init(void)
{

  /* USER CODE BEGIN SDMMC1_Init 0 */

  /* USER CODE END SDMMC1_Init 0 */

  /* USER CODE BEGIN SDMMC1_Init 1 */

  /* USER CODE END SDMMC1_Init 1 */
  /* Initialize SDMMC1 GPIOs and peripheral power cleanly using register-level driver */
  SDMMC_GPIO_Init();
  /* USER CODE BEGIN SDMMC1_Init 2 */

  /* USER CODE END SDMMC1_Init 2 */
}

/**
 * @brief USART3 Initialization Function
 * @param None
 * @retval None
 */
static void MX_USART3_UART_Init(void)
{

  /* USER CODE BEGIN USART3_Init 0 */

  /* USER CODE END USART3_Init 0 */

  /* USER CODE BEGIN USART3_Init 1 */

  /* USER CODE END USART3_Init 1 */
  huart3.Instance = USART3;
  huart3.Init.BaudRate = 115200;
  huart3.Init.WordLength = UART_WORDLENGTH_8B;
  huart3.Init.StopBits = UART_STOPBITS_1;
  huart3.Init.Parity = UART_PARITY_NONE;
  huart3.Init.Mode = UART_MODE_TX_RX;
  huart3.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart3.Init.OverSampling = UART_OVERSAMPLING_16;
  huart3.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart3.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART3_Init 2 */

  /* USER CODE END USART3_Init 2 */
}

/**
 * @brief GPIO Initialization Function
 * @param None
 * @retval None
 */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOG_CLK_ENABLE();

  /*Configure GPIO pin : PG2 */
  GPIO_InitStruct.Pin = GPIO_PIN_2;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_PULLUP;
  HAL_GPIO_Init(GPIOG, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
int __io_putchar(int ch)
{
  HAL_UART_Transmit(&huart3, (uint8_t *)&ch, 1, HAL_MAX_DELAY);
  return ch;
}

int _write(int file, char *ptr, int len)
{
  (void)file;
  if (ptr == NULL || len <= 0)
  {
    return 0;
  }
  HAL_UART_Transmit(&huart3, (uint8_t *)ptr, (uint16_t)len, 100);
  return len;
}

/* USER CODE END 4 */

/* USER CODE BEGIN Header_StartDefaultTask */
/**
 * @brief  Function implementing the defaultTask thread.
 * @param  argument: Not used
 * @retval None
 */
/* USER CODE END Header_StartDefaultTask */
void StartDefaultTask(void const *argument)
{
  /* init code for LWIP */
  MX_LWIP_Init();
  /* USER CODE BEGIN 5 */
  SysLog_Init();
  SysLog_Print(SYSLOG_LEVEL_INFO, "BOOT", "IEC 61850 Security Gateway started. STM32F767ZI.");
  SystemConfig_Init();
  SCD_Storage_Init();
  SCD_Config_Init();
  Security_Init();
  StorageService_Init();
  Security_SyncAlertCounter();

  LOCK_TCPIP_CORE();
  HTTP_API_Init();
  httpd_init();
  UNLOCK_TCPIP_CORE();

  SCD_Config_RequestLoadStartup();
  SysLog_Print(SYSLOG_LEVEL_INFO, "SYS", "HTTP server listening on port %d", HTTP_API_PORT);

  for (;;)
  {
    osDelay(100);
    StorageService_Run();
  }
  /* USER CODE END 5 */
}

/* USER CODE BEGIN Header_StartGooseTask */
/**
 * @brief Function implementing the GooseTask thread.
 * @param argument: Not used
 * @retval None
 */
/* USER CODE END Header_StartGooseTask */
void StartGooseTask(void const *argument)
{
  /* USER CODE BEGIN StartGooseTask */
  Goose_Task(argument);
  /* USER CODE END StartGooseTask */
}

/* USER CODE BEGIN Header_StartSCD_StorageTask */
/**
 * @brief Function implementing the SCD_StorageTask thread.
 * @param argument: Not used
 * @retval None
 */
/* USER CODE END Header_StartSCD_StorageTask */
void StartSCD_StorageTask(void const *argument)
{
  /* USER CODE BEGIN StartSCD_StorageTask */
  SCD_Storage_Task(argument);
  /* USER CODE END StartSCD_StorageTask */
}

/* USER CODE BEGIN Header_StartSCD_ConfigTask */
/**
 * @brief Function implementing the SCD_ConfigTask thread.
 * @param argument: Not used
 * @retval None
 */
/* USER CODE END Header_StartSCD_ConfigTask */
void StartSCD_ConfigTask(void const *argument)
{
  /* USER CODE BEGIN StartSCD_ConfigTask */
  SCD_Config_Task(argument);
  /* USER CODE END StartSCD_ConfigTask */
}

/* USER CODE BEGIN Header_StartSVTask */
/**
 * @brief Function implementing the SVTask thread.
 * @param argument: Not used
 * @retval None
 */
/* USER CODE END Header_StartSVTask */
void StartSVTask(void const *argument)
{
  /* USER CODE BEGIN StartSVTask */
  Sv_Task(argument);
  /* USER CODE END StartSVTask */
}

/* USER CODE BEGIN Header_StartMMSTask */
/**
 * @brief Function implementing the MMSTask thread.
 * @param argument: Not used
 * @retval None
 */
/* USER CODE END Header_StartMMSTask */
void StartMMSTask(void const *argument)
{
  /* USER CODE BEGIN StartMMSTask */
  Mms_Task(argument);
  /* USER CODE END StartMMSTask */
}

/* MPU Configuration */

void MPU_Config(void)
{
  MPU_Region_InitTypeDef MPU_InitStruct = {0};

  /* Disables the MPU */
  HAL_MPU_Disable();

  /** Initializes and configures the Region and the memory to be protected
   */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = 0x0;
  MPU_InitStruct.Size = MPU_REGION_SIZE_4GB;
  MPU_InitStruct.SubRegionDisable = 0x87;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL0;
  MPU_InitStruct.AccessPermission = MPU_REGION_NO_ACCESS;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
  MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  /* Enables the MPU */
  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);
}

/**
 * @brief  Period elapsed callback in non blocking mode
 * @note   This function is called  when TIM6 interrupt took place, inside
 * HAL_TIM_IRQHandler(). It makes a direct call to HAL_IncTick() to increment
 * a global variable "uwTick" used as application time base.
 * @param  htim : TIM handle
 * @retval None
 */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
  /* USER CODE BEGIN Callback 0 */

  /* USER CODE END Callback 0 */
  if (htim->Instance == TIM6)
  {
    HAL_IncTick();
  }
  /* USER CODE BEGIN Callback 1 */

  /* USER CODE END Callback 1 */
}

/**
 * @brief  This function is executed in case of error occurrence.
 * @retval None
 */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
 * @brief  Reports the name of the source file and the source line number
 *         where the assert_param error has occurred.
 * @param  file: pointer to the source file name
 * @param  line: assert_param error line source number
 * @retval None
 */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
   ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

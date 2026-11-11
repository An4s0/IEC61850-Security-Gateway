#include "health_monitor.h"
#include "stm32f7xx_hal.h"
#include "sys_diag.h"
#include "system_logger.h"
#include "FreeRTOS.h"
#include "task.h"

#define IWDG_KEY_RELOAD 0x0000AAAAUL
#define IWDG_KEY_ENABLE 0x0000CCCCUL
#define IWDG_KEY_WRITE_ACCESS 0x00005555UL

#define HEALTH_NO_TASK 0xFFU
#define HEALTH_NOINIT_MAGIC 0x484D4F4EUL

typedef struct
{
    volatile uint32_t last_beat_ms;
    uint32_t max_gap_ms;
    uint32_t misses;
} health_channel_t;

static health_channel_t s_channels[HEALTH_TASK_COUNT];
static HealthMonitor_Stats_t s_stats;
static volatile uint8_t s_enabled = 0;
static uint32_t s_last_service_ms = 0;

static volatile uint32_t s_persist_magic __attribute__((section(".noinit")));
static volatile uint32_t s_persist_fail_task __attribute__((section(".noinit")));
static volatile uint32_t s_persist_withheld __attribute__((section(".noinit")));

#ifndef HEALTH_MEASURE_TIMEOUT
#define HEALTH_MEASURE_TIMEOUT 0
#endif

#define HEALTH_PROBE_MAGIC 0x57444D54UL
#define HEALTH_PROBE_DONE 0x444F4E45UL /
#define HEALTH_PROBE_CYCLES_PER_MS 216000UL

#ifndef HEALTH_PROBE_PR
#define HEALTH_PROBE_PR 6U
#endif
#ifndef HEALTH_PROBE_RLR
#define HEALTH_PROBE_RLR (HEALTH_IWDG_TIMEOUT_MS / 8U)
#endif

static volatile uint32_t s_probe_magic __attribute__((section(".noinit")));
static volatile uint32_t s_probe_start_ms __attribute__((section(".noinit")));
static volatile uint32_t s_probe_stop_ms __attribute__((section(".noinit")));
static volatile uint32_t s_probe_start_cyc __attribute__((section(".noinit")));
static volatile uint32_t s_probe_stop_cyc __attribute__((section(".noinit")));

void HealthMonitor_GetProbe(uint32_t *start_ms, uint32_t *stop_ms, uint32_t *start_cyc, uint32_t *stop_cyc);

static const char *const s_task_names[HEALTH_TASK_COUNT] = {"eth_rx", "goose", "sv", "mms", "storage"};

/**
 * @brief Programs the IWDG prescaler and reload, verifying the latch by
 *        read-back. PR/RLR are dropped until the LSI runs and no update is
 *        pending, so it is retried and also re-run from the service loop if the
 *        first attempt lost the race (otherwise the IWDG silently keeps its
 *        reset defaults of /4 and 4095, i.e. about 512 ms).
 * @return true when the requested configuration is latched.
 */
static bool program_iwdg(void)
{
#if HEALTH_MEASURE_TIMEOUT
    const uint32_t want_pr = HEALTH_PROBE_PR;
    const uint32_t want_rlr = HEALTH_PROBE_RLR;
#else
    const uint32_t want_pr = 6U;
    const uint32_t want_rlr = (HEALTH_IWDG_TIMEOUT_MS / 8U);
#endif

    for (uint32_t wait = 0U; wait < 100000U; wait++)
    {
        if ((RCC->CSR & RCC_CSR_LSIRDY) != 0U)
        {
            break;
        }
    }

    for (uint32_t attempt = 0U; attempt < 10U; attempt++)
    {
        for (volatile uint32_t spin = 0U; spin < 40000U; spin++)
        {
            /* let the LSI settle before touching PR/RLR */
        }

        IWDG->KR = IWDG_KEY_WRITE_ACCESS;
        while (IWDG->SR != 0U)
        {
        }
        IWDG->PR = want_pr;
        while (IWDG->SR != 0U)
        {
        }
        IWDG->RLR = want_rlr;
        while (IWDG->SR != 0U)
        {
        }

        if (((IWDG->PR & 7U) == want_pr) && ((IWDG->RLR & 0xFFFU) == want_rlr))
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Reads back the timestamps captured by the one-shot IWDG timeout probe.
 * @param start_ms Optional output for the tick timestamp taken when the probe was armed.
 * @param stop_ms Optional output for the tick timestamp last sampled before the reset.
 * @param start_cyc Optional output for the DWT cycle count taken when the probe was armed.
 * @param stop_cyc Optional output for the DWT cycle count last sampled before the reset.
 */
void HealthMonitor_GetProbe(uint32_t *start_ms, uint32_t *stop_ms, uint32_t *start_cyc, uint32_t *stop_cyc)
{
    if (start_ms != NULL)
    {
        *start_ms = s_probe_start_ms;
    }
    if (stop_ms != NULL)
    {
        *stop_ms = s_probe_stop_ms;
    }
    if (start_cyc != NULL)
    {
        *start_cyc = s_probe_start_cyc;
    }
    if (stop_cyc != NULL)
    {
        *stop_cyc = s_probe_stop_cyc;
    }
}

/**
 * @brief Initialises the beat channels, reports the reset cause of the previous boot and starts the IWDG.
 */
void HealthMonitor_Init(void)
{
    uint32_t now = HAL_GetTick();

    for (uint32_t i = 0U; i < (uint32_t)HEALTH_TASK_COUNT; i++)
    {
        s_channels[i].last_beat_ms = now;
        s_channels[i].max_gap_ms = 0U;
        s_channels[i].misses = 0U;
    }

    s_last_service_ms = now;
    s_stats.feeds = 0U;
    s_stats.withheld = 0U;
    s_stats.max_service_gap_ms = 0U;
    s_stats.last_fail_task = HEALTH_NO_TASK;
    s_stats.reset_by_iwdg = 0U;

    {
        SysDiag_Stats_t diag;
        SysDiag_Get(&diag);
        const uint32_t flags = diag.reset_flags;

        s_stats.reset_by_iwdg = ((flags & RCC_CSR_IWDGRSTF) != 0U) ? 1U : 0U;

        if (s_stats.reset_by_iwdg != 0U)
        {
            SysLog_Print(SYSLOG_LEVEL_WARN, "HEALTH",
                         "Previous boot was reset by the watchdog after %lu withheld reloads (task %lu)",
                         (unsigned long)s_persist_withheld, (unsigned long)s_persist_fail_task);
        }
        else
        {
            const char *cause = "unknown";
            if ((flags & RCC_CSR_PORRSTF) != 0U)
            {
                cause = "power-on";
            }
            else if ((flags & RCC_CSR_BORRSTF) != 0U)
            {
                cause = "brown-out";
            }
            else if ((flags & RCC_CSR_PINRSTF) != 0U)
            {
                cause = "external NRST";
            }
            else if ((flags & RCC_CSR_SFTRSTF) != 0U)
            {
                cause = "software";
            }
            else if ((flags & RCC_CSR_WWDGRSTF) != 0U)
            {
                cause = "window watchdog";
            }
            else if ((flags & RCC_CSR_LPWRRSTF) != 0U)
            {
                cause = "low-power";
            }
            SysLog_Print(SYSLOG_LEVEL_INFO, "HEALTH",
                         "Previous reset cause: %s (CSR=0x%08lx), not a watchdog reset",
                         cause, (unsigned long)flags);
        }
    }
    s_persist_magic = HEALTH_NOINIT_MAGIC;
    s_persist_fail_task = HEALTH_NO_TASK;
    s_persist_withheld = 0U;

    IWDG->KR = IWDG_KEY_ENABLE;
    s_stats.configured = program_iwdg() ? 1U : 0U;
    IWDG->KR = IWDG_KEY_RELOAD;

    if (s_stats.configured == 0U)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "HEALTH",
                     "IWDG did not accept PR/RLR (PR=%lu RLR=%lu); retrying from the service loop",
                     (unsigned long)(IWDG->PR & 7U), (unsigned long)(IWDG->RLR & 0xFFFU));
    }

    s_enabled = 1U;
    s_stats.enabled = 1U;

#if HEALTH_MEASURE_TIMEOUT
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    DWT->CYCCNT = 0U;

    if (s_probe_magic == HEALTH_PROBE_MAGIC)
    {
        s_probe_magic = HEALTH_PROBE_DONE;
    }
    else if (s_probe_magic != HEALTH_PROBE_DONE)
    {
        s_probe_magic = 0U;
        s_probe_start_ms = 0U;
        s_probe_stop_ms = 0U;
        s_probe_start_cyc = 0U;
        s_probe_stop_cyc = 0U;
    }
#endif
}

/**
 * @brief Records a progress beat for one supervised task.
 * @param id Task channel that just ran; out of range values are ignored.
 */
void HealthMonitor_Beat(HealthTaskId_t id)
{
    if ((uint32_t)id >= (uint32_t)HEALTH_TASK_COUNT)
    {
        return;
    }

#if HEALTH_INJECT_TASK >= 0
    if ((int)id == HEALTH_INJECT_TASK)
    {
        return; /* test-only: never reports progress */
    }
#endif

    uint32_t now = HAL_GetTick();
    uint32_t previous = s_channels[id].last_beat_ms;
    uint32_t gap = now - previous;

    if (gap > s_channels[id].max_gap_ms)
    {
        s_channels[id].max_gap_ms = gap;
    }
    s_channels[id].last_beat_ms = now;
}

/**
 * @brief Checks every task beat and either reloads the IWDG or withholds the reload.
 */
void HealthMonitor_Service(void)
{
    if (s_enabled == 0U)
    {
        return;
    }

#if HEALTH_MEASURE_TIMEOUT
    if (s_probe_magic == HEALTH_PROBE_MAGIC)
    {
        for (;;)
        {
            s_probe_stop_ms = HAL_GetTick();
            s_probe_stop_cyc = DWT->CYCCNT;
        }
    }

    if (s_probe_magic == 0U && HAL_GetTick() >= 5000U)
    {
        s_probe_magic = HEALTH_PROBE_MAGIC;
        s_probe_start_ms = HAL_GetTick();
        s_probe_start_cyc = DWT->CYCCNT;
        s_probe_stop_ms = s_probe_start_ms;
        s_probe_stop_cyc = s_probe_start_cyc;
        IWDG->KR = IWDG_KEY_RELOAD;
        return;
    }
#endif

    uint32_t now = HAL_GetTick();
    uint32_t service_gap = now - s_last_service_ms;
    s_last_service_ms = now;

    if (s_stats.configured == 0U && program_iwdg())
    {
        s_stats.configured = 1U;
        IWDG->KR = IWDG_KEY_RELOAD;
    }

    if (service_gap > s_stats.max_service_gap_ms)
    {
        s_stats.max_service_gap_ms = service_gap;
    }

    uint8_t fail_task = HEALTH_NO_TASK;

    for (uint32_t i = 0U; i < (uint32_t)HEALTH_TASK_COUNT; i++)
    {
        if ((now - s_channels[i].last_beat_ms) > HEALTH_TASK_DEADLINE_MS)
        {
            if (s_channels[i].misses != UINT32_MAX)
            {
                s_channels[i].misses++;
            }
            if (fail_task == HEALTH_NO_TASK)
            {
                fail_task = (uint8_t)i;
            }
        }
    }

    if (fail_task == HEALTH_NO_TASK)
    {
        s_stats.last_fail_task = HEALTH_NO_TASK;
        if (s_stats.feeds != UINT32_MAX)
        {
            s_stats.feeds++;
        }
        IWDG->KR = IWDG_KEY_RELOAD;
        return;
    }

    s_stats.last_fail_task = fail_task;
    if (s_stats.withheld != UINT32_MAX)
    {
        s_stats.withheld++;
    }
    s_persist_fail_task = fail_task;
    s_persist_withheld = s_stats.withheld;
}

/**
 * @brief Copies the health statistics and the per-task maximum beat gaps out atomically.
 * @param out Destination structure; the call is ignored when NULL.
 */
void HealthMonitor_GetStats(HealthMonitor_Stats_t *out)
{
    if (out == NULL)
    {
        return;
    }

    taskENTER_CRITICAL();
    *out = s_stats;
    for (uint32_t i = 0U; i < (uint32_t)HEALTH_TASK_COUNT; i++)
    {
        out->max_beat_gap_ms[i] = s_channels[i].max_gap_ms;
    }
    taskEXIT_CRITICAL();
}

/**
 * @brief Maps a supervised task index to its printable name.
 * @param id Task channel index.
 * @return Constant task name, or "none" when the index is out of range.
 */
const char *HealthMonitor_TaskName(uint8_t id)
{
    return (id < HEALTH_TASK_COUNT) ? s_task_names[id] : "none";
}

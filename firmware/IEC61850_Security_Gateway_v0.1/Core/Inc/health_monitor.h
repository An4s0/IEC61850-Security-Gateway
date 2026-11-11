#ifndef HEALTH_MONITOR_H
#define HEALTH_MONITOR_H

#include <stdint.h>

typedef enum
{
    HEALTH_TASK_ETH_RX = 0,
    HEALTH_TASK_GOOSE,
    HEALTH_TASK_SV,
    HEALTH_TASK_MMS,
    HEALTH_TASK_STORAGE,
    HEALTH_TASK_COUNT
} HealthTaskId_t;

#define HEALTH_BEAT_PERIOD_MS 250U
#define HEALTH_TASK_DEADLINE_MS (3U * HEALTH_BEAT_PERIOD_MS)

#ifndef HEALTH_IWDG_TIMEOUT_MS
#define HEALTH_IWDG_TIMEOUT_MS 8000U
#endif

#ifndef HEALTH_INJECT_TASK
#define HEALTH_INJECT_TASK (-1)
#endif

typedef struct
{
    uint32_t feeds;
    uint32_t withheld;
    uint32_t max_service_gap_ms;
    uint32_t max_beat_gap_ms[HEALTH_TASK_COUNT];
    uint32_t misses[HEALTH_TASK_COUNT];
    uint8_t last_fail_task;
    uint8_t reset_by_iwdg;
    uint8_t enabled;
    uint8_t configured;
} HealthMonitor_Stats_t;

void HealthMonitor_Init(void);
void HealthMonitor_Beat(HealthTaskId_t id);
void HealthMonitor_Service(void);
void HealthMonitor_GetStats(HealthMonitor_Stats_t *out);
void HealthMonitor_GetProbe(uint32_t *start_ms, uint32_t *stop_ms, uint32_t *start_cyc, uint32_t *stop_cyc);
const char *HealthMonitor_TaskName(uint8_t id);

#endif /* HEALTH_MONITOR_H */

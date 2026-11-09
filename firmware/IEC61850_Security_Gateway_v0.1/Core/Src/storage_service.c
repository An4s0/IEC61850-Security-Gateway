#include "storage_service.h"
#include "security.h"
#include "system_config.h"
#include "system_logger.h"
#include "fatfs.h"
#include "ff.h"
#include "cmsis_os.h"
#include "stm32f7xx_hal.h"
#include <string.h>

#define STORAGE_HISTORY_LINE_MAX 512
#define STORAGE_LOCK_TIMEOUT_MS 1000
#define STORAGE_CLEAR_DRAIN_MS 2000

osMessageQDef(StorageServiceQueue, STORAGE_QUEUE_DEPTH, uint32_t);

static osMessageQId s_queue = NULL;
static StorageRequest_t s_requests[STORAGE_MAX_REQUESTS];
static StorageCompleteHook_t s_complete_hook = NULL;
static StorageService_Stats_t s_stats;

static char s_history_line[STORAGE_HISTORY_LINE_MAX];

static void storage_stat_inc(uint32_t *field)
{
    taskENTER_CRITICAL();
    if (*field != UINT32_MAX)
    {
        (*field)++;
    }
    taskEXIT_CRITICAL();
}

void StorageService_Init(void)
{
    if (s_queue == NULL)
    {
        s_queue = osMessageCreate(osMessageQ(StorageServiceQueue), NULL);
    }
    memset(&s_stats, 0, sizeof(s_stats));
}

void StorageService_SetCompleteHook(StorageCompleteHook_t hook)
{
    s_complete_hook = hook;
}

StorageRequest_t *StorageService_Acquire(void)
{
    StorageRequest_t *found = NULL;
    taskENTER_CRITICAL();
    for (int i = 0; i < STORAGE_MAX_REQUESTS; i++)
    {
        if (s_requests[i].state == STORAGE_REQ_FREE)
        {
            memset(&s_requests[i], 0, sizeof(StorageRequest_t));
            s_requests[i].state = STORAGE_REQ_PENDING;
            s_requests[i].buf_idx = -1;
            s_requests[i].submitted_ms = HAL_GetTick();
            found = &s_requests[i];
            break;
        }
    }
    taskEXIT_CRITICAL();
    return found;
}

bool StorageService_Submit(StorageRequest_t *req)
{
    if (req == NULL || s_queue == NULL)
    {
        return false;
    }

    storage_stat_inc(&s_stats.submitted);

    if (osMessagePut(s_queue, (uint32_t)req, 0) != osOK)
    {
        storage_stat_inc(&s_stats.queue_full);
        req->state = STORAGE_REQ_FREE;
        return false;
    }

    return true;
}

void StorageService_Release(StorageRequest_t *req)
{
    if (req == NULL)
    {
        return;
    }
    taskENTER_CRITICAL();
    req->state = STORAGE_REQ_FREE;
    req->out = NULL;
    req->ctx = NULL;
    req->buf_idx = -1;
    taskEXIT_CRITICAL();
}

void StorageService_SetQueueHighWater(uint32_t depth)
{
    taskENTER_CRITICAL();
    if (depth > s_stats.queue_high_water)
    {
        s_stats.queue_high_water = depth;
    }
    taskEXIT_CRITICAL();
}

void StorageService_GetStats(StorageService_Stats_t *out)
{
    if (out == NULL)
    {
        return;
    }
    taskENTER_CRITICAL();
    *out = s_stats;
    taskEXIT_CRITICAL();
}

/**
 * @brief Appends matching NDJSON records from the alert log to the request buffer.
 *        Executes exclusively in the storage-owner task.
 */
static bool storage_do_alert_history(StorageRequest_t *req)
{
    if (req->out == NULL || req->out_cap == 0)
    {
        return false;
    }

    if (!Security_LockSD(STORAGE_LOCK_TIMEOUT_MS))
    {
        storage_stat_inc(&s_stats.lock_timeouts);
        return false;
    }

    FIL file;
    memset(&file, 0, sizeof(file));
    FRESULT res = f_open(&file, SECURITY_ALERTS_FILE, FA_READ);
    if (res != FR_OK)
    {
        Security_UnlockSD();
        /* A missing log is an empty history, not a failure. */
        req->records_read = 0;
        return (res == FR_NO_FILE || res == FR_NO_PATH);
    }

    uint32_t seen = 0;
    uint32_t read = 0;
    uint32_t off = req->out_used;

    if (off > req->out_cap)
    {
        off = req->out_cap;
    }

    while (read < req->limit && (req->out_cap - off) > 520)
    {
        if (f_gets(s_history_line, sizeof(s_history_line), &file) == NULL)
        {
            break;
        }

        size_t slen = strlen(s_history_line);
        while (slen > 0 && (s_history_line[slen - 1] == '\r' || s_history_line[slen - 1] == '\n'))
        {
            s_history_line[--slen] = '\0';
        }

        if (slen == 0)
        {
            continue;
        }

        if (seen++ < req->offset)
        {
            continue;
        }

        if (read > 0)
        {
            req->out[off++] = ',';
        }

        if ((req->out_cap - off) <= slen)
        {
            if (read > 0)
            {
                off--; /* drop the separator we just added */
            }
            break;
        }

        memcpy(&req->out[off], s_history_line, slen);
        off += slen;
        read++;
    }

    if (f_close(&file) != FR_OK)
    {
        Security_UnlockSD();
        return false;
    }

    Security_UnlockSD();
    req->out_used = off;
    req->records_read = read;
    return true;
}

/**
 * @brief Clears the alert log. Drains any in-flight record first so that a
 *        record cannot be appended after the file has been truncated.
 */
static bool storage_do_alert_clear(StorageRequest_t *req)
{
    uint32_t waited = 0;
    while (Security_HasPendingAlert() && waited < STORAGE_CLEAR_DRAIN_MS)
    {
        Security_PeriodicFlush();
        if (Security_HasPendingAlert())
        {
            osDelay(10);
            waited += 10;
        }
    }

    if (Security_HasPendingAlert())
    {
        return false;
    }

    if (!Security_ClearAlertsOnSD())
    {
        return false;
    }

    uint32_t purged = Security_PurgePendingAlerts();
    (void)req;
    if (purged != 0U)
    {
        taskENTER_CRITICAL();
        s_stats.alerts_purged += purged;
        taskEXIT_CRITICAL();
    }
    return true;
}

static bool storage_do_config_save(StorageRequest_t *req)
{
    (void)req;
    return SystemConfig_SaveToSD();
}

static bool storage_dispatch(StorageRequest_t *req)
{
    switch ((StorageOp_t)req->op)
    {
    case STORAGE_OP_ALERT_HISTORY:
        return storage_do_alert_history(req);
    case STORAGE_OP_ALERT_CLEAR:
        return storage_do_alert_clear(req);
    case STORAGE_OP_CONFIG_SAVE:
        return storage_do_config_save(req);
    default:
        return false;
    }
}

void StorageService_Run(void)
{
    /* Background maintenance keeps the alert and system logs drained; it is
     * bounded by the SD mutex zero-wait policy inside the called functions. */
    Security_PeriodicFlush();

    osEvent evt = osMessageGet(s_queue, 0);
    if (evt.status == osEventMessage)
    {
        StorageRequest_t *req = (StorageRequest_t *)evt.value.p;
        if (req != NULL && req->state == STORAGE_REQ_PENDING)
        {
            req->state = STORAGE_REQ_RUNNING;
            bool ok = storage_dispatch(req);
            req->ok = ok ? 1U : 0U;
            req->state = STORAGE_REQ_DONE;

            if (ok)
            {
                storage_stat_inc(&s_stats.completed_ok);
            }
            else
            {
                storage_stat_inc(&s_stats.completed_fail);
            }

            if (s_complete_hook != NULL)
            {
                s_complete_hook(req);
            }
            else
            {
                StorageService_Release(req);
            }
        }
        else if (req != NULL)
        {
            StorageService_Release(req);
        }
    }

    SysLog_PeriodicFlush();
}

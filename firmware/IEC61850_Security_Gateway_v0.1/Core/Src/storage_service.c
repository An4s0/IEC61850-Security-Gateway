#include "storage_service.h"
#include "security.h"
#include "system_config.h"
#include "system_logger.h"
#include "fatfs.h"
#include "ff.h"
#include "cmsis_os.h"
#include "stm32f7xx_hal.h"
#include "sdmmc.h"
#include "user_diskio.h"
#include <string.h>

#define STORAGE_HISTORY_LINE_MAX 512
#define STORAGE_PAGE_BLOCK 2048
#define STORAGE_PAGE_MAX_RECORDS 40
#define STORAGE_FILTER_PREFIX 224
#define STORAGE_LOCK_TIMEOUT_MS 1000
#define STORAGE_CLEAR_DRAIN_MS 2000

#define SD_MEDIA_POLL_MS 200U
#define SD_MEDIA_DEBOUNCE_SAMPLES 3U
#define SD_MEDIA_REMOUNT_RETRY_MS 2000U
#define SD_MEDIA_REMOUNT_MAX_TRIES 5U
#define SD_MEDIA_LOCK_TIMEOUT_MS 500U

osMessageQDef(StorageServiceQueue, STORAGE_QUEUE_DEPTH, uint32_t);

static osMessageQId s_queue = NULL;
static StorageRequest_t s_requests[STORAGE_MAX_REQUESTS];
static StorageCompleteHook_t s_complete_hook = NULL;
static StorageService_Stats_t s_stats;

typedef struct
{
    bool initialized;
    bool drive_ready;
    bool pin_raw;
    bool pin_present;
    uint32_t pin_stable;
    bool mounted;
    uint32_t last_poll_ms;
    uint32_t last_attempt_ms;
    uint32_t tries;
    uint32_t removals;
    uint32_t insertions;
    uint32_t faults;
    uint32_t recoveries;
    uint32_t attempts;
    uint32_t succeeded;
    uint32_t failed;
    uint32_t verify_failures;
    uint32_t lock_timeouts;
} SdMediaState_t;

static SdMediaState_t s_media;

static char s_history_line[STORAGE_HISTORY_LINE_MAX];
static char s_filter_prefix[STORAGE_FILTER_PREFIX];

static const char *const s_proto_patterns[] = {
    NULL, "\"proto\":\"GOOSE\"", "\"proto\":\"SV\"", "\"proto\":\"MMS\""};
static const char *const s_sev_patterns[] = {
    NULL, "\"sev\":\"INFO\"", "\"sev\":\"WARNING\"", "\"sev\":\"HIGH\"",
    "\"sev\":\"CRITICAL\""};

/**
 * @brief Tests one NUL-terminated record prefix against the request filters.
 * @param text Record prefix to test.
 * @param req Request carrying the protocol and severity filters.
 * @return true when the record passes both filters, false when it is excluded.
 */
static bool alert_prefix_matches(const char *text, const StorageRequest_t *req)
{
    if (req->proto_filter != STORAGE_ALERT_PROTO_ANY)
    {
        if (req->proto_filter > STORAGE_ALERT_PROTO_MMS ||
            s_proto_patterns[req->proto_filter] == NULL ||
            strstr(text, s_proto_patterns[req->proto_filter]) == NULL)
        {
            return false;
        }
    }
    if (req->sev_filter != STORAGE_ALERT_SEV_ANY)
    {
        if (req->sev_filter > STORAGE_ALERT_SEV_CRITICAL ||
            s_sev_patterns[req->sev_filter] == NULL ||
            strstr(text, s_sev_patterns[req->sev_filter]) == NULL)
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Tests one stored record against the request filters, reading only the
 *        fixed prefix that carries the "proto" and "sev" fields.
 *        Executes in the storage-owner task with the log file already open.
 * @param file Open alert log.
 * @param blk Block currently cached from the log.
 * @param blk_start File offset of blk[0].
 * @param blk_len Number of valid bytes in blk.
 * @param start File offset of the record.
 * @param len Record length in bytes.
 * @param req Request carrying the filters.
 * @return true when the record passes the filters, false when excluded or unreadable.
 */
static bool alert_record_matches(FIL *file, const char *blk, uint32_t blk_start,
                                 UINT blk_len, uint32_t start, uint32_t len,
                                 const StorageRequest_t *req)
{
    uint32_t take = (len < (uint32_t)STORAGE_FILTER_PREFIX - 1U)
                        ? len
                        : (uint32_t)STORAGE_FILTER_PREFIX - 1U;

    if (take == 0U)
    {
        return true;
    }

    if (start >= blk_start && (start - blk_start) + take <= blk_len)
    {
        memcpy(s_filter_prefix, &blk[start - blk_start], take);
        s_filter_prefix[take] = '\0';
        return alert_prefix_matches(s_filter_prefix, req);
    }

    UINT got = 0;
    if (f_lseek(file, start) != FR_OK)
    {
        return false;
    }
    if (f_read(file, s_filter_prefix, take, &got) != FR_OK || got != take)
    {
        return false;
    }
    s_filter_prefix[take] = '\0';
    return alert_prefix_matches(s_filter_prefix, req);
}

/**
 * @brief Increments a statistics counter without wrapping.
 * @param field Counter to increment, saturated at UINT32_MAX.
 */
static void storage_stat_inc(uint32_t *field)
{
    taskENTER_CRITICAL();
    if (*field != UINT32_MAX)
    {
        (*field)++;
    }
    taskEXIT_CRITICAL();
}

/**
 * @brief Creates the storage request queue and clears the service statistics.
 */
void StorageService_Init(void)
{
    if (s_queue == NULL)
    {
        s_queue = osMessageCreate(osMessageQ(StorageServiceQueue), NULL);
    }
    memset(&s_stats, 0, sizeof(s_stats));
}

/**
 * @brief Installs the callback invoked when a request completes.
 * @param hook Completion hook, or NULL to release completed requests directly.
 */
void StorageService_SetCompleteHook(StorageCompleteHook_t hook)
{
    s_complete_hook = hook;
}

/**
 * @brief Reserves a free request slot and marks it pending.
 * @return Pointer to the reserved request, or NULL when every slot is in use.
 */
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

/**
 * @brief Queues a reserved request for execution by the storage-owner task.
 * @param req Request previously obtained from StorageService_Acquire().
 * @return true when queued, false when the request is invalid or the queue is full.
 */
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

/**
 * @brief Returns a request slot to the free pool.
 * @param req Request to release; ignored when NULL.
 */
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

/**
 * @brief Raises the recorded queue-depth high-water mark.
 * @param depth Observed queue depth.
 */
void StorageService_SetQueueHighWater(uint32_t depth)
{
    taskENTER_CRITICAL();
    if (depth > s_stats.queue_high_water)
    {
        s_stats.queue_high_water = depth;
    }
    taskEXIT_CRITICAL();
}

/**
 * @brief Copies the service statistics out atomically.
 * @param out Destination structure; ignored when NULL.
 */
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
 * @brief Reports SD media state, combining the disk driver counters with the media supervisor state.
 * @param out Destination structure; ignored when NULL.
 */
void StorageService_GetMediaStats(StorageService_MediaStats_t *out)
{
    USER_DiskioStats_t disk;
    if (out == NULL)
    {
        return;
    }
    USER_Diskio_GetStats(&disk);
    taskENTER_CRITICAL();
    out->card_present = SDMMC_IsCardInserted() ? 1U : 0U;
    out->drive_ready = disk.not_ready ? 0U : 1U;
    out->mounted = s_media.mounted ? 1U : 0U;
    out->removals = s_media.removals;
    out->insertions = s_media.insertions;
    out->drive_faults = s_media.faults;
    out->drive_recoveries = s_media.recoveries;
    out->remount_attempts = s_media.attempts;
    out->remount_ok = s_media.succeeded;
    out->remount_fail = s_media.failed;
    out->verify_failures = s_media.verify_failures;
    out->disk_init_attempts = disk.init_attempts;
    out->disk_init_failures = disk.init_failures;
    taskEXIT_CRITICAL();
}

/**
 * @brief Drops the FatFs mount so no reader keeps stale volume state.
 *
 * Only the file-system object is invalidated; the volume stays registered,
 * because an unregistered volume makes every later file call return
 * FR_NOT_ENABLED without ever re-initialising the card. Keeping it registered is
 * what lets FatFs retry disk_initialize() and recover the card.
 */
static void sd_media_invalidate(void)
{
    if (Security_LockSD(SD_MEDIA_LOCK_TIMEOUT_MS))
    {
        (void)f_mount(&USERFatFS, (TCHAR const *)USERPath, 0);
        Security_UnlockSD();
    }
    s_media.mounted = false;
    s_media.tries = 0;
}

/**
 * @brief Unmounts, remounts and verifies the volume before writes may resume.
 *        Called from the storage-owner task only.
 */
static void sd_media_try_mount(void)
{
    s_media.attempts++;
    s_media.last_attempt_ms = HAL_GetTick();

    if (!Security_LockSD(SD_MEDIA_LOCK_TIMEOUT_MS))
    {
        s_media.failed++;
        s_media.tries++;
        s_media.lock_timeouts++;
        return;
    }

    FRESULT res = f_mount(&USERFatFS, (TCHAR const *)USERPath, 1);
    if (res == FR_OK)
    {
        DIR dir;
        memset(&dir, 0, sizeof(dir));
        res = f_opendir(&dir, "/");
        if (res == FR_OK)
        {
            (void)f_closedir(&dir);
        }
        else
        {
            s_media.verify_failures++;
            (void)f_mount(&USERFatFS, (TCHAR const *)USERPath, 0);
        }
    }

    Security_UnlockSD();

    if (res == FR_OK)
    {
        s_media.mounted = true;
        s_media.succeeded++;
        s_media.tries = SD_MEDIA_REMOUNT_MAX_TRIES;
    }
    else
    {
        s_media.mounted = false;
        s_media.failed++;
        s_media.tries++;
    }

    SysLog_Print((res == FR_OK) ? SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_WARN, "SD",
                 "Storage remount %s (attempt %lu, failures=%lu, res=%d)",
                 (res == FR_OK) ? "succeeded" : "failed",
                 (unsigned long)s_media.attempts, (unsigned long)s_media.failed,
                 (int)res);
}

/**
 * @brief Supervises SD media presence: detection, remount and bounded retry.
 *
 * Runs in the storage-owner task. Never called from an interrupt, the RX path or
 * a lwIP callback, so FatFs access stays single-threaded by construction.
 *
 * Two independent detectors are used: the debounced card-detect switch (fast,
 * but only an optimisation) and the drive state reported by user_diskio.c, which
 * marks the drive STA_NOINIT after any failed transfer. Recovery depends on
 * neither alone: the mount attempts below re-run the card initialisation, so a
 * card that returns is picked up even if the switch never reports an edge.
 */
void StorageService_MediaService(void)
{
    uint32_t now = HAL_GetTick();

    if ((now - s_media.last_poll_ms) < SD_MEDIA_POLL_MS)
    {
        return;
    }
    s_media.last_poll_ms = now;

    bool ready = USER_Diskio_IsReady();
    bool pin_present = SDMMC_IsCardInserted();

    if (!s_media.initialized)
    {
        s_media.initialized = true;
        s_media.drive_ready = ready;
        s_media.pin_raw = pin_present;
        s_media.pin_present = pin_present;
        s_media.mounted = false;
        s_media.tries = 0;
    }

    if (pin_present != s_media.pin_raw)
    {
        s_media.pin_raw = pin_present;
        s_media.pin_stable = 0;
    }
    else if (s_media.pin_stable < SD_MEDIA_DEBOUNCE_SAMPLES)
    {
        s_media.pin_stable++;
    }
    else if (pin_present != s_media.pin_present)
    {
        s_media.pin_present = pin_present;
        s_media.tries = 0;

        if (pin_present)
        {
            s_media.insertions++;
        }
        else
        {
            s_media.removals++;
            sd_media_invalidate();
            SysLog_Print(SYSLOG_LEVEL_WARN, "SD",
                         "SD card removed; pending alerts kept in RAM (removals=%lu)",
                         (unsigned long)s_media.removals);
        }
    }

    if (ready != s_media.drive_ready)
    {
        s_media.drive_ready = ready;

        if (ready)
        {
            s_media.recoveries++;
            s_media.tries = 0;
        }
        else
        {
            s_media.faults++;
            sd_media_invalidate();
        }
    }

    if (s_media.mounted || (s_media.tries >= SD_MEDIA_REMOUNT_MAX_TRIES) ||
        ((s_media.tries != 0U) && ((now - s_media.last_attempt_ms) < SD_MEDIA_REMOUNT_RETRY_MS)))
    {
        return;
    }

    sd_media_try_mount();
}

/**
 * @brief Appends matching NDJSON records from the alert log to the request buffer.
 *        Executes exclusively in the storage-owner task.
 * @param req Request supplying the output buffer, filters, offset and limit.
 * @return true when the scan completed (an absent log counts as an empty history),
 *         false on lock or access error.
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

        if (!alert_prefix_matches(s_history_line, req))
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
                off--;
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
 * @brief Emits one page of alerts in newest-first order.
 *
 * The alert log is append-only NDJSON, so the newest record is at the end of the
 * file. Scanning backwards from the requested cursor keeps each page at O(page)
 * work and never loads the whole history. The cursor returned to the client is
 * the byte offset of the oldest record in the page, which stays valid while new
 * records are appended at the end.
 * @param req Request carrying cursor_in, filters, limit and the output buffer.
 * @return true when the page was produced, false on lock or access error.
 */
static bool storage_do_alert_page(StorageRequest_t *req)
{
    static char block[STORAGE_PAGE_BLOCK];
    uint32_t starts[STORAGE_PAGE_MAX_RECORDS];
    uint32_t lengths[STORAGE_PAGE_MAX_RECORDS];
    uint16_t found = 0;

    uint32_t limit = req->limit;
    if (limit == 0U || limit > STORAGE_PAGE_MAX_RECORDS)
    {
        limit = STORAGE_PAGE_MAX_RECORDS;
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
        req->records_read = 0;
        req->cursor_out = 0;
        req->has_more = 0;
        return (res == FR_NO_FILE || res == FR_NO_PATH);
    }

    FSIZE_t size = f_size(&file);
    uint32_t scan = (req->cursor_in == UINT32_MAX || req->cursor_in > (uint32_t)size)
                        ? (uint32_t)size
                        : req->cursor_in;

    uint32_t block_start = 0;
    UINT block_len = 0;
    uint32_t line_len = 0;

    while (scan > 0U && found < limit)
    {
        scan--;

        if (scan < block_start || scan >= block_start + block_len)
        {
            uint32_t upper = scan + 1U;
            block_start = (upper > STORAGE_PAGE_BLOCK) ? (upper - STORAGE_PAGE_BLOCK) : 0U;
            UINT got = 0;
            res = f_lseek(&file, block_start);
            if (res == FR_OK)
            {
                res = f_read(&file, block, (UINT)(upper - block_start), &got);
            }
            if (res != FR_OK)
            {
                break;
            }
            block_len = got;
        }

        char c = block[scan - block_start];
        if (c == '\n')
        {
            if (line_len > 0U)
            {
                uint32_t rec_start = scan + 1U;
                bool accept = true;

                if (req->proto_filter != STORAGE_ALERT_PROTO_ANY ||
                    req->sev_filter != STORAGE_ALERT_SEV_ANY)
                {
                    accept = alert_record_matches(&file, block, block_start, block_len,
                                                  rec_start, line_len, req);
                }

                if (accept)
                {
                    starts[found] = rec_start;
                    lengths[found] = line_len;
                    found++;
                }
                line_len = 0;
            }
        }
        else if (c != '\r')
        {
            line_len++;
        }
    }

    if (found < limit && line_len > 0U && scan == 0U)
    {
        bool accept = true;
        if (req->proto_filter != STORAGE_ALERT_PROTO_ANY ||
            req->sev_filter != STORAGE_ALERT_SEV_ANY)
        {
            accept = alert_record_matches(&file, block, block_start, block_len, 0U,
                                          line_len, req);
        }
        if (accept)
        {
            starts[found] = 0U;
            lengths[found] = line_len;
            found++;
        }
    }

    if (res != FR_OK)
    {
        (void)f_close(&file);
        Security_UnlockSD();
        return false;
    }

    uint32_t off = req->out_used;
    uint32_t emitted = 0;

    for (uint16_t i = 0; i < found; i++)
    {
        uint32_t len = lengths[i];
        uint32_t room = req->out_cap - off;
        uint32_t needed = len + 80U; /* leave room for the JSON suffix */

        if (len == 0U || room <= needed)
        {
            break;
        }
        if (emitted > 0U)
        {
            req->out[off++] = ',';
        }

        res = f_lseek(&file, starts[i]);
        if (res != FR_OK)
        {
            break;
        }
        UINT got = 0;
        res = f_read(&file, &req->out[off], len, &got);
        if (res != FR_OK || got != len)
        {
            break;
        }

        off += len;
        if (off > 0U && req->out[off - 1U] == '\r')
        {
            off--;
        }
        emitted++;
    }

    (void)f_close(&file);
    Security_UnlockSD();

    req->out_used = off;
    req->records_read = emitted;

    if (emitted > 0U)
    {
        req->cursor_out = starts[emitted - 1U];
        req->has_more = (starts[emitted - 1U] > 0U) ? 1U : 0U;
    }
    else
    {
        req->cursor_out = 0U;
        req->has_more = 0U;
    }

    return true;
}

/**
 * @brief Clears the alert log. Drains any in-flight record first so that a
 *        record cannot be appended after the file has been truncated.
 * @param req Unused request context.
 * @return true when the log was cleared, false when pending records could not be drained
 *         or the truncation failed.
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

/**
 * @brief Persists the active configuration from the storage-owner task.
 * @param req Unused request context.
 * @return true when the configuration was written, false otherwise.
 */
static bool storage_do_config_save(StorageRequest_t *req)
{
    (void)req;
    return SystemConfig_SaveToSD();
}

/**
 * @brief Routes a request to the handler for its operation.
 * @param req Request to execute.
 * @return true when the handler reported success, false on failure or an unknown operation.
 */
static bool storage_dispatch(StorageRequest_t *req)
{
    switch ((StorageOp_t)req->op)
    {
    case STORAGE_OP_ALERT_HISTORY:
        return storage_do_alert_history(req);
    case STORAGE_OP_ALERT_PAGE:
        return storage_do_alert_page(req);
    case STORAGE_OP_ALERT_CLEAR:
        return storage_do_alert_clear(req);
    case STORAGE_OP_CONFIG_SAVE:
        return storage_do_config_save(req);
    default:
        return false;
    }
}

/**
 * @brief One iteration of the storage-owner task: supervise the media, flush logs and run one request.
 */
void StorageService_Run(void)
{
    StorageService_MediaService();

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

    osDelay(Security_HasPendingAlert() ? 1 : 100);
}

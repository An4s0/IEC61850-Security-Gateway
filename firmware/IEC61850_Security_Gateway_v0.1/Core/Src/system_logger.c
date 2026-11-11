#include "system_logger.h"
#include "security.h"
#include "cmsis_os.h"
#include "fatfs.h"
#include "ff.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

typedef struct
{
    char msg[SYSLOG_ENTRY_MAX_LEN];
} SysLogEntry_t;

static SysLogEntry_t s_log_queue[SYSLOG_QUEUE_DEPTH];
static uint16_t s_head = 0;
static uint16_t s_tail = 0;
static uint16_t s_count = 0;

static osMutexId s_syslog_mutex = NULL;
osMutexDef(SysLogMutex);

static uint32_t s_total_logged = 0;
static uint32_t s_total_dropped = 0;
static uint32_t s_rotations = 0;
static bool s_initialized = false;

static SysLog_Stats_t s_stats;
static bool s_segment_known = false;
static bool s_full_reported = false;
static uint8_t s_repair_buf[256];

/**
 * @brief Converts a log level enum to its string representation.
 * @param level Log level value.
 * @return Constant string label.
 */
static const char *level_to_string(SysLogLevel_t level)
{
    switch (level)
    {
    case SYSLOG_LEVEL_DEBUG:
        return "DEBUG";
    case SYSLOG_LEVEL_INFO:
        return "INFO ";
    case SYSLOG_LEVEL_WARN:
        return "WARN ";
    case SYSLOG_LEVEL_ERROR:
        return "ERROR";
    case SYSLOG_LEVEL_CRITICAL:
        return "CRIT ";
    default:
        return "LOG  ";
    }
}

/**
 * @brief Moves a legacy file to its new location, keeping the destination if both exist.
 * @param src Legacy file path.
 * @param dst Current file path.
 */
static void migrate_file(const char *src, const char *dst)
{
    FILINFO fno;
    if (f_stat(src, &fno) == FR_OK)
    {
        if (f_stat(dst, &fno) != FR_OK)
        {
            FRESULT r = f_rename(src, dst);
            if (r == FR_OK)
            {
                SysLog_Print(SYSLOG_LEVEL_INFO, "STORAGE", "Migrated legacy file %s -> %s", src, dst);
            }
        }
        else
        {
            f_unlink(src);
        }
    }
}

/**
 * @brief Ensures the standard SD directory hierarchy exists and migrates legacy root files.
 */
void Storage_EnsureDirectories(void)
{
    f_mkdir("0:/config");
    f_mkdir("0:/substation");
    f_mkdir("0:/alerts");
    f_mkdir("0:/logs");

    migrate_file("0:/substation.json", "0:/substation/substation.json");
    migrate_file("0:/ids_config.bin", "0:/config/ids_config.bin");
    migrate_file("0:/alerts.json", "0:/alerts/alerts.ndjson");
}

/**
 * @brief Initializes the system logger module and RAM queue.
 */
void SysLog_Init(void)
{
    if (s_initialized)
    {
        return;
    }

    if (s_syslog_mutex == NULL)
    {
        s_syslog_mutex = osMutexCreate(osMutex(SysLogMutex));
    }

    s_head = 0;
    s_tail = 0;
    s_count = 0;
    s_initialized = true;

    Storage_EnsureDirectories();
}

/**
 * @brief Non-blocking logging function safe to call from any FreeRTOS thread.
 *        Never blocks on physical SD I/O or FatFS locks.
 *
 * @param level Log severity level.
 * @param module Tag/module identifier (e.g. "SYS", "ETH", "SD", "HTTP", "CONFIG", "SCD").
 * @param fmt printf-style format string.
 */
void SysLog_Print(SysLogLevel_t level, const char *module, const char *fmt, ...)
{
    char formatted_msg[128];
    va_list args;
    va_start(args, fmt);
    vsnprintf(formatted_msg, sizeof(formatted_msg), fmt, args);
    va_end(args);

    uint32_t now = HAL_GetTick();
    uint32_t sec = now / 1000;
    uint32_t ms = now % 1000;

    char full_entry[SYSLOG_ENTRY_MAX_LEN];
    int len = snprintf(full_entry, sizeof(full_entry), "[%lu.%03lu] [%s] [%s] %s\n",
                       (unsigned long)sec, (unsigned long)ms,
                       level_to_string(level),
                       module ? module : "SYS",
                       formatted_msg);

    if (len <= 0)
    {
        return;
    }

    bool print_to_serial = false;
    if (level >= SYSLOG_LEVEL_WARN)
    {
        print_to_serial = true;
    }
    else if (level == SYSLOG_LEVEL_INFO)
    {
        if (module != NULL && (strcmp(module, "BOOT") == 0 ||
                               strcmp(module, "NET") == 0 ||
                               strcmp(module, "ETH") == 0 ||
                               strcmp(module, "SCD") == 0 ||
                               strcmp(module, "CONFIG") == 0))
        {
            print_to_serial = true;
        }
    }

    if (print_to_serial)
    {
        if (level >= SYSLOG_LEVEL_ERROR)
        {
            printf("[%s] ERROR: %s\r\n", module ? module : "SYS", formatted_msg);
        }
        else if (level == SYSLOG_LEVEL_WARN)
        {
            printf("[%s] WARN: %s\r\n", module ? module : "SYS", formatted_msg);
        }
        else
        {
            printf("[%s] %s\r\n", module ? module : "SYS", formatted_msg);
        }
    }

    if (!s_initialized || s_syslog_mutex == NULL)
    {
        return;
    }

    if (osMutexWait(s_syslog_mutex, 0) == osOK)
    {
        if (s_count < SYSLOG_QUEUE_DEPTH)
        {
            strncpy(s_log_queue[s_head].msg, full_entry, sizeof(s_log_queue[s_head].msg) - 1);
            s_log_queue[s_head].msg[sizeof(s_log_queue[s_head].msg) - 1] = '\0';
            s_head = (s_head + 1) % SYSLOG_QUEUE_DEPTH;
            s_count++;
            s_total_logged++;
            if (s_count > s_stats.queue_high_water)
            {
                s_stats.queue_high_water = s_count;
            }
        }
        else
        {
            s_tail = (s_tail + 1) % SYSLOG_QUEUE_DEPTH;
            strncpy(s_log_queue[s_head].msg, full_entry, sizeof(s_log_queue[s_head].msg) - 1);
            s_log_queue[s_head].msg[sizeof(s_log_queue[s_head].msg) - 1] = '\0';
            s_head = (s_head + 1) % SYSLOG_QUEUE_DEPTH;
            s_total_dropped++;
        }
        osMutexRelease(s_syslog_mutex);
    }
    else
    {
        s_total_dropped++;
    }
}

/**
 * @brief Builds the path of a numbered log segment.
 * @param index Segment number to encode.
 * @param out Destination buffer for the formatted path.
 * @param out_size Size of the destination buffer.
 */
static void segment_path(uint32_t index, char *out, size_t out_size)
{
    snprintf(out, out_size, SYSLOG_SEGMENT_FMT, (unsigned long)index);
}

/**
 * @brief Trims an incomplete trailing record from a segment.
 *
 * A reset during f_write can leave the last line unterminated. Everything before
 * the last newline was parsed and is kept; only the partial tail is removed, so
 * no valid historical record is ever destroyed.
 * @param path Segment file to inspect and repair.
 */
static void repair_segment_tail(const char *path)
{
    static FIL file;
    UINT got = 0;
    uint32_t offset = 0;
    uint32_t complete_len = 0;

    memset(&file, 0, sizeof(file));
    if (f_open(&file, path, FA_READ | FA_WRITE) != FR_OK)
    {
        return;
    }

    FSIZE_t size = f_size(&file);
    for (;;)
    {
        got = 0;
        if (f_read(&file, s_repair_buf, sizeof(s_repair_buf), &got) != FR_OK || got == 0)
        {
            break;
        }
        for (UINT i = 0; i < got; i++)
        {
            offset++;
            if (s_repair_buf[i] == '\n')
            {
                complete_len = offset;
            }
        }
    }

    if ((size > 0) && (complete_len != (uint32_t)size))
    {
        if ((f_lseek(&file, complete_len) == FR_OK) && (f_truncate(&file) == FR_OK))
        {
            (void)f_sync(&file);
            s_stats.tail_repairs++;
            SysLog_Print(SYSLOG_LEVEL_WARN, "STORAGE",
                         "Log segment %s ended mid-record; trimmed %lu byte tail",
                         path, (unsigned long)((uint32_t)size - complete_len));
        }
    }

    (void)f_close(&file);
}

/**
 * @brief Finds the highest existing segment and adopts it for appending.
 *
 * Runs once per boot, in the storage-owner task, before the first append. The
 * directory scan is bounded by the number of files in 0:/logs.
 */
static void discover_segment(void)
{
    static DIR dir;
    static FILINFO info;
    uint32_t highest = 0;

    if (s_segment_known)
    {
        return;
    }

    memset(&dir, 0, sizeof(dir));
    if (f_opendir(&dir, SYSLOG_DIR) == FR_OK)
    {
        for (;;)
        {
            memset(&info, 0, sizeof(info));
            if ((f_readdir(&dir, &info) != FR_OK) || (info.fname[0] == '\0'))
            {
                break;
            }
            unsigned long num = 0;
            if (sscanf(info.fname, "system_%lu.log", &num) == 1)
            {
                if ((uint32_t)num > highest)
                {
                    highest = (uint32_t)num;
                }
            }
        }
        (void)f_closedir(&dir);
    }

    if (highest == 0U)
    {
        highest = 1U;
    }

    s_stats.segment_index = highest;
    s_stats.segments = highest;
    s_segment_known = true;

    char path[48];
    segment_path(highest, path, sizeof(path));
    repair_segment_tail(path);

    memset(&info, 0, sizeof(info));
    if (f_stat(path, &info) == FR_OK)
    {
        s_stats.segment_bytes = (uint32_t)info.fsize;
    }
    else
    {
        s_stats.segment_bytes = 0U;
    }
    s_stats.ready = 1U;
}

/**
 * @brief Moves appends to the next segment number.
 *
 * The current segment is closed by the caller and left untouched on the medium;
 * nothing is renamed, truncated or deleted.
 */
static void advance_segment(void)
{
    if (s_stats.segment_index >= SYSLOG_SEGMENT_MAX)
    {
        if (!s_full_reported)
        {
            s_full_reported = true;
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE",
                         "Log segment limit reached (%lu); no further segments will be created",
                         (unsigned long)SYSLOG_SEGMENT_MAX);
        }
        s_stats.storage_full = 1U;
        return;
    }

    s_stats.segment_index++;
    if (s_stats.segment_index > s_stats.segments)
    {
        s_stats.segments = s_stats.segment_index;
    }
    s_stats.segment_bytes = 0U;
    s_rotations++;
    SysLog_Print(SYSLOG_LEVEL_INFO, "STORAGE", "Log segment %lu started (append-only)",
                 (unsigned long)s_stats.segment_index);
}

/**
 * @brief Copies the persistent logging statistics to the caller.
 * @param out Destination structure; the call is ignored when NULL.
 */
void SysLog_GetStats(SysLog_Stats_t *out)
{
    if (out == NULL)
    {
        return;
    }
    s_stats.queue_dropped = s_total_dropped;
    *out = s_stats;
}

/**
 * @brief Background task periodic worker to flush RAM log entries to SD storage.
 *        Should be called from a low-priority/background loop (e.g. defaultTask).
 */
void SysLog_PeriodicFlush(void)
{
    if (!s_initialized || s_syslog_mutex == NULL)
    {
        return;
    }

    if (s_count == 0)
    {
        return;
    }

    if (!Security_LockSD(0))
    {
        return;
    }

    static SysLogEntry_t local_batch[SYSLOG_QUEUE_DEPTH];
    uint16_t batch_count = 0;

    if (osMutexWait(s_syslog_mutex, 10) == osOK)
    {
        while (s_count > 0 && batch_count < SYSLOG_QUEUE_DEPTH)
        {
            local_batch[batch_count++] = s_log_queue[s_tail];
            s_tail = (s_tail + 1) % SYSLOG_QUEUE_DEPTH;
            s_count--;
        }
        osMutexRelease(s_syslog_mutex);
    }

    if (batch_count == 0)
    {
        Security_UnlockSD();
        return;
    }

    static FIL file;
    static char path[48];
    memset(&file, 0, sizeof(file));

    discover_segment();
    segment_path(s_stats.segment_index, path, sizeof(path));

    FRESULT res = f_open(&file, path, FA_OPEN_ALWAYS | FA_WRITE);
    if (res != FR_OK)
    {
        s_stats.last_error = (int32_t)res;
        s_stats.unpersisted += batch_count;
        if (!s_full_reported)
        {
            s_full_reported = true;
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE",
                         "STORAGE_FULL: cannot open log segment (res=%d), %u records unpersisted",
                         (int)res, (unsigned)batch_count);
        }
        s_stats.storage_full = 1U;
        Security_UnlockSD();
        return;
    }

    (void)f_lseek(&file, f_size(&file));

    uint16_t written_count = 0;
    for (uint16_t i = 0; i < batch_count; i++)
    {
        UINT bw = 0;
        size_t len = strlen(local_batch[i].msg);
        FRESULT wres = f_write(&file, local_batch[i].msg, (UINT)len, &bw);
        if ((wres != FR_OK) || (bw != (UINT)len))
        {
            s_stats.last_error = (int32_t)((wres != FR_OK) ? wres : FR_DISK_ERR);
            break;
        }
        written_count++;
    }

    FSIZE_t current_sz = f_size(&file);
    FRESULT sync_res = f_sync(&file);
    FRESULT close_res = f_close(&file);

    s_stats.stored += written_count;
    s_stats.segment_bytes = (uint32_t)current_sz;

    if (written_count < batch_count)
    {
        s_stats.unpersisted += (uint32_t)(batch_count - written_count);
        if (sync_res != FR_OK || close_res != FR_OK)
        {
            s_stats.last_error = (int32_t)((sync_res != FR_OK) ? sync_res : close_res);
        }
        if (!s_full_reported)
        {
            s_full_reported = true;
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE",
                         "STORAGE_FULL: %u of %u log records unpersisted (last error %ld)",
                         (unsigned)(batch_count - written_count), (unsigned)batch_count,
                         (long)s_stats.last_error);
        }
        s_stats.storage_full = 1U;
    }
    else if (s_stats.storage_full != 0U)
    {
        s_stats.storage_full = 0U;
        s_full_reported = false;
        SysLog_Print(SYSLOG_LEVEL_INFO, "STORAGE", "Persistent log storage available again");
    }

    if (current_sz >= SYSLOG_MAX_FILE_SIZE)
    {
        advance_segment();
        if (s_stats.storage_full != 0U)
        {
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE",
                         "STORAGE_FULL: no further log segments can be created");
        }
    }

    Security_UnlockSD();
}

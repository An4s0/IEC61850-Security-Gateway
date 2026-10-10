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
 * @brief Migrates a file from src path to dst path if src exists and dst does not.
 * @param src Source file path.
 * @param dst Destination file path.
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
 * @brief Ensures standard SD storage directory hierarchy exists and migrates legacy root files.
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
 * @brief Rotates system log files:
 *        system.log.2 -> deleted,
 *        system.log.1 -> system.log.2,
 *        system.log   -> system.log.1.
 */
static void rotate_logs(void)
{
    f_unlink(SYSLOG_FILE_ROT2);
    f_rename(SYSLOG_FILE_ROT1, SYSLOG_FILE_ROT2);
    f_rename(SYSLOG_FILE_CURRENT, SYSLOG_FILE_ROT1);
    s_rotations++;
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

    FIL file;
    memset(&file, 0, sizeof(file));
    FRESULT res = f_open(&file, SYSLOG_FILE_CURRENT, FA_OPEN_ALWAYS | FA_WRITE);
    if (res != FR_OK)
    {
        Security_UnlockSD();
        return;
    }

    f_lseek(&file, f_size(&file));

    for (uint16_t i = 0; i < batch_count; i++)
    {
        UINT bw = 0;
        size_t len = strlen(local_batch[i].msg);
        f_write(&file, local_batch[i].msg, (UINT)len, &bw);
    }

    FSIZE_t current_sz = f_size(&file);
    f_close(&file);

    if (current_sz >= SYSLOG_MAX_FILE_SIZE)
    {
        rotate_logs();
    }

    Security_UnlockSD();
}

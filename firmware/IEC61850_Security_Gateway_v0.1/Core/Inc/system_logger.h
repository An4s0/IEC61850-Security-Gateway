#ifndef SYSTEM_LOGGER_H
#define SYSTEM_LOGGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SYSLOG_DIR "0:/logs"
#define SYSLOG_FILE_CURRENT "0:/logs/system.log"
#define SYSLOG_FILE_ROT1 "0:/logs/system.log.1"
#define SYSLOG_FILE_ROT2 "0:/logs/system.log.2"

/* 64 KB per log file */
#define SYSLOG_MAX_FILE_SIZE (64 * 1024)

/* Capacity of non-blocking RAM ring buffer */
#define SYSLOG_QUEUE_DEPTH 24
#define SYSLOG_ENTRY_MAX_LEN 160

typedef enum
{
    SYSLOG_LEVEL_DEBUG = 0,
    SYSLOG_LEVEL_INFO,
    SYSLOG_LEVEL_WARN,
    SYSLOG_LEVEL_ERROR,
    SYSLOG_LEVEL_CRITICAL
} SysLogLevel_t;

void Storage_EnsureDirectories(void);
void SysLog_Init(void);
void SysLog_Print(SysLogLevel_t level, const char *module, const char *fmt, ...);
void SysLog_PeriodicFlush(void);

#endif /* SYSTEM_LOGGER_H */

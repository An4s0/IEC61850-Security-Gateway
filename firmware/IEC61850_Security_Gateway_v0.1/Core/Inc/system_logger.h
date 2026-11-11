#ifndef SYSTEM_LOGGER_H
#define SYSTEM_LOGGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SYSLOG_DIR "0:/logs"
#define SYSLOG_FILE_CURRENT "0:/logs/system.log" /* legacy file, kept read-only */
#define SYSLOG_SEGMENT_FMT "0:/logs/system_%04lu.log"
#define SYSLOG_SEGMENT_MAX 9999U

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

typedef struct
{
    uint32_t stored;        /* records written to segments since boot */
    uint32_t unpersisted;   /* records that could not be persisted since boot */
    uint32_t queue_dropped; /* records dropped from the RAM queue (producer side) */
    uint32_t queue_high_water;
    uint32_t segment_index; /* active segment number */
    uint32_t segments;      /* highest segment number seen on the medium */
    uint32_t segment_bytes; /* bytes in the active segment */
    uint32_t tail_repairs;  /* incomplete trailing records repaired at mount */
    int32_t last_error;     /* last FatFs result for a persistent write */
    uint8_t storage_full;   /* 1 while records cannot be persisted */
    uint8_t ready;          /* discovery completed */
} SysLog_Stats_t;

void SysLog_GetStats(SysLog_Stats_t *out);

#endif /* SYSTEM_LOGGER_H */

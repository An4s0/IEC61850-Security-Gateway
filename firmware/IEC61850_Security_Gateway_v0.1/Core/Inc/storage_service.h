#ifndef STORAGE_SERVICE_H
#define STORAGE_SERVICE_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Storage ownership model
 * -----------------------
 * Exactly one task (the storage-owner task, see StorageService_Run) performs
 * FatFs work for the HTTP API: alert history reads, alert clearing and system
 * configuration persistence. No lwIP TCP/IP callback may call f_* or take the
 * security SD mutex.
 *
 * Requests are submitted without blocking. The owner task executes them one at
 * a time (FIFO) and then invokes the registered completion hook. The hook must
 * be non-blocking: it only schedules the HTTP response onto the TCP/IP thread.
 */

#define STORAGE_QUEUE_DEPTH 8
#define STORAGE_MAX_REQUESTS 8

typedef enum
{
    STORAGE_OP_NONE = 0,
    STORAGE_OP_ALERT_HISTORY,
    STORAGE_OP_ALERT_PAGE,
    STORAGE_OP_ALERT_CLEAR,
    STORAGE_OP_CONFIG_SAVE
} StorageOp_t;

typedef enum
{
    STORAGE_REQ_FREE = 0,
    STORAGE_REQ_PENDING,
    STORAGE_REQ_RUNNING,
    STORAGE_REQ_DONE
} StorageReqState_t;

/* Alert record filters applied while scanning the log, before a page is
 * selected. STORAGE_ALERT_PROTO_ANY / STORAGE_ALERT_SEV_ANY mean "no filter". */
typedef enum
{
    STORAGE_ALERT_PROTO_ANY = 0,
    STORAGE_ALERT_PROTO_GOOSE,
    STORAGE_ALERT_PROTO_SV,
    STORAGE_ALERT_PROTO_MMS
} StorageAlertProto_t;

typedef enum
{
    STORAGE_ALERT_SEV_ANY = 0,
    STORAGE_ALERT_SEV_INFO,
    STORAGE_ALERT_SEV_WARNING,
    STORAGE_ALERT_SEV_HIGH,
    STORAGE_ALERT_SEV_CRITICAL
} StorageAlertSev_t;

typedef struct StorageRequest_s
{
    volatile uint8_t state;
    uint8_t op;
    uint8_t ok;
    uint8_t _pad;

    /* Alert history parameters and result. */
    uint32_t offset;
    uint32_t limit;
    char *out;          /* NDJSON records are appended at out[out_used] */
    uint32_t out_cap;
    uint32_t out_used;  /* offset of the first free byte when submitted */
    uint32_t records_read;

    /* Newest-first page parameters and result. */
    uint32_t cursor_in; /* byte offset to scan before; UINT32_MAX means end of file */
    uint32_t cursor_out;/* byte offset of the oldest record returned */
    uint8_t has_more;
    uint8_t proto_filter; /* StorageAlertProto_t */
    uint8_t sev_filter;   /* StorageAlertSev_t */

    /* Opaque completion routing owned by the HTTP layer. */
    void *ctx;
    uint32_t ctx_gen;
    int16_t buf_idx;    /* alert response buffer index, -1 when unused */

    uint32_t submitted_ms;
} StorageRequest_t;

typedef void (*StorageCompleteHook_t)(StorageRequest_t *req);

void StorageService_Init(void);

/* Runs one maintenance step plus at most one queued request. Called from the
 * storage-owner task loop; never blocks on something other than the queue. */
void StorageService_Run(void);

void StorageService_SetCompleteHook(StorageCompleteHook_t hook);

StorageRequest_t *StorageService_Acquire(void);
bool StorageService_Submit(StorageRequest_t *req);
void StorageService_Release(StorageRequest_t *req);

typedef struct
{
    uint32_t submitted;
    uint32_t completed_ok;
    uint32_t completed_fail;
    uint32_t queue_full;
    uint32_t seq_inflight;      /* high-water of concurrently in-flight requests */
    uint32_t queue_high_water;
    uint32_t lock_timeouts;
    uint32_t alerts_purged;
} StorageService_Stats_t;

void StorageService_GetStats(StorageService_Stats_t *out);
void StorageService_SetQueueHighWater(uint32_t depth);

#endif /* STORAGE_SERVICE_H */

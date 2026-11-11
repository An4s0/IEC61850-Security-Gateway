#ifndef STORAGE_SERVICE_H
#define STORAGE_SERVICE_H

#include <stdint.h>
#include <stdbool.h>

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
    char *out; /* NDJSON records are appended at out[out_used] */
    uint32_t out_cap;
    uint32_t out_used; /* offset of the first free byte when submitted */
    uint32_t records_read;

    /* Newest-first page parameters and result. */
    uint32_t cursor_in;  /* byte offset to scan before; UINT32_MAX means end of file */
    uint32_t cursor_out; /* byte offset of the oldest record returned */
    uint8_t has_more;
    uint8_t proto_filter; /* StorageAlertProto_t */
    uint8_t sev_filter;   /* StorageAlertSev_t */

    /* Opaque completion routing owned by the HTTP layer. */
    void *ctx;
    uint32_t ctx_gen;
    int16_t buf_idx; /* alert response buffer index, -1 when unused */

    uint32_t submitted_ms;
} StorageRequest_t;

typedef void (*StorageCompleteHook_t)(StorageRequest_t *req);

void StorageService_Init(void);

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
    uint32_t seq_inflight; /* high-water of concurrently in-flight requests */
    uint32_t queue_high_water;
    uint32_t lock_timeouts;
    uint32_t alerts_purged;
} StorageService_Stats_t;

void StorageService_GetStats(StorageService_Stats_t *out);
void StorageService_SetQueueHighWater(uint32_t depth);

typedef struct
{
    uint32_t card_present;     /* card-detect switch level (diagnostic only) */
    uint32_t drive_ready;      /* SD drive initialised, no failed transfer */
    uint32_t mounted;          /* volume remounted and verified */
    uint32_t removals;         /* debounced card-detect removal edges */
    uint32_t insertions;       /* debounced card-detect insertion edges */
    uint32_t drive_faults;     /* transfers failed: drive marked not ready */
    uint32_t drive_recoveries; /* drive ready again after a fault */
    uint32_t remount_attempts;
    uint32_t remount_ok;
    uint32_t remount_fail;
    uint32_t verify_failures; /* mounted but root directory not accessible */
    uint32_t disk_init_attempts;
    uint32_t disk_init_failures;
} StorageService_MediaStats_t;

void StorageService_MediaService(void);
void StorageService_GetMediaStats(StorageService_MediaStats_t *out);

#endif /* STORAGE_SERVICE_H */

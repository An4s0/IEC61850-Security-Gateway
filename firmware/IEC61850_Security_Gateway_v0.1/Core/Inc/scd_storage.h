#ifndef SCD_STORAGE_H
#define SCD_STORAGE_H

#include "cmsis_os.h"
#include <stdint.h>

#define SCD_CHUNK_SIZE 1024
#define SCD_CHUNK_POOL_SIZE 8
#define SCD_QUEUE_SIZE 8

typedef enum
{
    SCD_EVENT_START = 0,
    SCD_EVENT_DATA,
    SCD_EVENT_END
} SCD_EventType_t;

typedef struct
{
    SCD_EventType_t type;
    uint16_t length;
    uint8_t data[SCD_CHUNK_SIZE];
} SCD_Chunk_t;

void SCD_Storage_Init(void);
void SCD_Storage_Start(void);
void SCD_Storage_Enqueue(const uint8_t *data, uint16_t length);
void SCD_Storage_End(void);
void SCD_Storage_Task(void const *argument);
void SCD_Storage_Free(SCD_Chunk_t *chunk);

#endif /* SCD_STORAGE_H */
#include "scd_storage.h"
#include "scd_config.h"
#include "main.h"
#include "fatfs.h"
#include "ff.h"
#include <string.h>
#include <stdio.h>

extern osMessageQId SCD_StorageQueueHandle;

osPoolDef(SCDChunkPool, SCD_CHUNK_POOL_SIZE, SCD_Chunk_t);
static osPoolId SCDChunkPoolHandle = NULL;

static FIL SCD_File;
static uint8_t SCD_FileOpen = 0;

/**
 * @brief Initializes the memory pool for SCD chunks.
 */
void SCD_Storage_Init(void)
{
    SCDChunkPoolHandle = osPoolCreate(osPool(SCDChunkPool));
}

/**
 * @brief Enqueues a start event to initialize a new JSON configuration file write.
 */
void SCD_Storage_Start(void)
{
    if (SCDChunkPoolHandle == NULL)
    {
        return;
    }

    SCD_Chunk_t *chunk = (SCD_Chunk_t *)osPoolAlloc(SCDChunkPoolHandle);
    if (chunk == NULL)
    {
        printf("[SCD] Pool alloc failed in Start\n");
        return;
    }

    chunk->type = SCD_EVENT_START;
    chunk->length = 0;

    osStatus status = osMessagePut(SCD_StorageQueueHandle, (uint32_t)chunk, osWaitForever);
    if (status != osOK)
    {
        printf("[SCD] Queue full in Start\n");
        osPoolFree(SCDChunkPoolHandle, chunk);
    }
}

/**
 * @brief Enqueues raw configuration data chunks for asynchronous storage.
 * @param data Pointer to data buffer.
 * @param length Length of data in bytes.
 */
void SCD_Storage_Enqueue(const uint8_t *data, uint16_t length)
{
    if (SCDChunkPoolHandle == NULL || data == NULL || length == 0)
    {
        return;
    }

    while (length > 0)
    {
        uint16_t chunk_length = (length > SCD_CHUNK_SIZE) ? SCD_CHUNK_SIZE : length;

        SCD_Chunk_t *chunk = (SCD_Chunk_t *)osPoolAlloc(SCDChunkPoolHandle);
        if (chunk == NULL)
        {
            printf("[SCD] Pool alloc failed in Enqueue\n");
            return;
        }

        chunk->type = SCD_EVENT_DATA;
        chunk->length = chunk_length;
        memcpy(chunk->data, data, chunk_length);

        osStatus status = osMessagePut(SCD_StorageQueueHandle, (uint32_t)chunk, osWaitForever);
        if (status != osOK)
        {
            printf("[SCD] Queue full in Enqueue\n");
            osPoolFree(SCDChunkPoolHandle, chunk);
            return;
        }

        data += chunk_length;
        length -= chunk_length;
    }
}

/**
 * @brief Enqueues an end event to finalize and sync the written JSON configuration file.
 */
void SCD_Storage_End(void)
{
    if (SCDChunkPoolHandle == NULL)
    {
        return;
    }

    SCD_Chunk_t *chunk = (SCD_Chunk_t *)osPoolAlloc(SCDChunkPoolHandle);
    if (chunk == NULL)
    {
        printf("[SCD] Pool alloc failed in End\n");
        return;
    }

    chunk->type = SCD_EVENT_END;
    chunk->length = 0;

    osStatus status = osMessagePut(SCD_StorageQueueHandle, (uint32_t)chunk, osWaitForever);
    if (status != osOK)
    {
        printf("[SCD] Queue full in End\n");
        osPoolFree(SCDChunkPoolHandle, chunk);
    }
}

/**
 * @brief FreeRTOS task handling asynchronous file storage operations for SCD configuration.
 * @param argument Unused task parameter.
 */
void SCD_Storage_Task(void const *argument)
{
    (void)argument;

    for (;;)
    {
        osEvent evt = osMessageGet(SCD_StorageQueueHandle, osWaitForever);
        if (evt.status != osEventMessage)
        {
            continue;
        }

        SCD_Chunk_t *chunk = (SCD_Chunk_t *)evt.value.v;
        if (chunk == NULL)
        {
            continue;
        }

        if (chunk->type == SCD_EVENT_START)
        {
            if (SCD_FileOpen)
            {
                f_close(&SCD_File);
                SCD_FileOpen = 0;
            }

            FRESULT res = f_open(&SCD_File, "0:/substation.json", FA_CREATE_ALWAYS | FA_WRITE);
            if (res == FR_OK)
            {
                printf("[SCD] Storage Start: File opened\n");
                SCD_FileOpen = 1;
            }
            else
            {
                printf("[SCD] Storage Start: File open failed (FRESULT %d)\n", res);
                SCD_FileOpen = 0;
            }
        }
        else if (chunk->type == SCD_EVENT_DATA)
        {
            if (SCD_FileOpen)
            {
                UINT bytesWritten;
                f_write(&SCD_File, chunk->data, chunk->length, &bytesWritten);
                if (bytesWritten != chunk->length)
                {
                    printf("[SCD] Write error: expected %u, wrote %u\n", chunk->length, bytesWritten);
                }
            }
        }
        else if (chunk->type == SCD_EVENT_END)
        {
            if (SCD_FileOpen)
            {
                f_sync(&SCD_File);
                FRESULT res = f_close(&SCD_File);
                if (res == FR_OK)
                {
                    printf("[SCD] Storage End: File closed, requesting reload\n");
                    SCD_Config_RequestReload();
                }
                else
                {
                    printf("[SCD] Storage End: File close failed (FRESULT %d)\n", res);
                }
                SCD_FileOpen = 0;
            }
        }

        SCD_Storage_Free(chunk);
    }
}

/**
 * @brief Releases a chunk back to the storage memory pool.
 * @param chunk Pointer to the chunk to be freed.
 */
void SCD_Storage_Free(SCD_Chunk_t *chunk)
{
    if (chunk != NULL && SCDChunkPoolHandle != NULL)
    {
        osPoolFree(SCDChunkPoolHandle, chunk);
    }
}
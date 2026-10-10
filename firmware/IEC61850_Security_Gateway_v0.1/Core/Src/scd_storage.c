#include "scd_storage.h"
#include "scd_config.h"
#include "system_logger.h"
#include "security.h"
#include "main.h"
#include "fatfs.h"
#include "ff.h"
#include <string.h>
#include <stdio.h>

extern osMessageQId SCD_StorageQueueHandle;

osPoolDef(SCDChunkPool, SCD_CHUNK_POOL_SIZE, SCD_Chunk_t);
static osPoolId SCDChunkPoolHandle = NULL;

osSemaphoreDef(SCDPoolSem);
static osSemaphoreId SCDPoolSemHandle = NULL;

osSemaphoreDef(SCDEndDoneSem);
static osSemaphoreId SCDEndDoneSemHandle = NULL;

static SCD_Chunk_t s_start_event = {.type = SCD_EVENT_START, .length = 0};
static SCD_Chunk_t s_end_event = {.type = SCD_EVENT_END, .length = 0};
static SCD_Chunk_t s_abort_event = {.type = SCD_EVENT_ABORT, .length = 0};

static FIL SCD_File;
static uint8_t SCD_FileOpen = 0;
static uint8_t s_upload_ok = 0;
static volatile bool s_storage_result_ok = false;

/**
 * @brief Initializes the memory pool and flow-control semaphores for SCD chunks.
 */
void SCD_Storage_Init(void)
{
    if (SCDChunkPoolHandle == NULL)
    {
        SCDChunkPoolHandle = osPoolCreate(osPool(SCDChunkPool));
    }
    if (SCDPoolSemHandle == NULL)
    {
        SCDPoolSemHandle = osSemaphoreCreate(osSemaphore(SCDPoolSem), SCD_CHUNK_POOL_SIZE);
    }
    if (SCDEndDoneSemHandle == NULL)
    {
        SCDEndDoneSemHandle = osSemaphoreCreate(osSemaphore(SCDEndDoneSem), 1);
        if (SCDEndDoneSemHandle != NULL)
        {
            osSemaphoreWait(SCDEndDoneSemHandle, 0);
        }
    }
}

/**
 * @brief Enqueues a start event to initialize a new JSON configuration file write.
 */
void SCD_Storage_Start(void)
{
    if (SCD_StorageQueueHandle == NULL)
    {
        return;
    }

    if (SCDEndDoneSemHandle != NULL)
    {
        osSemaphoreWait(SCDEndDoneSemHandle, 0);
    }

    s_storage_result_ok = false;
    osStatus status = osMessagePut(SCD_StorageQueueHandle, (uint32_t)&s_start_event, 5000);
    if (status != osOK)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "Failed to enqueue Start event (status %d)", status);
    }
}

/**
 * @brief Enqueues raw configuration data chunks for asynchronous storage with backpressure.
 * @param data Pointer to data buffer.
 * @param length Length of data in bytes.
 * @return true on success, false on failure or timeout.
 */
bool SCD_Storage_Enqueue(const uint8_t *data, uint16_t length)
{
    if (SCDChunkPoolHandle == NULL || SCDPoolSemHandle == NULL || data == NULL || length == 0)
    {
        return false;
    }

    while (length > 0)
    {
        uint16_t chunk_length = (length > SCD_CHUNK_SIZE) ? SCD_CHUNK_SIZE : length;

        int32_t tokens = osSemaphoreWait(SCDPoolSemHandle, 100);
        if (tokens != osOK)
        {
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "Pool wait timeout in Enqueue (result %ld)", (long)tokens);
            return false;
        }

        SCD_Chunk_t *chunk = (SCD_Chunk_t *)osPoolAlloc(SCDChunkPoolHandle);
        if (chunk == NULL)
        {
            osSemaphoreRelease(SCDPoolSemHandle);
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "Pool alloc unexpected NULL in Enqueue");
            return false;
        }

        chunk->type = SCD_EVENT_DATA;
        chunk->length = chunk_length;
        memcpy(chunk->data, data, chunk_length);

        osStatus status = osMessagePut(SCD_StorageQueueHandle, (uint32_t)chunk, 100);
        if (status != osOK)
        {
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "Queue put failed in Enqueue (status %d)", status);
            SCD_Storage_Free(chunk);
            return false;
        }

        data += chunk_length;
        length -= chunk_length;
    }

    return true;
}

/**
 * @brief Enqueues an end event and waits for storage finalization and config reload.
 * @return true if file written and synced successfully, false on error.
 */
bool SCD_Storage_End(void)
{
    if (SCD_StorageQueueHandle == NULL)
    {
        return false;
    }

    osStatus status = osMessagePut(SCD_StorageQueueHandle, (uint32_t)&s_end_event, 5000);
    if (status != osOK)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "Queue put failed in End (status %d)", status);
        return false;
    }

    if (SCDEndDoneSemHandle != NULL)
    {
        int32_t res = osSemaphoreWait(SCDEndDoneSemHandle, 10000);
        if (res != osOK)
        {
            SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "End wait timeout (result %ld)", (long)res);
            return false;
        }
    }

    return s_storage_result_ok;
}

/**
 * @brief Enqueues an end event WITHOUT waiting for storage finalization.
 *
 * This is the safe version to call from the lwIP tcpip thread (api_recv callbacks).
 * The SCD_Storage_Task will flush the file and signal SCD_Config_Task to reload
 * asynchronously. The HTTP response is sent before this function returns.
 */
void SCD_Storage_End_Async(void)
{
    if (SCD_StorageQueueHandle == NULL)
    {
        return;
    }

    if (SCDEndDoneSemHandle != NULL)
    {
        osSemaphoreWait(SCDEndDoneSemHandle, 0);
    }

    s_storage_result_ok = false;
    osStatus status = osMessagePut(SCD_StorageQueueHandle, (uint32_t)&s_end_event, 1000);
    if (status != osOK)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "Queue put failed in End_Async (status %d)", status);
    }
}

/**
 * @brief Aborts the ongoing SCD upload and cleans up temporary files.
 */
void SCD_Storage_Abort(void)
{
    if (SCD_StorageQueueHandle != NULL)
    {
        osMessagePut(SCD_StorageQueueHandle, (uint32_t)&s_abort_event, 1000);
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
            Security_LockSD(1000);
            if (SCD_FileOpen)
            {
                f_close(&SCD_File);
                SCD_FileOpen = 0;
            }

            f_mkdir("0:/substation");
            f_unlink(SCD_CONFIG_FILE_PATH);
            FRESULT res = f_open(&SCD_File, SCD_CONFIG_FILE_PATH, FA_CREATE_ALWAYS | FA_WRITE);
            if (res == FR_OK)
            {
                SysLog_Print(SYSLOG_LEVEL_DEBUG, "STORAGE", "SCD upload stream started");
                SCD_FileOpen = 1;
                s_upload_ok = 1;
            }
            else
            {
                SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "SCD file open failed (FRESULT %d)", res);
                SCD_FileOpen = 0;
                s_upload_ok = 0;
            }
            Security_UnlockSD();
        }
        else if (chunk->type == SCD_EVENT_DATA)
        {
            if (SCD_FileOpen && s_upload_ok)
            {
                Security_LockSD(1000);
                UINT bytesWritten = 0;
                FRESULT r = f_write(&SCD_File, chunk->data, chunk->length, &bytesWritten);
                if (r != FR_OK || bytesWritten != chunk->length)
                {
                    SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "SCD write error (expected %u, wrote %u, res %d)", chunk->length, bytesWritten, r);
                    s_upload_ok = 0;
                }
                Security_UnlockSD();
            }
        }
        else if (chunk->type == SCD_EVENT_END)
        {
            bool ok = false;
            if (SCD_FileOpen)
            {
                Security_LockSD(1000);
                if (s_upload_ok)
                {
                    f_sync(&SCD_File);
                    FRESULT res = f_close(&SCD_File);
                    SCD_FileOpen = 0;

                    if (res == FR_OK)
                    {
                        SysLog_Print(SYSLOG_LEVEL_INFO, "STORAGE", "SCD upload file saved, requesting reload");
                        SCD_Config_RequestReload();
                        ok = true;
                    }
                    else
                    {
                        SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "SCD file close failed (FRESULT %d)", res);
                    }
                }
                else
                {
                    f_close(&SCD_File);
                    SCD_FileOpen = 0;
                    f_unlink(SCD_CONFIG_FILE_PATH);
                    SysLog_Print(SYSLOG_LEVEL_ERROR, "STORAGE", "SCD upload aborted due to write errors");
                }
                Security_UnlockSD();
            }

            s_storage_result_ok = ok;
            if (SCDEndDoneSemHandle != NULL)
            {
                osSemaphoreRelease(SCDEndDoneSemHandle);
            }
        }
        else if (chunk->type == SCD_EVENT_ABORT)
        {
            if (SCD_FileOpen)
            {
                Security_LockSD(1000);
                f_close(&SCD_File);
                SCD_FileOpen = 0;
                f_unlink(SCD_CONFIG_FILE_PATH);
                Security_UnlockSD();
            }
            s_upload_ok = 0;
            s_storage_result_ok = false;
            SysLog_Print(SYSLOG_LEVEL_WARN, "STORAGE", "SCD upload aborted and cleaned up");
        }

        SCD_Storage_Free(chunk);
    }
}

/**
 * @brief Releases a chunk back to the storage memory pool and releases semaphore token.
 * @param chunk Pointer to the chunk to be freed.
 */
void SCD_Storage_Free(SCD_Chunk_t *chunk)
{
    if (chunk != NULL && chunk != &s_start_event && chunk != &s_end_event && chunk != &s_abort_event)
    {
        if (SCDChunkPoolHandle != NULL)
        {
            osPoolFree(SCDChunkPoolHandle, chunk);
        }
        if (SCDPoolSemHandle != NULL)
        {
            osSemaphoreRelease(SCDPoolSemHandle);
        }
    }
}
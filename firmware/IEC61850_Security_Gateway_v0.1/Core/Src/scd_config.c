#include "scd_config.h"
#include "system_logger.h"
#include "security.h"
#include "main.h"
#include "fatfs.h"
#include "ff.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

extern osMessageQId SCD_ConfigQueueHandle;

static SCD_Config_t *g_scd_active_config = NULL;
static SCD_ConfigState_t g_scd_config_state = SCD_CONFIG_STATE_NONE;

static osMutexId g_scd_config_mutex = NULL;
osMutexDef(SCDConfigMutex);

typedef enum
{
    TOK_EOF = 0,
    TOK_ERROR,
    TOK_OBJ_START,
    TOK_OBJ_END,
    TOK_ARR_START,
    TOK_ARR_END,
    TOK_COLON,
    TOK_COMMA,
    TOK_STRING,
    TOK_NUMBER,
    TOK_BOOLEAN,
    TOK_NULL
} json_tok_type_t;

typedef struct
{
    FIL *file;
    char buffer[512];
    UINT buf_pos;
    UINT buf_len;
    uint8_t eof;
} json_reader_t;

static FIL s_scd_json_file;
static json_reader_t s_scd_json_reader;

static uint16_t s_parse_total_ieds = 0;
static uint16_t s_parse_total_goose = 0;
static uint16_t s_parse_total_sv = 0;
static uint16_t s_parse_total_mms = 0;

/**
 * @brief Computes standard IEEE 802.3 CRC32 checksum.
 */
static uint32_t scd_crc32(uint32_t crc, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    crc ^= 0xFFFFFFFF;
    while (len--)
    {
        crc ^= *p++;
        for (int i = 0; i < 8; i++)
        {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

/**
 * @brief Copies a string safely ensuring null-termination.
 */
static void safe_strcpy(char *dst, const char *src, size_t max_len)
{
    if (dst == NULL || max_len == 0)
    {
        return;
    }
    if (src == NULL)
    {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, max_len - 1);
    dst[max_len - 1] = '\0';
}

/**
 * @brief Parses a MAC address string ("01:0C:CD:01:00:01" or "01-0C-CD-01-00-01") into 6 bytes.
 */
static bool parse_mac_address(const char *mac_str, uint8_t *mac_bytes)
{
    if (mac_str == NULL || mac_bytes == NULL)
    {
        return false;
    }
    unsigned int bytes[6];
    int count = sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                       &bytes[0], &bytes[1], &bytes[2],
                       &bytes[3], &bytes[4], &bytes[5]);
    if (count != 6)
    {
        count = sscanf(mac_str, "%x-%x-%x-%x-%x-%x",
                       &bytes[0], &bytes[1], &bytes[2],
                       &bytes[3], &bytes[4], &bytes[5]);
    }
    if (count == 6)
    {
        for (int i = 0; i < 6; i++)
        {
            mac_bytes[i] = (uint8_t)bytes[i];
        }
        return true;
    }
    return false;
}

/**
 * @brief Parses an APPID value from string (base-16 hex per IEC 61850 SCL, e.g. "4000" or "0x4000").
 */
static uint16_t parse_appid(const char *str)
{
    if (str == NULL || str[0] == '\0')
    {
        return 0;
    }
    return (uint16_t)strtoul(str, NULL, 16);
}

/**
 * @brief Reads the next character from the JSON input stream.
 */
static int json_reader_getc(json_reader_t *reader)
{
    if (reader->buf_pos >= reader->buf_len)
    {
        if (reader->eof)
        {
            return -1;
        }
        FRESULT res = f_read(reader->file, reader->buffer, sizeof(reader->buffer), &reader->buf_len);
        reader->buf_pos = 0;
        if (res != FR_OK || reader->buf_len == 0)
        {
            reader->eof = 1;
            return -1;
        }
    }
    return (unsigned char)reader->buffer[reader->buf_pos++];
}

/**
 * @brief Moves the JSON reader position back by one character.
 */

static void json_reader_ungetc(json_reader_t *reader)
{
    if (reader->buf_pos > 0)
    {
        reader->buf_pos--;
    }
}

/**
 * @brief Skips whitespace characters in the JSON input stream.
 */
static void json_skip_whitespace(json_reader_t *reader)
{
    int c;
    while ((c = json_reader_getc(reader)) != -1)
    {
        if (!isspace(c))
        {
            json_reader_ungetc(reader);
            break;
        }
    }
}

/**
 * @brief Reads and parses the next JSON token from the input stream.
 */
static json_tok_type_t json_next_token(json_reader_t *reader, char *val_buf, size_t val_buf_size)
{
    if (val_buf != NULL && val_buf_size > 0)
    {
        val_buf[0] = '\0';
    }

    json_skip_whitespace(reader);

    int c = json_reader_getc(reader);
    if (c == -1)
    {
        return TOK_EOF;
    }

    switch (c)
    {
    case '{':
        return TOK_OBJ_START;
    case '}':
        return TOK_OBJ_END;
    case '[':
        return TOK_ARR_START;
    case ']':
        return TOK_ARR_END;
    case ':':
        return TOK_COLON;
    case ',':
        return TOK_COMMA;
    case '"':
    {
        size_t idx = 0;
        while ((c = json_reader_getc(reader)) != -1)
        {
            if (c == '"')
            {
                if (val_buf != NULL && idx < val_buf_size)
                {
                    val_buf[idx] = '\0';
                }
                return TOK_STRING;
            }
            if (c == '\\')
            {
                c = json_reader_getc(reader);
                if (c == -1)
                    break;
            }
            if (val_buf != NULL && idx < (val_buf_size - 1))
            {
                val_buf[idx++] = (char)c;
            }
        }
        return TOK_ERROR;
    }
    default:
        if (isdigit(c) || c == '-')
        {
            size_t idx = 0;
            if (val_buf != NULL && idx < (val_buf_size - 1))
            {
                val_buf[idx++] = (char)c;
            }
            while ((c = json_reader_getc(reader)) != -1)
            {
                if (isdigit(c) || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')
                {
                    if (val_buf != NULL && idx < (val_buf_size - 1))
                    {
                        val_buf[idx++] = (char)c;
                    }
                }
                else
                {
                    json_reader_ungetc(reader);
                    break;
                }
            }
            if (val_buf != NULL && idx < val_buf_size)
            {
                val_buf[idx] = '\0';
            }
            return TOK_NUMBER;
        }
        else if (isalpha(c))
        {
            size_t idx = 0;
            if (val_buf != NULL && idx < (val_buf_size - 1))
            {
                val_buf[idx++] = (char)c;
            }
            while ((c = json_reader_getc(reader)) != -1)
            {
                if (isalpha(c))
                {
                    if (val_buf != NULL && idx < (val_buf_size - 1))
                    {
                        val_buf[idx++] = (char)c;
                    }
                }
                else
                {
                    json_reader_ungetc(reader);
                    break;
                }
            }
            if (val_buf != NULL && idx < val_buf_size)
            {
                val_buf[idx] = '\0';
            }
            if (strcmp(val_buf, "true") == 0 || strcmp(val_buf, "false") == 0)
            {
                return TOK_BOOLEAN;
            }
            if (strcmp(val_buf, "null") == 0)
            {
                return TOK_NULL;
            }
            return TOK_ERROR;
        }
        break;
    }
    return TOK_ERROR;
}

/**
 * @brief Skips a JSON value, including nested objects and arrays.
 */
static void json_skip_value(json_reader_t *reader, json_tok_type_t tok)
{
    char dummy[32];
    if (tok == TOK_OBJ_START)
    {
        int depth = 1;
        while (depth > 0)
        {
            json_tok_type_t t = json_next_token(reader, dummy, sizeof(dummy));
            if (t == TOK_EOF || t == TOK_ERROR)
                break;
            if (t == TOK_OBJ_START)
                depth++;
            else if (t == TOK_OBJ_END)
                depth--;
        }
    }
    else if (tok == TOK_ARR_START)
    {
        int depth = 1;
        while (depth > 0)
        {
            json_tok_type_t t = json_next_token(reader, dummy, sizeof(dummy));
            if (t == TOK_EOF || t == TOK_ERROR)
                break;
            if (t == TOK_ARR_START)
                depth++;
            else if (t == TOK_ARR_END)
                depth--;
        }
    }
}

/**
 * @brief Saves an in-memory configuration to a binary file with CRC32.
 */
static bool ids_bin_save_to_file(const char *path, const SCD_Config_t *cfg)
{
    if (path == NULL || cfg == NULL)
    {
        return false;
    }

    FRESULT fr = f_open(&s_scd_json_file, path, FA_CREATE_ALWAYS | FA_WRITE);
    if (fr != FR_OK)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Failed to create binary file %s (res %d)", path, fr);
        return false;
    }

    ids_bin_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = IDS_CONFIG_BIN_MAGIC;
    hdr.format_version = IDS_CONFIG_BIN_VERSION;
    hdr.header_len = sizeof(ids_bin_header_t);
    hdr.config_version = cfg->configVersion;
    hdr.timestamp = cfg->loadTimestamp;
    hdr.num_goose = cfg->numGoose;
    hdr.num_sv = cfg->numSv;
    hdr.num_mms = cfg->numMms;
    hdr.num_ieds = cfg->numIeds;
    strncpy(hdr.substation_id, cfg->header.id, sizeof(hdr.substation_id) - 1);
    strncpy(hdr.file_name, cfg->header.fileName, sizeof(hdr.file_name) - 1);
    strncpy(hdr.version, cfg->header.version, sizeof(hdr.version) - 1);

    UINT bw = 0;
    fr = f_write(&s_scd_json_file, &hdr, sizeof(hdr), &bw);
    if (fr != FR_OK || bw != sizeof(hdr))
    {
        f_close(&s_scd_json_file);
        f_unlink(path);
        return false;
    }

    uint32_t crc = 0;
    if (cfg->numGoose > 0 && cfg->goose != NULL)
    {
        UINT sz = (UINT)(cfg->numGoose * sizeof(SCD_GOOSE_t));
        fr = f_write(&s_scd_json_file, cfg->goose, sz, &bw);
        if (fr != FR_OK || bw != sz)
        {
            f_close(&s_scd_json_file);
            f_unlink(path);
            return false;
        }
        crc = scd_crc32(crc, cfg->goose, sz);
    }
    if (cfg->numSv > 0 && cfg->sv != NULL)
    {
        UINT sz = (UINT)(cfg->numSv * sizeof(SCD_SV_t));
        fr = f_write(&s_scd_json_file, cfg->sv, sz, &bw);
        if (fr != FR_OK || bw != sz)
        {
            f_close(&s_scd_json_file);
            f_unlink(path);
            return false;
        }
        crc = scd_crc32(crc, cfg->sv, sz);
    }
    if (cfg->numMms > 0 && cfg->mms != NULL)
    {
        UINT sz = (UINT)(cfg->numMms * sizeof(SCD_MMS_t));
        fr = f_write(&s_scd_json_file, cfg->mms, sz, &bw);
        if (fr != FR_OK || bw != sz)
        {
            f_close(&s_scd_json_file);
            f_unlink(path);
            return false;
        }
        crc = scd_crc32(crc, cfg->mms, sz);
    }
    if (cfg->numIeds > 0 && cfg->ieds != NULL)
    {
        UINT sz = (UINT)(cfg->numIeds * sizeof(SCD_IED_t));
        fr = f_write(&s_scd_json_file, cfg->ieds, sz, &bw);
        if (fr != FR_OK || bw != sz)
        {
            f_close(&s_scd_json_file);
            f_unlink(path);
            return false;
        }
        crc = scd_crc32(crc, cfg->ieds, sz);
    }

    hdr.crc32 = crc;
    hdr.file_size = (uint32_t)f_size(&s_scd_json_file);

    f_lseek(&s_scd_json_file, 0);
    f_write(&s_scd_json_file, &hdr, sizeof(hdr), &bw);
    f_sync(&s_scd_json_file);
    f_close(&s_scd_json_file);

    return true;
}

/**
 * @brief Reads, verifies, and loads a binary configuration into a single heap-allocated block.
 */
static SCD_Config_t *ids_bin_load_from_file(const char *path)
{
    if (path == NULL)
    {
        return NULL;
    }

    FRESULT fr = f_open(&s_scd_json_file, path, FA_READ);
    if (fr != FR_OK)
    {
        return NULL;
    }

    ids_bin_header_t hdr;
    UINT br = 0;
    fr = f_read(&s_scd_json_file, &hdr, sizeof(hdr), &br);
    if (fr != FR_OK || br != sizeof(hdr))
    {
        f_close(&s_scd_json_file);
        return NULL;
    }

    if (hdr.magic != IDS_CONFIG_BIN_MAGIC || hdr.format_version != IDS_CONFIG_BIN_VERSION)
    {
        f_close(&s_scd_json_file);
        return NULL;
    }

    if (hdr.file_size != f_size(&s_scd_json_file))
    {
        f_close(&s_scd_json_file);
        return NULL;
    }

    if (hdr.num_goose > IDS_MAX_GOOSE || hdr.num_sv > IDS_MAX_SV ||
        hdr.num_mms > IDS_MAX_MMS || hdr.num_ieds > IDS_MAX_IEDS)
    {
        f_close(&s_scd_json_file);
        return NULL;
    }

    size_t goose_sz = hdr.num_goose * sizeof(SCD_GOOSE_t);
    size_t sv_sz = hdr.num_sv * sizeof(SCD_SV_t);
    size_t mms_sz = hdr.num_mms * sizeof(SCD_MMS_t);
    size_t ieds_sz = hdr.num_ieds * sizeof(SCD_IED_t);
    size_t payload_sz = goose_sz + sv_sz + mms_sz + ieds_sz;

    if (sizeof(hdr) + payload_sz != hdr.file_size)
    {
        f_close(&s_scd_json_file);
        return NULL;
    }

    size_t total_alloc = sizeof(SCD_Config_t) + payload_sz;
    SCD_Config_t *cfg = (SCD_Config_t *)pvPortMalloc(total_alloc);
    if (cfg == NULL)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Heap allocation failed for %u bytes", (unsigned int)total_alloc);
        f_close(&s_scd_json_file);
        return NULL;
    }

    memset(cfg, 0, sizeof(SCD_Config_t));
    strncpy(cfg->header.fileName, hdr.file_name, sizeof(cfg->header.fileName) - 1);
    strncpy(cfg->header.id, hdr.substation_id, sizeof(cfg->header.id) - 1);
    strncpy(cfg->header.version, hdr.version, sizeof(cfg->header.version) - 1);
    cfg->loadTimestamp = hdr.timestamp;
    cfg->configVersion = hdr.config_version;
    cfg->numGoose = hdr.num_goose;
    cfg->numSv = hdr.num_sv;
    cfg->numMms = hdr.num_mms;
    cfg->numIeds = hdr.num_ieds;

    uint8_t *p = (uint8_t *)(cfg + 1);
    cfg->goose = (hdr.num_goose > 0) ? (SCD_GOOSE_t *)p : NULL;
    p += goose_sz;
    cfg->sv = (hdr.num_sv > 0) ? (SCD_SV_t *)p : NULL;
    p += sv_sz;
    cfg->mms = (hdr.num_mms > 0) ? (SCD_MMS_t *)p : NULL;
    p += mms_sz;
    cfg->ieds = (hdr.num_ieds > 0) ? (SCD_IED_t *)p : NULL;

    fr = f_read(&s_scd_json_file, cfg + 1, (UINT)payload_sz, &br);
    f_close(&s_scd_json_file);

    if (fr != FR_OK || br != payload_sz)
    {
        vPortFree(cfg);
        return NULL;
    }

    uint32_t calc_crc = scd_crc32(0, cfg + 1, payload_sz);
    if (calc_crc != hdr.crc32)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "%s: CRC32 error! Expected 0x%08lX, got 0x%08lX",
                     path, (unsigned long)hdr.crc32, (unsigned long)calc_crc);
        vPortFree(cfg);
        return NULL;
    }

    cfg->isValid = 1;
    return cfg;
}

/**
 * @brief Verifies a binary configuration file on SDMMC using streaming CRC32 (zero heap allocation).
 */
static bool ids_bin_verify_file(const char *path)
{
    FRESULT fr = f_open(&s_scd_json_file, path, FA_READ);
    if (fr != FR_OK)
    {
        return false;
    }

    ids_bin_header_t hdr;
    UINT br = 0;
    fr = f_read(&s_scd_json_file, &hdr, sizeof(hdr), &br);
    if (fr != FR_OK || br != sizeof(hdr))
    {
        f_close(&s_scd_json_file);
        return false;
    }

    if (hdr.magic != IDS_CONFIG_BIN_MAGIC || hdr.format_version != IDS_CONFIG_BIN_VERSION ||
        hdr.file_size != f_size(&s_scd_json_file))
    {
        f_close(&s_scd_json_file);
        return false;
    }

    uint8_t chunk[256];
    uint32_t calc_crc = 0;
    UINT remaining = hdr.file_size - sizeof(hdr);

    while (remaining > 0)
    {
        UINT to_read = (remaining > sizeof(chunk)) ? sizeof(chunk) : remaining;
        fr = f_read(&s_scd_json_file, chunk, to_read, &br);
        if (fr != FR_OK || br != to_read)
        {
            f_close(&s_scd_json_file);
            return false;
        }
        calc_crc = scd_crc32(calc_crc, chunk, br);
        remaining -= br;
    }

    f_close(&s_scd_json_file);
    return (calc_crc == hdr.crc32);
}

/**
 * @brief Executes a safe atomic commit with backup:
 *        ids_config.new -> ids_config.bak -> ids_config.bin
 */
static bool ids_bin_commit(const SCD_Config_t *new_cfg)
{
    if (new_cfg == NULL)
    {
        return false;
    }

    f_unlink(IDS_CONFIG_NEW_PATH);
    if (!ids_bin_save_to_file(IDS_CONFIG_NEW_PATH, new_cfg))
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Commit failed: Unable to write %s", IDS_CONFIG_NEW_PATH);
        return false;
    }

    if (!ids_bin_verify_file(IDS_CONFIG_NEW_PATH))
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Commit failed: %s failed CRC verification", IDS_CONFIG_NEW_PATH);
        f_unlink(IDS_CONFIG_NEW_PATH);
        return false;
    }

    f_unlink(IDS_CONFIG_BAK_PATH);
    f_rename(IDS_CONFIG_BIN_PATH, IDS_CONFIG_BAK_PATH);
    FRESULT r = f_rename(IDS_CONFIG_NEW_PATH, IDS_CONFIG_BIN_PATH);
    if (r == FR_OK)
    {
        f_unlink(IDS_CONFIG_BAK_PATH);
        SysLog_Print(SYSLOG_LEVEL_INFO, "SCD", "Committed %s (Version %lu)",
                     IDS_CONFIG_BIN_PATH, (unsigned long)new_cfg->configVersion);
        return true;
    }
    else
    {
        f_rename(IDS_CONFIG_BAK_PATH, IDS_CONFIG_BIN_PATH);
        f_unlink(IDS_CONFIG_NEW_PATH);
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Commit rename failed (%d), restored backup", r);
        return false;
    }
}

/**
 * @brief Parses the SCD file header from the JSON input stream.
 */
static void parse_scd_header(json_reader_t *reader, SCD_Header_t *header)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_OBJ_START || tok == TOK_COMMA)
            continue;
        if (tok != TOK_STRING)
            break;
        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
            break;
        tok = json_next_token(reader, val, sizeof(val));

        if (strcmp(key, "fileName") == 0)
        {
            safe_strcpy(header->fileName, val, sizeof(header->fileName));
        }
        else if (strcmp(key, "id") == 0)
        {
            safe_strcpy(header->id, val, sizeof(header->id));
        }
        else if (strcmp(key, "version") == 0)
        {
            safe_strcpy(header->version, val, sizeof(header->version));
        }
        else
        {
            json_skip_value(reader, tok);
        }
    }
}

/**
 * @brief Parses the access points of an IED from the JSON input stream.
 */
static void parse_ied_access_points(json_reader_t *reader, SCD_IED_t *ied)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_OBJ_START)
            break;

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
                continue;
            if (tok != TOK_STRING)
                break;
            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
                break;
            tok = json_next_token(reader, val, sizeof(val));

            if (strcmp(key, "name") == 0)
            {
                safe_strcpy(ied->apName, val, sizeof(ied->apName));
            }
            else if (strcmp(key, "ip") == 0)
            {
                safe_strcpy(ied->ip, val, sizeof(ied->ip));
            }
            else
            {
                json_skip_value(reader, tok);
            }
        }
    }
}

/**
 * @brief Parses the IED array from the JSON input stream.
 */
static void parse_ieds_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_OBJ_START)
            break;

        s_parse_total_ieds++;

        SCD_IED_t *ied = NULL;
        if (config->numIeds < IDS_MAX_IEDS)
        {
            ied = &config->ieds[config->numIeds];
            memset(ied, 0, sizeof(SCD_IED_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
                continue;
            if (tok != TOK_STRING)
                break;
            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
                break;
            tok = json_next_token(reader, val, sizeof(val));

            if (ied == NULL)
            {
                json_skip_value(reader, tok);
                continue;
            }

            if (strcmp(key, "id") == 0)
            {
                safe_strcpy(ied->id, val, sizeof(ied->id));
            }
            else if (strcmp(key, "accessPoints") == 0)
            {
                if (tok == TOK_ARR_START)
                {
                    parse_ied_access_points(reader, ied);
                }
                else
                {
                    json_skip_value(reader, tok);
                }
            }
            else
            {
                json_skip_value(reader, tok);
            }
        }

        if (ied != NULL)
        {
            config->numIeds++;
        }
    }
}

/**
 * @brief Parses the publisher information of a GOOSE configuration.
 */
static void parse_goose_publisher(json_reader_t *reader, SCD_GOOSE_t *g)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_STRING)
            break;
        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
            break;
        tok = json_next_token(reader, val, sizeof(val));

        if (strcmp(key, "ied") == 0)
        {
            safe_strcpy(g->publisherIed, val, sizeof(g->publisherIed));
        }
        else if (strcmp(key, "logicalDevice") == 0)
        {
            safe_strcpy(g->logicalDevice, val, sizeof(g->logicalDevice));
        }
        else if (strcmp(key, "logicalNode") == 0)
        {
            safe_strcpy(g->logicalNode, val, sizeof(g->logicalNode));
        }
        else if (strcmp(key, "controlBlock") == 0)
        {
            safe_strcpy(g->controlBlock, val, sizeof(g->controlBlock));
        }
        else
        {
            json_skip_value(reader, tok);
        }
    }
}

/**
 * @brief Parses the timing parameters of a GOOSE configuration.
 */
static void parse_goose_timing(json_reader_t *reader, SCD_GOOSE_t *g)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_STRING)
            break;
        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
            break;
        tok = json_next_token(reader, val, sizeof(val));

        if (strcmp(key, "minTimeMs") == 0)
        {
            g->minTimeMs = (uint32_t)strtoul(val, NULL, 10);
        }
        else if (strcmp(key, "maxTimeMs") == 0)
        {
            g->maxTimeMs = (uint32_t)strtoul(val, NULL, 10);
        }
        else
        {
            json_skip_value(reader, tok);
        }
    }
}

/**
 * @brief Parses the GOOSE configuration array from the JSON input stream.
 */
static void parse_goose_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_OBJ_START)
            break;

        s_parse_total_goose++;

        SCD_GOOSE_t *g = NULL;
        if (config->numGoose < IDS_MAX_GOOSE)
        {
            g = &config->goose[config->numGoose];
            memset(g, 0, sizeof(SCD_GOOSE_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
                continue;
            if (tok != TOK_STRING)
                break;
            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
                break;
            tok = json_next_token(reader, val, sizeof(val));

            if (g == NULL)
            {
                json_skip_value(reader, tok);
                continue;
            }

            if (strcmp(key, "publisher") == 0)
            {
                if (tok == TOK_OBJ_START)
                    parse_goose_publisher(reader, g);
                else
                    json_skip_value(reader, tok);
            }
            else if (strcmp(key, "mac") == 0)
            {
                safe_strcpy(g->macStr, val, sizeof(g->macStr));
                parse_mac_address(val, g->mac);
            }
            else if (strcmp(key, "appId") == 0)
            {
                g->appId = parse_appid(val);
            }
            else if (strcmp(key, "vlanId") == 0)
            {
                g->vlanId = (uint16_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "vlanPriority") == 0)
            {
                g->vlanPriority = (uint8_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "confRev") == 0)
            {
                g->confRev = (uint32_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "timing") == 0)
            {
                if (tok == TOK_OBJ_START)
                    parse_goose_timing(reader, g);
                else
                    json_skip_value(reader, tok);
            }
            else
            {
                json_skip_value(reader, tok);
            }
        }

        if (g != NULL)
        {
            config->numGoose++;
        }
    }
}

/**
 * @brief Parses the publisher information of an SV configuration.
 */
static void parse_sv_publisher(json_reader_t *reader, SCD_SV_t *sv)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_STRING)
            break;
        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
            break;
        tok = json_next_token(reader, val, sizeof(val));

        if (strcmp(key, "ied") == 0)
        {
            safe_strcpy(sv->publisherIed, val, sizeof(sv->publisherIed));
        }
        else if (strcmp(key, "logicalDevice") == 0)
        {
            safe_strcpy(sv->logicalDevice, val, sizeof(sv->logicalDevice));
        }
        else if (strcmp(key, "logicalNode") == 0)
        {
            safe_strcpy(sv->logicalNode, val, sizeof(sv->logicalNode));
        }
        else if (strcmp(key, "controlBlock") == 0)
        {
            safe_strcpy(sv->controlBlock, val, sizeof(sv->controlBlock));
        }
        else
        {
            json_skip_value(reader, tok);
        }
    }
}

/**
 * @brief Parses the Sampled Values configuration array from the JSON input stream.
 */
static void parse_sv_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_OBJ_START)
            break;

        s_parse_total_sv++;

        SCD_SV_t *sv = NULL;
        if (config->numSv < IDS_MAX_SV)
        {
            sv = &config->sv[config->numSv];
            memset(sv, 0, sizeof(SCD_SV_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
                continue;
            if (tok != TOK_STRING)
                break;
            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
                break;
            tok = json_next_token(reader, val, sizeof(val));

            if (sv == NULL)
            {
                json_skip_value(reader, tok);
                continue;
            }

            if (strcmp(key, "publisher") == 0)
            {
                if (tok == TOK_OBJ_START)
                    parse_sv_publisher(reader, sv);
                else
                    json_skip_value(reader, tok);
            }
            else if (strcmp(key, "mac") == 0)
            {
                safe_strcpy(sv->macStr, val, sizeof(sv->macStr));
                parse_mac_address(val, sv->mac);
            }
            else if (strcmp(key, "appId") == 0)
            {
                sv->appId = parse_appid(val);
            }
            else if (strcmp(key, "vlanId") == 0)
            {
                sv->vlanId = (uint16_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "vlanPriority") == 0)
            {
                sv->vlanPriority = (uint8_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "svId") == 0)
            {
                safe_strcpy(sv->svId, val, sizeof(sv->svId));
            }
            else if (strcmp(key, "sampleRate") == 0)
            {
                sv->sampleRate = (uint32_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "nofASDU") == 0)
            {
                sv->nofASDU = (uint16_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "confRev") == 0)
            {
                sv->confRev = (uint32_t)strtoul(val, NULL, 10);
            }
            else
            {
                json_skip_value(reader, tok);
            }
        }

        if (sv != NULL)
        {
            config->numSv++;
        }
    }
}

/**
 * @brief Parses the MMS configuration array from the JSON input stream.
 */
static void parse_mms_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_OBJ_START)
            break;

        s_parse_total_mms++;

        SCD_MMS_t *mms = NULL;
        if (config->numMms < IDS_MAX_MMS)
        {
            mms = &config->mms[config->numMms];
            memset(mms, 0, sizeof(SCD_MMS_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
                continue;
            if (tok != TOK_STRING)
                break;
            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
                break;
            tok = json_next_token(reader, val, sizeof(val));

            if (mms == NULL)
            {
                json_skip_value(reader, tok);
                continue;
            }

            if (strcmp(key, "ied") == 0)
            {
                safe_strcpy(mms->ied, val, sizeof(mms->ied));
            }
            else if (strcmp(key, "accessPoint") == 0)
            {
                safe_strcpy(mms->accessPoint, val, sizeof(mms->accessPoint));
            }
            else if (strcmp(key, "ip") == 0)
            {
                safe_strcpy(mms->ip, val, sizeof(mms->ip));
            }
            else
            {
                json_skip_value(reader, tok);
            }
        }

        if (mms != NULL)
        {
            config->numMms++;
        }
    }
}

/**
 * @brief Parses the SCD JSON file into the provided configuration structure.
 */
static bool parse_scd_json_file(const char *file_path, SCD_Config_t *config)
{
    FRESULT fr = f_open(&s_scd_json_file, file_path, FA_READ);
    if (fr != FR_OK)
    {
        return false;
    }

    memset(&s_scd_json_reader, 0, sizeof(s_scd_json_reader));
    s_scd_json_reader.file = &s_scd_json_file;

    s_parse_total_ieds = 0;
    s_parse_total_goose = 0;
    s_parse_total_sv = 0;
    s_parse_total_mms = 0;

    char key[32];
    char val[64];

    json_tok_type_t tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
    if (tok != TOK_OBJ_START)
    {
        f_close(&s_scd_json_file);
        return false;
    }

    while ((tok = json_next_token(&s_scd_json_reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
            continue;
        if (tok != TOK_STRING)
            break;

        tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
        if (tok != TOK_COLON)
            break;

        if (strcmp(key, "scd") == 0)
        {
            tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
            if (tok == TOK_OBJ_START)
                parse_scd_header(&s_scd_json_reader, &config->header);
            else
                json_skip_value(&s_scd_json_reader, tok);
        }
        else if (strcmp(key, "ieds") == 0)
        {
            tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
                parse_ieds_array(&s_scd_json_reader, config);
            else
                json_skip_value(&s_scd_json_reader, tok);
        }
        else if (strcmp(key, "goose") == 0)
        {
            tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
                parse_goose_array(&s_scd_json_reader, config);
            else
                json_skip_value(&s_scd_json_reader, tok);
        }
        else if (strcmp(key, "sv") == 0)
        {
            tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
                parse_sv_array(&s_scd_json_reader, config);
            else
                json_skip_value(&s_scd_json_reader, tok);
        }
        else if (strcmp(key, "mms") == 0)
        {
            tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
                parse_mms_array(&s_scd_json_reader, config);
            else
                json_skip_value(&s_scd_json_reader, tok);
        }
        else
        {
            tok = json_next_token(&s_scd_json_reader, val, sizeof(val));
            json_skip_value(&s_scd_json_reader, tok);
        }
    }

    f_close(&s_scd_json_file);

    if (s_parse_total_ieds > IDS_MAX_IEDS || s_parse_total_goose > IDS_MAX_GOOSE ||
        s_parse_total_sv > IDS_MAX_SV || s_parse_total_mms > IDS_MAX_MMS)
    {
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "REJECTED: SCD exceeds limits (IEDs: %u/%u, GOOSE: %u/%u, SV: %u/%u, MMS: %u/%u)",
                     s_parse_total_ieds, IDS_MAX_IEDS,
                     s_parse_total_goose, IDS_MAX_GOOSE,
                     s_parse_total_sv, IDS_MAX_SV,
                     s_parse_total_mms, IDS_MAX_MMS);
        return false;
    }

    return true;
}

/**
 * @brief Validates the parsed SCD configuration for required fields and content.
 */
static bool scd_validate_config(const SCD_Config_t *config)
{
    if (config == NULL)
    {
        return false;
    }
    if (config->header.id[0] == '\0' && config->header.fileName[0] == '\0')
    {
        return false;
    }
    if (config->numIeds == 0 && config->numGoose == 0 && config->numSv == 0 && config->numMms == 0)
    {
        return false;
    }
    return true;
}

/**
 * @brief Loads, validates, and commits the SCD configuration during startup or reload.
 */
static void scd_load_internal(bool is_startup)
{
    SysLog_Print(SYSLOG_LEVEL_DEBUG, "SCD", "Loading configuration (Startup: %d)...", is_startup);

    if (!Security_LockSD(2000))
    {
        SysLog_Print(SYSLOG_LEVEL_WARN, "SCD", "Failed to acquire SD lock for config load");
        return;
    }

    if (is_startup)
    {
        SCD_Config_t *bin_cfg = ids_bin_load_from_file(IDS_CONFIG_BIN_PATH);
        if (bin_cfg == NULL)
        {
            bin_cfg = ids_bin_load_from_file(IDS_CONFIG_BAK_PATH);
            if (bin_cfg != NULL)
            {
                f_rename(IDS_CONFIG_BAK_PATH, IDS_CONFIG_BIN_PATH);
            }
        }
        if (bin_cfg == NULL)
        {
            bin_cfg = ids_bin_load_from_file(IDS_CONFIG_NEW_PATH);
            if (bin_cfg != NULL)
            {
                f_rename(IDS_CONFIG_NEW_PATH, IDS_CONFIG_BIN_PATH);
            }
        }

        if (bin_cfg != NULL)
        {
            SCD_Config_Lock();
            SCD_Config_t *old = g_scd_active_config;
            g_scd_active_config = bin_cfg;
            g_scd_config_state = SCD_CONFIG_STATE_READY;
            SCD_Config_Unlock();
            if (old != NULL)
            {
                vPortFree(old);
            }
            Security_UnlockSD();
            SysLog_Print(SYSLOG_LEVEL_INFO, "SCD", "Configuration loaded: Version %lu (IEDs: %u, GOOSE: %u, SV: %u, MMS: %u)",
                         (unsigned long)bin_cfg->configVersion, bin_cfg->numIeds, bin_cfg->numGoose, bin_cfg->numSv, bin_cfg->numMms);
            return;
        }

        SysLog_Print(SYSLOG_LEVEL_DEBUG, "SCD", "No valid binary configuration found on boot. Checking JSON...");
    }

    FILINFO fno;
    FRESULT fr = f_stat(SCD_CONFIG_FILE_PATH, &fno);
    if (fr != FR_OK || fno.fsize == 0)
    {
        if (g_scd_active_config == NULL)
        {
            g_scd_config_state = SCD_CONFIG_STATE_NONE;
        }
        Security_UnlockSD();
        SysLog_Print(SYSLOG_LEVEL_INFO, "SCD", "No active SCD configuration found (substation.json empty/missing, fr=%d)", (int)fr);
        return;
    }

    size_t max_stage_sz = sizeof(SCD_Config_t) +
                          (IDS_MAX_IEDS * sizeof(SCD_IED_t)) +
                          (IDS_MAX_GOOSE * sizeof(SCD_GOOSE_t)) +
                          (IDS_MAX_SV * sizeof(SCD_SV_t)) +
                          (IDS_MAX_MMS * sizeof(SCD_MMS_t));

    SCD_Config_t *staging = (SCD_Config_t *)pvPortMalloc(max_stage_sz);
    if (staging == NULL)
    {
        Security_UnlockSD();
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Staging malloc failed (%u bytes)", (unsigned int)max_stage_sz);
        return;
    }

    memset(staging, 0, sizeof(SCD_Config_t));
    uint8_t *p = (uint8_t *)(staging + 1);
    staging->ieds = (SCD_IED_t *)p;
    p += IDS_MAX_IEDS * sizeof(SCD_IED_t);
    staging->goose = (SCD_GOOSE_t *)p;
    p += IDS_MAX_GOOSE * sizeof(SCD_GOOSE_t);
    staging->sv = (SCD_SV_t *)p;
    p += IDS_MAX_SV * sizeof(SCD_SV_t);
    staging->mms = (SCD_MMS_t *)p;

    g_scd_config_state = SCD_CONFIG_STATE_LOADING;

    if (!parse_scd_json_file(SCD_CONFIG_FILE_PATH, staging))
    {
        vPortFree(staging);
        if (g_scd_active_config != NULL)
        {
            g_scd_config_state = SCD_CONFIG_STATE_READY;
        }
        else
        {
            g_scd_config_state = SCD_CONFIG_STATE_ERROR;
        }
        Security_UnlockSD();
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "JSON parsing failed or rejected");
        return;
    }

    if (!scd_validate_config(staging))
    {
        vPortFree(staging);
        if (g_scd_active_config != NULL)
        {
            g_scd_config_state = SCD_CONFIG_STATE_READY;
        }
        else
        {
            g_scd_config_state = SCD_CONFIG_STATE_ERROR;
        }
        Security_UnlockSD();
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Validation failed");
        return;
    }

    staging->configVersion = (g_scd_active_config != NULL) ? (g_scd_active_config->configVersion + 1) : 1;
    staging->loadTimestamp = HAL_GetTick();

    if (!ids_bin_commit(staging))
    {
        vPortFree(staging);
        if (g_scd_active_config != NULL)
        {
            g_scd_config_state = SCD_CONFIG_STATE_READY;
        }
        else
        {
            g_scd_config_state = SCD_CONFIG_STATE_ERROR;
        }
        Security_UnlockSD();
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Binary commit failed, retaining active config");
        return;
    }

    vPortFree(staging);

    SCD_Config_t *active = ids_bin_load_from_file(IDS_CONFIG_BIN_PATH);
    Security_UnlockSD();

    if (active != NULL)
    {
        SCD_Config_Lock();
        SCD_Config_t *old = g_scd_active_config;
        g_scd_active_config = active;
        g_scd_config_state = SCD_CONFIG_STATE_READY;
        SCD_Config_Unlock();
        if (old != NULL)
        {
            vPortFree(old);
        }
        SysLog_Print(SYSLOG_LEVEL_INFO, "SCD", "Configuration loaded: Version %lu (IEDs: %u, GOOSE: %u, SV: %u, MMS: %u)",
                     (unsigned long)active->configVersion,
                     active->numIeds, active->numGoose, active->numSv, active->numMms);
    }
    else
    {
        if (g_scd_active_config != NULL)
        {
            g_scd_config_state = SCD_CONFIG_STATE_READY;
        }
        else
        {
            g_scd_config_state = SCD_CONFIG_STATE_ERROR;
        }
        SysLog_Print(SYSLOG_LEVEL_ERROR, "SCD", "Failed to load committed binary config into RAM");
    }
}

/**
 * @brief Initializes the SCD configuration mutex.
 */
void SCD_Config_Init(void)
{
    if (g_scd_config_mutex == NULL)
    {
        g_scd_config_mutex = osMutexCreate(osMutex(SCDConfigMutex));
    }
}

/**
 * @brief Queues a request to load the SCD configuration during startup.
 */
void SCD_Config_RequestLoadStartup(void)
{
    if (SCD_ConfigQueueHandle != NULL)
    {
        osMessagePut(SCD_ConfigQueueHandle, (uint32_t)SCD_CONFIG_CMD_LOAD_STARTUP, 0);
    }
}

/**
 * @brief Queues a request to reload the SCD configuration.
 */
void SCD_Config_RequestReload(void)
{
    if (SCD_ConfigQueueHandle != NULL)
    {
        osMessagePut(SCD_ConfigQueueHandle, (uint32_t)SCD_CONFIG_CMD_RELOAD, 0);
    }
}

/**
 * @brief Processes SCD configuration commands from the configuration queue.
 */
void SCD_Config_Task(void const *argument)
{
    (void)argument;
    SCD_Config_Init();

    for (;;)
    {
        osEvent evt = osMessageGet(SCD_ConfigQueueHandle, osWaitForever);
        if (evt.status == osEventMessage)
        {
            uint32_t cmd = evt.value.v;
            if (cmd == SCD_CONFIG_CMD_LOAD_STARTUP)
            {
                scd_load_internal(true);
            }
            else if (cmd == SCD_CONFIG_CMD_RELOAD)
            {
                scd_load_internal(false);
            }
        }
    }
}

/**
 * @brief Returns the current SCD configuration state.
 */
SCD_ConfigState_t SCD_Config_GetState(void)
{
    return g_scd_config_state;
}

/**
 * @brief Returns a pointer to the active SCD configuration.
 */
const SCD_Config_t *SCD_Config_GetActive(void)
{
    return g_scd_active_config;
}

/**
 * @brief Returns the version of the active SCD configuration.
 */
uint32_t SCD_Config_GetVersion(void)
{
    uint32_t ver = 0;
    SCD_Config_Lock();
    if (g_scd_active_config != NULL)
    {
        ver = g_scd_active_config->configVersion;
    }
    SCD_Config_Unlock();
    return ver;
}

/**
 * @brief Acquires the SCD configuration mutex.
 */
void SCD_Config_Lock(void)
{
    if (g_scd_config_mutex != NULL)
    {
        osMutexWait(g_scd_config_mutex, osWaitForever);
    }
}

/**
 * @brief Releases the SCD configuration mutex.
 */
void SCD_Config_Unlock(void)
{
    if (g_scd_config_mutex != NULL)
    {
        osMutexRelease(g_scd_config_mutex);
    }
}

/**
 * @brief Finds an IED by its configured name.
 */
const SCD_IED_t *SCD_Config_FindIEDByName(const char *ied_name)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->ieds == NULL || ied_name == NULL || ied_name[0] == '\0')
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numIeds; i++)
    {
        if (strcmp(cfg->ieds[i].id, ied_name) == 0)
        {
            return &cfg->ieds[i];
        }
    }
    return NULL;
}

/**
 * @brief Finds an IED by its IP address.
 */
const SCD_IED_t *SCD_Config_FindIEDByIP(const char *ip_str)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->ieds == NULL || ip_str == NULL || ip_str[0] == '\0')
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numIeds; i++)
    {
        if (strcmp(cfg->ieds[i].ip, ip_str) == 0)
        {
            return &cfg->ieds[i];
        }
    }
    return NULL;
}

/**
 * @brief Finds a GOOSE configuration by APPID and optional MAC address.
 */
const SCD_GOOSE_t *SCD_Config_FindGOOSE(uint16_t app_id, const uint8_t *mac)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->goose == NULL)
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numGoose; i++)
    {
        if (cfg->goose[i].appId == app_id)
        {
            if (mac == NULL || memcmp(cfg->goose[i].mac, mac, SCD_MAC_ADDR_LEN) == 0)
            {
                return &cfg->goose[i];
            }
        }
    }
    return NULL;
}

/**
 * @brief Finds a GOOSE configuration by publisher IED and control block.
 */
const SCD_GOOSE_t *SCD_Config_FindGOOSEByControlBlock(const char *ied, const char *cb)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->goose == NULL || ied == NULL || cb == NULL)
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numGoose; i++)
    {
        if (strcmp(cfg->goose[i].publisherIed, ied) == 0 &&
            strcmp(cfg->goose[i].controlBlock, cb) == 0)
        {
            return &cfg->goose[i];
        }
    }
    return NULL;
}

/**
 * @brief Finds an SV configuration by APPID and optional MAC address.
 */
const SCD_SV_t *SCD_Config_FindSV(uint16_t app_id, const uint8_t *mac)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->sv == NULL)
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numSv; i++)
    {
        if (cfg->sv[i].appId == app_id)
        {
            if (mac == NULL || memcmp(cfg->sv[i].mac, mac, SCD_MAC_ADDR_LEN) == 0)
            {
                return &cfg->sv[i];
            }
        }
    }
    return NULL;
}

/**
 * @brief Finds an SV configuration by its SV ID.
 */
const SCD_SV_t *SCD_Config_FindSVBySvId(const char *sv_id)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->sv == NULL || sv_id == NULL || sv_id[0] == '\0')
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numSv; i++)
    {
        if (strcmp(cfg->sv[i].svId, sv_id) == 0)
        {
            return &cfg->sv[i];
        }
    }
    return NULL;
}

/**
 * @brief Finds an MMS configuration by its IP address.
 */
const SCD_MMS_t *SCD_Config_FindMMSByIP(const char *ip_str)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->mms == NULL || ip_str == NULL || ip_str[0] == '\0')
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numMms; i++)
    {
        if (strcmp(cfg->mms[i].ip, ip_str) == 0)
        {
            return &cfg->mms[i];
        }
    }
    return NULL;
}

/**
 * @brief Finds an MMS configuration by its associated IED name.
 */
const SCD_MMS_t *SCD_Config_FindMMSByIED(const char *ied_name)
{
    const SCD_Config_t *cfg = g_scd_active_config;
    if (cfg == NULL || !cfg->isValid || cfg->mms == NULL || ied_name == NULL || ied_name[0] == '\0')
    {
        return NULL;
    }
    for (uint16_t i = 0; i < cfg->numMms; i++)
    {
        if (strcmp(cfg->mms[i].ied, ied_name) == 0)
        {
            return &cfg->mms[i];
        }
    }
    return NULL;
}

/**
 * @brief Calculates the total and active memory usage of the SCD configuration.
 */
void SCD_Config_GetMemoryUsage(uint32_t *total_bytes, uint32_t *active_bytes)
{
    SCD_Config_Lock();
    uint32_t bytes = 0;
    if (g_scd_active_config != NULL && g_scd_active_config->isValid)
    {
        bytes = (uint32_t)(sizeof(SCD_Config_t) +
                           (g_scd_active_config->numGoose * sizeof(SCD_GOOSE_t)) +
                           (g_scd_active_config->numSv * sizeof(SCD_SV_t)) +
                           (g_scd_active_config->numMms * sizeof(SCD_MMS_t)) +
                           (g_scd_active_config->numIeds * sizeof(SCD_IED_t)));
    }
    if (total_bytes != NULL)
    {
        *total_bytes = bytes;
    }
    if (active_bytes != NULL)
    {
        *active_bytes = bytes;
    }
    SCD_Config_Unlock();
}

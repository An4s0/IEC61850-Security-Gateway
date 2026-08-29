#include "scd_config.h"
#include "main.h"
#include "fatfs.h"
#include "ff.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

extern osMessageQId SCD_ConfigQueueHandle;

static SCD_Config_t g_scd_config_buffers[2];
static uint8_t g_scd_active_index = 0;
static uint8_t g_scd_has_active_config = 0;
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

/**
 * @brief Copies a string safely ensuring null-termination.
 * @param dst Destination buffer.
 * @param src Source string.
 * @param max_len Maximum buffer size.
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
 * @brief Parses a MAC address string in colon or hyphen notation into a byte array.
 * @param str MAC string.
 * @param mac_out Output buffer for 6 bytes.
 */
static void parse_mac_address(const char *str, uint8_t *mac_out)
{
    if (str == NULL || mac_out == NULL)
    {
        return;
    }

    memset(mac_out, 0, SCD_MAC_ADDR_LEN);
    unsigned int b[6] = {0};

    if (sscanf(str, "%x-%x-%x-%x-%x-%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6 ||
        sscanf(str, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6)
    {
        for (int i = 0; i < 6; i++)
        {
            mac_out[i] = (uint8_t)b[i];
        }
    }
}

/**
 * @brief Parses an APPID string into a 16-bit integer.
 * @param str Hexadecimal or decimal string representation.
 * @return Parsed 16-bit APPID.
 */
static uint16_t parse_appid(const char *str)
{
    if (str == NULL || str[0] == '\0')
    {
        return 0;
    }

    char *endptr = NULL;
    unsigned long val = strtoul(str, &endptr, 16);
    return (uint16_t)val;
}

/**
 * @brief Reads the next character from a chunked JSON file stream.
 * @param reader Pointer to JSON reader instance.
 * @return Next character or '\0' on EOF/error.
 */
static char json_reader_getc(json_reader_t *reader)
{
    if (reader->buf_pos >= reader->buf_len)
    {
        if (reader->eof)
        {
            return '\0';
        }

        FRESULT fr = f_read(reader->file, reader->buffer, sizeof(reader->buffer), &reader->buf_len);
        reader->buf_pos = 0;

        if (fr != FR_OK || reader->buf_len == 0)
        {
            reader->eof = 1;
            return '\0';
        }
    }

    return reader->buffer[reader->buf_pos++];
}

/**
 * @brief Pushes back the last read character into the reader buffer.
 * @param reader Pointer to JSON reader instance.
 */
static void json_reader_ungetc(json_reader_t *reader)
{
    if (reader->buf_pos > 0)
    {
        reader->buf_pos--;
    }
}

/**
 * @brief Lexes and returns the next token from the JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param val_out Output buffer for token string value.
 * @param max_val_len Size of output buffer.
 * @return Token type.
 */
static json_tok_type_t json_next_token(json_reader_t *reader, char *val_out, size_t max_val_len)
{
    char c;

    if (val_out != NULL && max_val_len > 0)
    {
        val_out[0] = '\0';
    }

    while ((c = json_reader_getc(reader)) != '\0')
    {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
        {
            break;
        }
    }

    if (c == '\0')
    {
        return TOK_EOF;
    }

    if (c == '{')
    {
        return TOK_OBJ_START;
    }
    if (c == '}')
    {
        return TOK_OBJ_END;
    }
    if (c == '[')
    {
        return TOK_ARR_START;
    }
    if (c == ']')
    {
        return TOK_ARR_END;
    }
    if (c == ':')
    {
        return TOK_COLON;
    }
    if (c == ',')
    {
        return TOK_COMMA;
    }

    if (c == '"')
    {
        size_t idx = 0;
        while ((c = json_reader_getc(reader)) != '\0')
        {
            if (c == '"')
            {
                break;
            }
            if (c == '\\')
            {
                c = json_reader_getc(reader);
            }
            if (val_out != NULL && idx < (max_val_len - 1))
            {
                val_out[idx++] = c;
            }
        }
        if (val_out != NULL && max_val_len > 0)
        {
            val_out[idx] = '\0';
        }
        return TOK_STRING;
    }

    if (isdigit((unsigned char)c) || c == '-')
    {
        size_t idx = 0;
        if (val_out != NULL && idx < (max_val_len - 1))
        {
            val_out[idx++] = c;
        }

        while ((c = json_reader_getc(reader)) != '\0')
        {
            if (isdigit((unsigned char)c) || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')
            {
                if (val_out != NULL && idx < (max_val_len - 1))
                {
                    val_out[idx++] = c;
                }
            }
            else
            {
                json_reader_ungetc(reader);
                break;
            }
        }
        if (val_out != NULL && max_val_len > 0)
        {
            val_out[idx] = '\0';
        }
        return TOK_NUMBER;
    }

    if (isalpha((unsigned char)c))
    {
        size_t idx = 0;
        if (val_out != NULL && idx < (max_val_len - 1))
        {
            val_out[idx++] = c;
        }

        while ((c = json_reader_getc(reader)) != '\0')
        {
            if (isalpha((unsigned char)c))
            {
                if (val_out != NULL && idx < (max_val_len - 1))
                {
                    val_out[idx++] = c;
                }
            }
            else
            {
                json_reader_ungetc(reader);
                break;
            }
        }
        if (val_out != NULL && max_val_len > 0)
        {
            val_out[idx] = '\0';
        }

        if (val_out != NULL)
        {
            if (strcmp(val_out, "true") == 0 || strcmp(val_out, "false") == 0)
            {
                return TOK_BOOLEAN;
            }
            if (strcmp(val_out, "null") == 0)
            {
                return TOK_NULL;
            }
        }
        return TOK_STRING;
    }

    return TOK_ERROR;
}

/**
 * @brief Skips nested JSON object or array values.
 * @param reader Pointer to JSON reader instance.
 * @param tok Token type of opening delimiter.
 */
static void json_skip_value(json_reader_t *reader, json_tok_type_t tok)
{
    char val[64];
    int depth = 0;

    if (tok == TOK_OBJ_START || tok == TOK_ARR_START)
    {
        depth = 1;
        while (depth > 0)
        {
            json_tok_type_t t = json_next_token(reader, val, sizeof(val));
            if (t == TOK_EOF || t == TOK_ERROR)
            {
                break;
            }
            if (t == TOK_OBJ_START || t == TOK_ARR_START)
            {
                depth++;
            }
            else if (t == TOK_OBJ_END || t == TOK_ARR_END)
            {
                depth--;
            }
        }
    }
}

/**
 * @brief Parses SCD metadata header section from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param header Output header structure.
 */
static void parse_scd_header(json_reader_t *reader, SCD_Header_t *header)
{
    char key[64];
    char val[64];

    json_tok_type_t tok = json_next_token(reader, val, sizeof(val));
    if (tok != TOK_OBJ_START)
    {
        return;
    }

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

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
 * @brief Parses IED location fields from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param ied Target IED structure.
 */
static void parse_ied_location(json_reader_t *reader, SCD_IED_t *ied)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (strcmp(key, "voltageLevel") == 0)
        {
            safe_strcpy(ied->voltageLevel, val, sizeof(ied->voltageLevel));
        }
        else if (strcmp(key, "bay") == 0)
        {
            safe_strcpy(ied->bay, val, sizeof(ied->bay));
        }
        else
        {
            json_skip_value(reader, tok);
        }
    }
}

/**
 * @brief Parses IED access points array from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param ied Target IED structure.
 */
static void parse_ied_access_points(json_reader_t *reader, SCD_IED_t *ied)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_OBJ_START)
        {
            break;
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
            {
                continue;
            }
            if (tok != TOK_STRING)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));
            if (strcmp(key, "name") == 0)
            {
                safe_strcpy(ied->apName, val, sizeof(ied->apName));
            }
            else if (strcmp(key, "network") == 0)
            {
                safe_strcpy(ied->network, val, sizeof(ied->network));
            }
            else if (strcmp(key, "ip") == 0)
            {
                safe_strcpy(ied->ip, val, sizeof(ied->ip));
            }
            else if (strcmp(key, "mac") == 0)
            {
                safe_strcpy(ied->macStr, val, sizeof(ied->macStr));
                parse_mac_address(val, ied->mac);
            }
            else
            {
                json_skip_value(reader, tok);
            }
        }
    }
}

/**
 * @brief Parses the array of configured IEDs from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param config Target SCD configuration structure.
 */
static void parse_ieds_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_OBJ_START)
        {
            break;
        }

        SCD_IED_t *ied = NULL;
        if (config->numIeds < SCD_MAX_IEDS)
        {
            ied = &config->ieds[config->numIeds];
            memset(ied, 0, sizeof(SCD_IED_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
            {
                continue;
            }
            if (tok != TOK_STRING)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
            {
                break;
            }

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
            else if (strcmp(key, "manufacturer") == 0)
            {
                safe_strcpy(ied->manufacturer, val, sizeof(ied->manufacturer));
            }
            else if (strcmp(key, "type") == 0)
            {
                safe_strcpy(ied->type, val, sizeof(ied->type));
            }
            else if (strcmp(key, "location") == 0)
            {
                if (tok == TOK_OBJ_START)
                {
                    parse_ied_location(reader, ied);
                }
                else
                {
                    json_skip_value(reader, tok);
                }
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
 * @brief Parses GOOSE publisher section from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param g Target GOOSE structure.
 */
static void parse_goose_publisher(json_reader_t *reader, SCD_GOOSE_t *g)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

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
 * @brief Parses GOOSE dataset section from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param g Target GOOSE structure.
 */
static void parse_goose_dataset(json_reader_t *reader, SCD_GOOSE_t *g)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (strcmp(key, "name") == 0)
        {
            safe_strcpy(g->datasetName, val, sizeof(g->datasetName));
        }
        else if (strcmp(key, "members") == 0)
        {
            if (tok == TOK_ARR_START)
            {
                while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
                {
                    if (tok == TOK_COMMA)
                    {
                        continue;
                    }
                    if (tok == TOK_STRING && g->numMembers < SCD_MAX_MEMBERS_COUNT)
                    {
                        safe_strcpy(g->members[g->numMembers++], val, SCD_MAX_NAME_LEN);
                    }
                    else
                    {
                        json_skip_value(reader, tok);
                    }
                }
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
}

/**
 * @brief Parses GOOSE subscriber IED names from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param g Target GOOSE structure.
 */
static void parse_goose_subscribers(json_reader_t *reader, SCD_GOOSE_t *g)
{
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok == TOK_STRING && g->numSubscribers < SCD_MAX_GOOSE_SUBSCRIBERS)
        {
            safe_strcpy(g->subscribers[g->numSubscribers++], val, SCD_MAX_NAME_LEN);
        }
        else
        {
            json_skip_value(reader, tok);
        }
    }
}

/**
 * @brief Parses GOOSE timing parameters from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param g Target GOOSE structure.
 */
static void parse_goose_timing(json_reader_t *reader, SCD_GOOSE_t *g)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (strcasecmp(key, "minTimeMs") == 0 || strcasecmp(key, "minTime") == 0)
        {
            g->minTimeMs = (uint32_t)strtoul(val, NULL, 10);
        }
        else if (strcasecmp(key, "maxTimeMs") == 0 || strcasecmp(key, "maxTime") == 0)
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
 * @brief Parses the array of configured GOOSE streams from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param config Target SCD configuration structure.
 */
static void parse_goose_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_OBJ_START)
        {
            break;
        }

        SCD_GOOSE_t *g = NULL;
        if (config->numGoose < SCD_MAX_GOOSE)
        {
            g = &config->goose[config->numGoose];
            memset(g, 0, sizeof(SCD_GOOSE_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
            {
                continue;
            }
            if (tok != TOK_STRING)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));

            if (g == NULL)
            {
                json_skip_value(reader, tok);
                continue;
            }

            if (strcmp(key, "publisher") == 0)
            {
                if (tok == TOK_OBJ_START)
                {
                    parse_goose_publisher(reader, g);
                }
                else
                {
                    json_skip_value(reader, tok);
                }
            }
            else if (strcmp(key, "network") == 0)
            {
                safe_strcpy(g->network, val, sizeof(g->network));
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
            else if (strcasecmp(key, "minTimeMs") == 0 || strcasecmp(key, "minTime") == 0)
            {
                g->minTimeMs = (uint32_t)strtoul(val, NULL, 10);
            }
            else if (strcasecmp(key, "maxTimeMs") == 0 || strcasecmp(key, "maxTime") == 0)
            {
                g->maxTimeMs = (uint32_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "dataset") == 0)
            {
                if (tok == TOK_OBJ_START)
                {
                    parse_goose_dataset(reader, g);
                }
                else
                {
                    json_skip_value(reader, tok);
                }
            }
            else if (strcmp(key, "subscribers") == 0)
            {
                if (tok == TOK_ARR_START)
                {
                    parse_goose_subscribers(reader, g);
                }
                else
                {
                    json_skip_value(reader, tok);
                }
            }
            else if (strcmp(key, "timing") == 0)
            {
                if (tok == TOK_OBJ_START)
                {
                    parse_goose_timing(reader, g);
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

        if (g != NULL)
        {
            config->numGoose++;
        }
    }
}

/**
 * @brief Parses Sampled Values (SV) publisher section from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param sv Target SV structure.
 */
static void parse_sv_publisher(json_reader_t *reader, SCD_SV_t *sv)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

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
 * @brief Parses Sampled Values (SV) dataset section from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param sv Target SV structure.
 */
static void parse_sv_dataset(json_reader_t *reader, SCD_SV_t *sv)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (strcmp(key, "name") == 0)
        {
            safe_strcpy(sv->datasetName, val, sizeof(sv->datasetName));
        }
        else if (strcmp(key, "members") == 0)
        {
            if (tok == TOK_ARR_START)
            {
                while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
                {
                    if (tok == TOK_COMMA)
                    {
                        continue;
                    }
                    if (tok == TOK_STRING && sv->numMembers < SCD_MAX_MEMBERS_COUNT)
                    {
                        safe_strcpy(sv->members[sv->numMembers++], val, SCD_MAX_NAME_LEN);
                    }
                    else
                    {
                        json_skip_value(reader, tok);
                    }
                }
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
}

/**
 * @brief Parses the array of configured Sampled Values (SV) streams from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param config Target SCD configuration structure.
 */
static void parse_sv_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_OBJ_START)
        {
            break;
        }

        SCD_SV_t *sv = NULL;
        if (config->numSv < SCD_MAX_SV)
        {
            sv = &config->sv[config->numSv];
            memset(sv, 0, sizeof(SCD_SV_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
            {
                continue;
            }
            if (tok != TOK_STRING)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));

            if (sv == NULL)
            {
                json_skip_value(reader, tok);
                continue;
            }

            if (strcmp(key, "publisher") == 0)
            {
                if (tok == TOK_OBJ_START)
                {
                    parse_sv_publisher(reader, sv);
                }
                else
                {
                    json_skip_value(reader, tok);
                }
            }
            else if (strcmp(key, "network") == 0)
            {
                safe_strcpy(sv->network, val, sizeof(sv->network));
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
            else if (strcmp(key, "dataset") == 0)
            {
                if (tok == TOK_OBJ_START)
                {
                    parse_sv_dataset(reader, sv);
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

        if (sv != NULL)
        {
            config->numSv++;
        }
    }
}

/**
 * @brief Parses MMS report trigger options from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param opt Target trigger options structure.
 */
static void parse_mms_trigger_options(json_reader_t *reader, SCD_MMS_TriggerOptions_t *opt)
{
    char key[32];
    char val[32];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

        tok = json_next_token(reader, val, sizeof(val));
        uint8_t bool_val = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0) ? 1 : 0;

        if (strcmp(key, "dchg") == 0)
        {
            opt->dchg = bool_val;
        }
        else if (strcmp(key, "qchg") == 0)
        {
            opt->qchg = bool_val;
        }
        else if (strcmp(key, "dupd") == 0)
        {
            opt->dupd = bool_val;
        }
        else if (strcmp(key, "period") == 0)
        {
            opt->period = bool_val;
        }
        else if (strcmp(key, "gi") == 0)
        {
            opt->gi = bool_val;
        }
        else
        {
            json_skip_value(reader, tok);
        }
    }
}

/**
 * @brief Parses MMS report configuration array from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param mms Target MMS structure.
 */
static void parse_mms_reports(json_reader_t *reader, SCD_MMS_t *mms)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_OBJ_START)
        {
            break;
        }

        SCD_MMS_Report_t *rep = NULL;
        if (mms->numReports < SCD_MAX_REPORTS_PER_MMS)
        {
            rep = &mms->reports[mms->numReports];
            memset(rep, 0, sizeof(SCD_MMS_Report_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
            {
                continue;
            }
            if (tok != TOK_STRING)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));

            if (rep == NULL)
            {
                json_skip_value(reader, tok);
                continue;
            }

            if (strcmp(key, "logicalDevice") == 0)
            {
                safe_strcpy(rep->logicalDevice, val, sizeof(rep->logicalDevice));
            }
            else if (strcmp(key, "logicalNode") == 0)
            {
                safe_strcpy(rep->logicalNode, val, sizeof(rep->logicalNode));
            }
            else if (strcmp(key, "name") == 0)
            {
                safe_strcpy(rep->name, val, sizeof(rep->name));
            }
            else if (strcmp(key, "dataset") == 0)
            {
                safe_strcpy(rep->dataset, val, sizeof(rep->dataset));
            }
            else if (strcmp(key, "buffered") == 0)
            {
                rep->buffered = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0) ? 1 : 0;
            }
            else if (strcmp(key, "confRev") == 0)
            {
                rep->confRev = (uint32_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "intgPd") == 0)
            {
                rep->intgPd = (uint32_t)strtoul(val, NULL, 10);
            }
            else if (strcmp(key, "triggerOptions") == 0)
            {
                if (tok == TOK_OBJ_START)
                {
                    parse_mms_trigger_options(reader, &rep->triggerOptions);
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

        if (rep != NULL)
        {
            mms->numReports++;
        }
    }
}

/**
 * @brief Parses the array of configured MMS services from JSON stream.
 * @param reader Pointer to JSON reader instance.
 * @param config Target SCD configuration structure.
 */
static void parse_mms_array(json_reader_t *reader, SCD_Config_t *config)
{
    char key[32];
    char val[64];
    json_tok_type_t tok;

    while ((tok = json_next_token(reader, val, sizeof(val))) != TOK_ARR_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_OBJ_START)
        {
            break;
        }

        SCD_MMS_t *mms = NULL;
        if (config->numMms < SCD_MAX_MMS)
        {
            mms = &config->mms[config->numMms];
            memset(mms, 0, sizeof(SCD_MMS_t));
        }

        while ((tok = json_next_token(reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
        {
            if (tok == TOK_COMMA)
            {
                continue;
            }
            if (tok != TOK_STRING)
            {
                break;
            }

            tok = json_next_token(reader, val, sizeof(val));
            if (tok != TOK_COLON)
            {
                break;
            }

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
            else if (strcmp(key, "reports") == 0)
            {
                if (tok == TOK_ARR_START)
                {
                    parse_mms_reports(reader, mms);
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

        if (mms != NULL)
        {
            config->numMms++;
        }
    }
}

/**
 * @brief Opens and parses the entire substation JSON configuration file.
 * @param file_path File system path to the JSON file.
 * @param config Target SCD configuration structure.
 * @return true on successful parsing, false on error.
 */
static bool parse_scd_json_file(const char *file_path, SCD_Config_t *config)
{
    FIL file;
    FRESULT fr = f_open(&file, file_path, FA_READ);
    if (fr != FR_OK)
    {
        return false;
    }

    json_reader_t reader;
    memset(&reader, 0, sizeof(reader));
    reader.file = &file;

    char key[32];
    char val[64];

    json_tok_type_t tok = json_next_token(&reader, val, sizeof(val));
    if (tok != TOK_OBJ_START)
    {
        f_close(&file);
        return false;
    }

    while ((tok = json_next_token(&reader, key, sizeof(key))) != TOK_OBJ_END && tok != TOK_EOF)
    {
        if (tok == TOK_COMMA)
        {
            continue;
        }
        if (tok != TOK_STRING)
        {
            break;
        }

        tok = json_next_token(&reader, val, sizeof(val));
        if (tok != TOK_COLON)
        {
            break;
        }

        if (strcmp(key, "scd") == 0)
        {
            parse_scd_header(&reader, &config->header);
        }
        else if (strcmp(key, "ieds") == 0)
        {
            tok = json_next_token(&reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
            {
                parse_ieds_array(&reader, config);
            }
            else
            {
                json_skip_value(&reader, tok);
            }
        }
        else if (strcmp(key, "goose") == 0)
        {
            tok = json_next_token(&reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
            {
                parse_goose_array(&reader, config);
            }
            else
            {
                json_skip_value(&reader, tok);
            }
        }
        else if (strcmp(key, "sv") == 0)
        {
            tok = json_next_token(&reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
            {
                parse_sv_array(&reader, config);
            }
            else
            {
                json_skip_value(&reader, tok);
            }
        }
        else if (strcmp(key, "mms") == 0)
        {
            tok = json_next_token(&reader, val, sizeof(val));
            if (tok == TOK_ARR_START)
            {
                parse_mms_array(&reader, config);
            }
            else
            {
                json_skip_value(&reader, tok);
            }
        }
        else
        {
            tok = json_next_token(&reader, val, sizeof(val));
            json_skip_value(&reader, tok);
        }
    }

    f_close(&file);
    return true;
}

/**
 * @brief Validates parsed configuration consistency and minimum required elements.
 * @param config Pointer to parsed configuration structure.
 * @return true if valid, false otherwise.
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
 * @brief Internal engine performing double-buffered configuration load and atomic swap.
 * @param is_startup Flag indicating if invocation occurs during startup.
 */
static void scd_load_internal(bool is_startup)
{
    (void)is_startup;
    printf("[SCD Config] Loading configuration (Startup: %d)...\n", is_startup);

    FILINFO fno;
    FRESULT fr = f_stat(SCD_CONFIG_FILE_PATH, &fno);
    if (fr != FR_OK)
    {
        if (!g_scd_has_active_config)
        {
            g_scd_config_state = SCD_CONFIG_STATE_NONE;
        }
        printf("[SCD Config] File not found or stat failed (FRESULT %d)\n", fr);
        return;
    }

    uint8_t staging_idx = 1 - g_scd_active_index;
    SCD_Config_t *staging = &g_scd_config_buffers[staging_idx];
    memset(staging, 0, sizeof(SCD_Config_t));

    g_scd_config_state = SCD_CONFIG_STATE_LOADING;

    if (!parse_scd_json_file(SCD_CONFIG_FILE_PATH, staging))
    {
        if (g_scd_has_active_config)
        {
            g_scd_config_state = SCD_CONFIG_STATE_READY;
        }
        else
        {
            g_scd_config_state = SCD_CONFIG_STATE_ERROR;
        }
        printf("[SCD Config] JSON parsing failed\n");
        return;
    }

    if (!scd_validate_config(staging))
    {
        if (g_scd_has_active_config)
        {
            g_scd_config_state = SCD_CONFIG_STATE_READY;
        }
        else
        {
            g_scd_config_state = SCD_CONFIG_STATE_ERROR;
        }
        printf("[SCD Config] Validation failed\n");
        return;
    }

    SCD_Config_Lock();
    staging->isValid = 1;
    staging->configVersion = (g_scd_has_active_config ? g_scd_config_buffers[g_scd_active_index].configVersion + 1 : 1);
    staging->loadTimestamp = HAL_GetTick();
    g_scd_active_index = staging_idx;
    g_scd_has_active_config = 1;
    g_scd_config_state = SCD_CONFIG_STATE_READY;
    SCD_Config_Unlock();

    printf("[SCD Config] Successfully loaded config v%lu\n", staging->configVersion);
}

/**
 * @brief Initializes the configuration mutex.
 */
void SCD_Config_Init(void)
{
    if (g_scd_config_mutex == NULL)
    {
        g_scd_config_mutex = osMutexCreate(osMutex(SCDConfigMutex));
    }
}

/**
 * @brief Enqueues a command to load configuration at startup.
 */
void SCD_Config_RequestLoadStartup(void)
{
    if (SCD_ConfigQueueHandle != NULL)
    {
        osMessagePut(SCD_ConfigQueueHandle, (uint32_t)SCD_CONFIG_CMD_LOAD_STARTUP, 0);
    }
}

/**
 * @brief Enqueues a command to reload configuration from storage.
 */
void SCD_Config_RequestReload(void)
{
    if (SCD_ConfigQueueHandle != NULL)
    {
        osMessagePut(SCD_ConfigQueueHandle, (uint32_t)SCD_CONFIG_CMD_RELOAD, 0);
    }
}

/**
 * @brief FreeRTOS task handling configuration loading and reload requests.
 * @param argument Unused task parameter.
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
 * @brief Retrieves the current state of the SCD configuration subsystem.
 * @return Configuration state enum value.
 */
SCD_ConfigState_t SCD_Config_GetState(void)
{
    return g_scd_config_state;
}

/**
 * @brief Retrieves a pointer to the active validated SCD configuration.
 * @return Pointer to active configuration or NULL if not ready.
 */
const SCD_Config_t *SCD_Config_GetActive(void)
{
    if (!g_scd_has_active_config || g_scd_config_state != SCD_CONFIG_STATE_READY)
    {
        return NULL;
    }
    return &g_scd_config_buffers[g_scd_active_index];
}

/**
 * @brief Retrieves the version number of the active SCD configuration.
 * @return Monotonically increasing version counter.
 */
uint32_t SCD_Config_GetVersion(void)
{
    if (!g_scd_has_active_config)
    {
        return 0;
    }
    return g_scd_config_buffers[g_scd_active_index].configVersion;
}

/**
 * @brief Acquires the configuration access mutex for thread-safe queries.
 */
void SCD_Config_Lock(void)
{
    if (g_scd_config_mutex != NULL)
    {
        osMutexWait(g_scd_config_mutex, osWaitForever);
    }
}

/**
 * @brief Releases the configuration access mutex.
 */
void SCD_Config_Unlock(void)
{
    if (g_scd_config_mutex != NULL)
    {
        osMutexRelease(g_scd_config_mutex);
    }
}

/**
 * @brief Finds an IED configuration by its name.
 * @param ied_name Name of the IED.
 * @return Pointer to IED structure or NULL if not found.
 */
const SCD_IED_t *SCD_Config_FindIEDByName(const char *ied_name)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL || ied_name == NULL)
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
 * @brief Finds an IED configuration by its IP address.
 * @param ip_str IP address string.
 * @return Pointer to IED structure or NULL if not found.
 */
const SCD_IED_t *SCD_Config_FindIEDByIP(const char *ip_str)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL || ip_str == NULL)
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
 * @brief Finds an IED configuration by its MAC address.
 * @param mac Pointer to 6-byte MAC address array.
 * @return Pointer to IED structure or NULL if not found.
 */
const SCD_IED_t *SCD_Config_FindIEDByMAC(const uint8_t *mac)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL || mac == NULL)
    {
        return NULL;
    }

    for (uint16_t i = 0; i < cfg->numIeds; i++)
    {
        if (memcmp(cfg->ieds[i].mac, mac, SCD_MAC_ADDR_LEN) == 0)
        {
            return &cfg->ieds[i];
        }
    }
    return NULL;
}

/**
 * @brief Finds a GOOSE control block by APPID and optional MAC.
 * @param app_id 16-bit APPID.
 * @param mac Optional 6-byte MAC address or NULL.
 * @return Pointer to matching GOOSE structure or NULL.
 */
const SCD_GOOSE_t *SCD_Config_FindGOOSE(uint16_t app_id, const uint8_t *mac)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL)
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
 * @brief Finds a GOOSE control block by publisher IED and control block name.
 * @param ied Publisher IED name.
 * @param cb Control block name.
 * @return Pointer to matching GOOSE structure or NULL.
 */
const SCD_GOOSE_t *SCD_Config_FindGOOSEByControlBlock(const char *ied, const char *cb)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL || ied == NULL || cb == NULL)
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
 * @brief Finds a Sampled Values control block by APPID and optional MAC.
 * @param app_id 16-bit APPID.
 * @param mac Optional 6-byte MAC address or NULL.
 * @return Pointer to matching SV structure or NULL.
 */
const SCD_SV_t *SCD_Config_FindSV(uint16_t app_id, const uint8_t *mac)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL)
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
 * @brief Finds a Sampled Values control block by its svID string.
 * @param sv_id String identifier.
 * @return Pointer to matching SV structure or NULL.
 */
const SCD_SV_t *SCD_Config_FindSVBySvId(const char *sv_id)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL || sv_id == NULL)
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
 * @brief Finds an MMS configuration by server IP address.
 * @param ip_str IP address string.
 * @return Pointer to matching MMS structure or NULL.
 */
const SCD_MMS_t *SCD_Config_FindMMSByIP(const char *ip_str)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL || ip_str == NULL)
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
 * @brief Finds an MMS configuration by publisher IED name.
 * @param ied_name IED name string.
 * @return Pointer to matching MMS structure or NULL.
 */
const SCD_MMS_t *SCD_Config_FindMMSByIED(const char *ied_name)
{
    const SCD_Config_t *cfg = SCD_Config_GetActive();
    if (cfg == NULL || ied_name == NULL)
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

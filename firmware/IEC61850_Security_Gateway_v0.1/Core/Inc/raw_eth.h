#ifndef RAW_ETH_H
#define RAW_ETH_H

#include "lwip/pbuf.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    ACCOUNT_GOOSE,
    ACCOUNT_SV,
    ACCOUNT_MMS,
    ACCOUNT_OTHER,
    ACCOUNT_PROTOCOLS
} AccountProtocol;
typedef enum
{
    ACCOUNT_RX,
    ACCOUNT_PARSED,
    ACCOUNT_PARSE_FAILED,
    ACCOUNT_DROP_SIZE_OR_INIT,
    ACCOUNT_DROP_POOL,
    ACCOUNT_DROP_QUEUE,
    ACCOUNT_FIELDS
} AccountField;
typedef struct
{
    uint32_t values[ACCOUNT_PROTOCOLS][ACCOUNT_FIELDS];
    uint32_t saturated;
    uint32_t last_parsed_ms;
} PacketAccounting;

void Accounting_Increment(AccountProtocol protocol, AccountField field);
void Accounting_Get(PacketAccounting *out);
bool RawEth_Process(struct pbuf *p, uint64_t rx_ticks, bool rx_valid);

#endif /* RAW_ETH_H */
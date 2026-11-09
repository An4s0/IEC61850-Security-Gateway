#ifndef SYS_DIAG_H
#define SYS_DIAG_H

#include <stdint.h>

/*
 * Boot/reset observability.
 *
 * RAM counters can only decrease when the MCU restarts, so capturing the reset
 * cause and a boot counter is the only way to distinguish a genuine counter
 * reset from a reporting error.
 */

typedef struct
{
    uint32_t uptime_ms;
    uint32_t boot_count;
    uint32_t reset_flags; /* RCC_CSR latched at boot */
} SysDiag_Stats_t;

void SysDiag_Init(void);
void SysDiag_Get(SysDiag_Stats_t *out);

#endif /* SYS_DIAG_H */

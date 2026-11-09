#include "sys_diag.h"
#include "stm32f7xx_hal.h"

#define SYS_DIAG_NOINIT_MAGIC 0x424F4F54UL /* "BOOT" */

/*
 * Lives in .noinit so the C startup code does not clear it and it survives a
 * warm reset. It is not validated against a cold power cycle beyond the magic,
 * so it reports "boots since this RAM image was first initialised".
 */
static volatile uint32_t s_boot_magic __attribute__((section(".noinit")));
static volatile uint32_t s_boot_count __attribute__((section(".noinit")));

static uint32_t s_reset_flags = 0;
static uint32_t s_boot_count_latched = 1;

void SysDiag_Init(void)
{
    s_reset_flags = RCC->CSR;
    __HAL_RCC_CLEAR_RESET_FLAGS();

    if (s_boot_magic != SYS_DIAG_NOINIT_MAGIC)
    {
        s_boot_magic = SYS_DIAG_NOINIT_MAGIC;
        s_boot_count = 0;
    }

    if (s_boot_count != UINT32_MAX)
    {
        s_boot_count++;
    }
    s_boot_count_latched = s_boot_count;
}

void SysDiag_Get(SysDiag_Stats_t *out)
{
    if (out == NULL)
    {
        return;
    }
    out->uptime_ms = HAL_GetTick();
    out->boot_count = s_boot_count_latched;
    out->reset_flags = s_reset_flags;
}

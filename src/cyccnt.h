/**
 * Inline functions for getting cycle counts from the Cortex-M33 core on RP2350
 *
 * Hardware register information can be found on the data sheet:
 * // https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf
 *
 * For reference, sleeping for 10ms takes about 1500000 cycles
 */
#ifndef CYCCNT_H
#define CYCCNT_H
#include <hardware/address_mapped.h>
#include <hardware/regs/m33.h>
#include <hardware/structs/m33.h>

/**
 * Enable DWT, which is required before reading from CYCCNT
 */
void inline enable_dwt(void) {
  *(io_rw_32 *)(PPB_BASE + M33_DEMCR_OFFSET) |= M33_DEMCR_TRCENA_BITS;
  *(io_rw_32 *)(PPB_BASE + M33_DWT_CYCCNT_OFFSET) = 0;
  *(io_rw_32 *)(PPB_BASE + M33_DWT_CTRL_OFFSET) |= M33_DWT_CTRL_CYCCNTENA_BITS;
}

/**
 * Reset CYCCNT to 0
 */
void inline reset_cyccnt(void) {
  *(io_rw_32 *)(PPB_BASE + M33_DWT_CYCCNT_OFFSET) = 0;
}

/**
 * Read from CYCCNT
 */
uint32_t inline read_cyccnt(void) {
  return *(io_rw_32 *)(PPB_BASE + M33_DWT_CYCCNT_OFFSET);
}
#endif

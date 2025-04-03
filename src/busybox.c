/**
 * Example program testing DWT and CYCCNT
 */
#include "cyccnt.h"
#include <inttypes.h>
#include <pico/stdio.h>
#include <pico/time.h>
#include <stdio.h>

#define SLEEP_MS 10

int main(void) {
  stdio_init_all();
  enable_dwt();

  while (1) {
    reset_cyccnt();
    uint32_t start_time = read_cyccnt();
    sleep_ms(SLEEP_MS);
    uint32_t end_time = read_cyccnt();
    printf("sleep: %3d, cycles: %" PRIu32 "\n", SLEEP_MS,
           end_time - start_time);
  }
}

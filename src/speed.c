#include "cyccnt.h"
#include <inttypes.h>
#include <pico/stdio.h>
#include <pico/time.h>
#include <stdio.h>

int main(void) {
  stdio_init_all();
  enable_dwt();

  while (1) {
    for (int i = 0; i < 10; i++) {
      printf("Clock: %" PRIu32 "\n", read_cyccnt());
      sleep_ms(100);
    }
    sleep_ms(1000);
    reset_cyccnt();
  }
}

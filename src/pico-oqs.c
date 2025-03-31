#include <stdio.h>
#include "pico/stdlib.h"

static void hello_with_ctr() {
    uint32_t ctr = 0;
    while (true) {
        printf("Hello, %d!\n", ctr++);
        sleep_ms(1000);
    }
}

int main()
{
    stdio_init_all();

    hello_with_ctr();
}

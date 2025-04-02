/**
 * Example program using the built-in random number generator
 * https://www.raspberrypi.com/documentation/pico-sdk/high_level.html#group_pico_rand
 */
#include <pico/rand.h>
#include <pico/stdio.h>
#include <pico/time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "randombytes.h"

#define RAND_PILOT_LEN 16
#define RAND_BENCH_LEN 4096


/**
 * Pring hex string
 */
static void print_hexstr(uint8_t *bytes, size_t len) {
  for (int i = 0; i < len; i++) {
    printf("%02X", bytes[i]);
  }
}

/**
 * How much time does it take to fill in 4kB of random data?
 */
static void benchmark_rng128(uint8_t *pilot, size_t pilotlen, uint8_t *bench,
                             size_t benchlen, uint32_t rounds) {
  randombytes_rng128(pilot, pilotlen);
  printf("randombytes 128 pilot: ");
  print_hexstr(pilot, pilotlen);

  uint64_t bench_start = time_us_64();
  for (uint32_t round = 0; round < rounds; round++) {
    randombytes_rng128(bench, benchlen);
  }
  uint64_t bench_dur = time_us_64() - bench_start;
  // TODO: remove overhead?
  printf("Generated %zu bytes in %llu us\n", benchlen * rounds, bench_dur);
}

/**
 * How much time does it take to fill in 4kB of random data?
 */
static void benchmark_rng64(uint8_t *pilot, size_t pilotlen, uint8_t *bench,
                            size_t benchlen, uint32_t rounds) {
  randombytes_rng64(pilot, pilotlen);
  printf("randombytes 64 pilot: ");
  print_hexstr(pilot, pilotlen);

  uint64_t bench_start = time_us_64();
  for (uint32_t round = 0; round < rounds; round++) {
    randombytes_rng64(bench, benchlen);
  }
  uint64_t bench_dur = time_us_64() - bench_start;
  // TODO: remove overhead?
  printf("Generated %zu bytes in %llu us\n", benchlen * rounds, bench_dur);
}

/**
 * How much time does it take to fill in 4kB of random data?
 */
static void benchmark_rng32(uint8_t *pilot, size_t pilotlen, uint8_t *bench,
                            size_t benchlen, uint32_t rounds) {
  randombytes_rng32(pilot, pilotlen);
  printf("randombytes 32 pilot: ");
  print_hexstr(pilot, pilotlen);
  printf("\n");

  uint64_t bench_start = time_us_64();
  for (uint32_t round = 0; round < rounds; round++) {
    randombytes_rng32(bench, benchlen);
  }
  uint64_t bench_dur = time_us_64() - bench_start;
  // TODO: remove overhead?
  printf("Generated %zu bytes in %llu us\n", benchlen * rounds, bench_dur);
}

int main(void) {
  stdio_init_all();

  uint16_t ctr = 0;
  uint8_t randpilot[RAND_PILOT_LEN] = {0};
  uint8_t randbench[RAND_BENCH_LEN] = {0};

  while (1) {
    printf("========== Epoch %03d ==========\n", ctr);
    benchmark_rng128(randpilot, RAND_PILOT_LEN, randbench, RAND_BENCH_LEN, 1000);
    benchmark_rng64(randpilot, RAND_PILOT_LEN, randbench, RAND_BENCH_LEN, 1000);
    benchmark_rng32(randpilot, RAND_PILOT_LEN, randbench, RAND_BENCH_LEN, 1000);
    printf("========== Epoch end  ==========\n");
    ctr++;
    sleep_ms(1000);
  }
}

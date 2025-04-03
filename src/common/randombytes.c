/**
 * Platform-dependent random number generator
 *
 * TODO: why does randombytes_rng64 have the best performance?
 *   randombytes_rng32 is half as fast; randombytes_rng128 is slightly slower
 */
#include "randombytes.h"
#include <pico/rand.h>
#include <string.h>

/**
 * Fill in the specified number of bytes using the rng128 method
 */
static void randombytes_rng128(uint8_t *bytes, size_t len) {
  rng_128_t rng_128;
  size_t written = 0;
  size_t chunklen;

  while (written < len) {
    get_rand_128(&rng_128);
    chunklen = MIN(len - written, sizeof(rng_128_t));
    memcpy(bytes + written, rng_128.r, chunklen);
    written += chunklen;
  }
}

/**
 * Fill in the specified number of bytes using the rng32 method
 */
static void randombytes_rng32(uint8_t *bytes, size_t len) {
  size_t written = 0;
  size_t chunklen;
  uint32_t rng;

  while (written < len) {
    rng = get_rand_32();
    chunklen = MIN(len - written, sizeof(uint32_t));
    memcpy(bytes + written, &rng, chunklen);
    written += chunklen;
  }
}

/**
 * Fill in the specified number of bytes using the rng32 method
 */
static void randombytes_rng64(uint8_t *bytes, size_t len) {
  size_t written = 0;
  size_t chunklen;
  uint64_t rng;

  while (written < len) {
    rng = get_rand_64();
    chunklen = MIN(len - written, sizeof(uint64_t));
    memcpy(bytes + written, &rng, chunklen);
    written += chunklen;
  }
}

int randombytes(uint8_t *output, size_t n) {
  randombytes_rng64(output, n);
  return 0;
}


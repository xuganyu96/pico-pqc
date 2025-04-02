/**
 * Random number generators for liboqs
 */
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stdint.h>
#include <stdlib.h>

void randombytes_rng128(uint8_t *bytes, size_t len);

void randombytes_rng64(uint8_t *bytes, size_t len);

void randombytes_rng32(uint8_t *bytes, size_t len);

#endif

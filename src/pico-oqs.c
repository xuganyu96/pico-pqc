// TODO: this is a POC, remove it afterwards
#include "oqs/kem.h"
#include "pico/stdio.h"
#include "pico/time.h"
#include <stdio.h>
#include <string.h>

#define TRY_MALLOC_MAX (400000)

/* Displays hexadecimal strings */
static void OQS_print_hex_string(const char *label, const uint8_t *str,
                                 size_t len) {
  printf("%-20s (%4zu bytes):  ", label, len);
  for (size_t i = 0; i < (len); i++) {
    printf("%02X", str[i]);
  }
  printf("\n");
}

/**
 * I rolled a dice and it came up 4. It is totally random!
 * TODO: good RNG
 * https://www.raspberrypi.com/documentation/pico-sdk/high_level.html#group_pico_rand_1ga97a9544b527a3ba865ab70142bdd5d1b
 */
static void bad_rng(uint8_t *arr, size_t len) {
  for (size_t i = 0; i < len; i++) {
    arr[i] = 4;
  }
}

static void *try_malloc(size_t size) {
  if (size > TRY_MALLOC_MAX) {
    return NULL;
  }
  return malloc(size);
}

static OQS_STATUS kem_test_correctness(const char *method_name) {
  OQS_STATUS ret = OQS_SUCCESS;
  OQS_KEM *kem = NULL;
  uint8_t *pk = NULL;
  uint8_t *sk = NULL;
  uint8_t *ct = NULL;
  uint8_t *ss = NULL;
  uint8_t *ss_cmp = NULL;

  kem = OQS_KEM_new(method_name);
  if (!kem) {
    goto err;
  }
  printf("Allocated for %s\n", method_name);
  pk = try_malloc(kem->length_public_key);
  if (!pk) {
    printf("Requested %zu/%zu bytes for pk\n", kem->length_public_key,
           TRY_MALLOC_MAX);
    goto err;
  }
  printf("Allocated %zu bytes for pk\n", kem->length_public_key);
  sk = try_malloc(kem->length_secret_key);
  if (!sk) {
    printf("Requested %zu/%zu bytes for sk\n", kem->length_secret_key,
           TRY_MALLOC_MAX);
    goto err;
  }
  printf("Allocated %zu bytes for sk\n", kem->length_secret_key);
  ct = try_malloc(kem->length_ciphertext);
  if (!ct) {
    printf("Requested %zu/%zu bytes for ct\n", kem->length_ciphertext,
           TRY_MALLOC_MAX);
    goto err;
  }
  printf("Allocated %zu bytes for ct\n", kem->length_ciphertext);
  ss = try_malloc(kem->length_shared_secret);
  if (!ss) {
    printf("Requested %zu/%zu bytes for ss\n", kem->length_shared_secret,
           TRY_MALLOC_MAX);
    goto err;
  }
  printf("Allocated %zu bytes for ss\n", kem->length_shared_secret);
  ss_cmp = try_malloc(kem->length_shared_secret);
  if (!ss_cmp) {
    printf("Requested %zu/%zu bytes for ss_cmp\n", kem->length_shared_secret,
           TRY_MALLOC_MAX);
    goto err;
  }
  printf("Allocated %zu bytes for ss_cmp\n", kem->length_shared_secret);

  if (kem->keypair(pk, sk) != OQS_SUCCESS) {
    printf("Keygen failed\n");
    goto err;
  }
  if (kem->encaps(ct, ss, pk) != OQS_SUCCESS) {
    printf("Encap failed\n");
    goto err;
  }
  if (kem->decaps(ss_cmp, ct, sk) != OQS_SUCCESS) {
    printf("Decap failed\n");
    goto err;
  }
  if (memcmp(ss, ss_cmp, kem->length_shared_secret) != 0) {
    printf("Decapsulation is incorect\n");
    goto err;
  }

  goto cleanup;

err:
  ret = OQS_ERROR;

cleanup:
  if (pk)
    OQS_MEM_insecure_free(pk);
  if (ct)
    OQS_MEM_insecure_free(ct);
  if (sk)
    OQS_MEM_secure_free(sk, kem->length_secret_key);
  if (ss)
    OQS_MEM_secure_free(ss, kem->length_shared_secret);
  if (ss_cmp)
    OQS_MEM_secure_free(ss_cmp, kem->length_shared_secret);
  OQS_KEM_free(kem);

  return ret;
}

int main() {
  stdio_init_all();

  OQS_init();
  OQS_randombytes_custom_algorithm(bad_rng);
  OQS_STATUS rc;
  int i = 0;

  while (1) {
    const char *alg_name = OQS_KEM_alg_identifier(i);
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
      printf("KEM algorithm %s not enabled!\n", alg_name);
      i = (i + 1) % OQS_KEM_alg_count();
      continue;
    }
    // TODO: skip classic mceliece for now
    if (strncmp(alg_name, "Classic", 7) == 0) {
      printf("Skipping %s\n", alg_name);
      i = (i + 1) % OQS_KEM_alg_count();
      continue;
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    printf("Testing %s\n", alg_name);
    rc = kem_test_correctness(alg_name);

    if (rc != OQS_SUCCESS) {
      printf("%s: Fail\n", alg_name);
    } else {
      printf("%s: Ok\n", alg_name);
    }
    printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n");

    i = (i + 1) % OQS_KEM_alg_count();
    sleep_ms(1000);
  }
}

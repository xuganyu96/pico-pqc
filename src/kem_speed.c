/**
 * Benchmarking speed for KEMs
 */
#include "cyccnt.h"
#include "oqs/kem.h"
#include "oqs/rand.h"
#include "randombytes.h"
#include <inttypes.h>
#include <pico/stdio.h>
#include <pico/time.h>
#include <stdio.h>
#include <string.h>

#define ROUNDS_LOG2 7
#define TRY_MALLOC_MAX (400000)

// TODO: may be custom allocators in `trymalloc.h`?
static void *try_malloc(size_t size) {
  if (size > TRY_MALLOC_MAX) {
    return NULL;
  }
  return malloc(size);
}

/**
 * naive benchmarker: start a timer, run the func a bunch of times, then print a
 * line of CSV: <target name>,total_dur
 *
 * TODO: this does not deal well with routines that have large variationss, such
 * as ML-DSA sign although maybe this should be treated as a building block to
 * produce primitive data, and the analysis on variations and stuff should NOT
 * happen on the board
 */
static void black_box_bench(const char *target_name,
                            void (*target_func)(void)) {
  uint32_t cycle_cnt = 0;
  uint32_t total_begin, total_end, overhead_begin, overhead_end, dur;
  reset_cyccnt();
  total_begin = read_cyccnt();
  for (uint32_t i = 0; i < (1 << ROUNDS_LOG2); i++) {
    target_func();
  }
  total_end = read_cyccnt();
  reset_cyccnt();
  overhead_begin = read_cyccnt();
  for (uint32_t i = 0; i < (1 << ROUNDS_LOG2); i++)
    ;
  overhead_end = read_cyccnt();
  dur = ((total_end - total_begin) - (overhead_end - overhead_begin)) >>
        ROUNDS_LOG2;

  printf("%s,%" PRIu32 "\n", target_name, dur);
}

static void busybox(void) { sleep_ms(10); }

/**
 * Benchmark a single instance of a KEM
 */
static void bench_kem(const char *method_name) {
  OQS_STATUS keypair_status, encap_status, decap_status, ret;
  OQS_KEM *kem = NULL;
  uint8_t *pk = NULL;
  uint8_t *sk = NULL;
  uint8_t *ct = NULL;
  uint8_t *ss = NULL;
  uint8_t *ss_cmp = NULL;
  uint32_t cyccnt_before, cyccnt_after;

  kem = OQS_KEM_new(method_name);
  if (!kem) {
    goto err;
  }
  pk = try_malloc(kem->length_public_key);
  if (!pk) {
    printf("Requested %zu/%zu bytes for pk\n", kem->length_public_key,
           TRY_MALLOC_MAX);
    goto err;
  }
  sk = try_malloc(kem->length_secret_key);
  if (!sk) {
    printf("Requested %zu/%zu bytes for sk\n", kem->length_secret_key,
           TRY_MALLOC_MAX);
    goto err;
  }
  ct = try_malloc(kem->length_ciphertext);
  if (!ct) {
    printf("Requested %zu/%zu bytes for ct\n", kem->length_ciphertext,
           TRY_MALLOC_MAX);
    goto err;
  }
  ss = try_malloc(kem->length_shared_secret);
  if (!ss) {
    printf("Requested %zu/%zu bytes for ss\n", kem->length_shared_secret,
           TRY_MALLOC_MAX);
    goto err;
  }
  ss_cmp = try_malloc(kem->length_shared_secret);
  if (!ss_cmp) {
    printf("Requested %zu/%zu bytes for ss_cmp\n", kem->length_shared_secret,
           TRY_MALLOC_MAX);
    goto err;
  }

  // TODO: we need more scientific testing methodology
  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  keypair_status = kem->keypair(pk, sk);
  cyccnt_after = read_cyccnt();
  printf("%s,%s,%" PRIu32 ",%d\n", kem->method_name, "keypair",
         cyccnt_after - cyccnt_before, keypair_status);
  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  encap_status = kem->encaps(ct, ss, pk);
  cyccnt_after = read_cyccnt();
  printf("%s,%s,%" PRIu32 ",%d\n", kem->method_name, "encaps",
         cyccnt_after - cyccnt_before, encap_status);
  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  decap_status = kem->decaps(ss_cmp, ct, sk);
  cyccnt_after = read_cyccnt();
  printf("%s,%s,%" PRIu32 ",%d\n", kem->method_name, "decaps",
         cyccnt_after - cyccnt_before, decap_status);
  if (memcmp(ss, ss_cmp, kem->length_shared_secret) != 0) {
    printf("ERROR: Decapsulation is incorect\n");
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
}

int main(void) {
  stdio_init_all();
  enable_dwt();
  OQS_init();
  OQS_randombytes_custom_algorithm(randombytes_rng64);

  while (1) {
    printf("algorithm,routine,cycles,fail\n");
    for (int alg_id = 0; alg_id < OQS_KEM_alg_count(); alg_id++) {
      const char *alg_name = OQS_KEM_alg_identifier(alg_id);
      if (!OQS_KEM_alg_is_enabled(alg_name)) {
        printf("ERROR: KEM algorithm %s not enabled!\n", alg_name);
        continue;
      }
      // if (strncmp(alg_name, "Classic", 7) == 0) {
      //   printf("WARNING: Skipping %s\n", alg_name);
      //   continue;
      // }
      bench_kem(alg_name);
    }
    sleep_ms(1000);
  }
}

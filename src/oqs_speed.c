/**
 * Benchmarking speed for KEMs
 */
#include "cyccnt.h"
#include "oqs/kem.h"
#include "oqs/rand.h"
#include "oqs/sig.h"
#include "randombytes.h"
#include <inttypes.h>
#include <pico/stdio.h>
#include <pico/time.h>
#include <stdio.h>
#include <string.h>

#define TRY_MALLOC_MAX (400000)
#define ESTIMATED_TLS_TRANSCRIPT_SIZE (4096)

// TODO: may be custom allocators in `trymalloc.h`?
static void *try_malloc(size_t size) {
  if (size > TRY_MALLOC_MAX) {
    return NULL;
  }
  return malloc(size);
}

/**
 * Benchmark a single instance of digital signature on a random msg of the
 * specified size
 */
static void bench_sig(const char *method_name, size_t msglen) {
  OQS_SIG *sig;
  uint8_t *pk;
  uint8_t *sk;
  uint8_t *msg;
  uint8_t *sigma;
  size_t sigmalen;
  OQS_STATUS rc, ret;

  sig = OQS_SIG_new(method_name);
  if (!sig) {
    printf("ERROR: Failed to fetch %s\n", method_name);
    goto err;
  }
  printf("%s,init,0,0\n", sig->method_name);

  pk = try_malloc(sig->length_public_key);
  if (!pk) {
    printf("Requested %zu/%zu bytes for pk\n", sig->length_public_key,
           TRY_MALLOC_MAX);
    goto err;
  }
  sk = try_malloc(sig->length_secret_key);
  if (!sk) {
    printf("Requested %zu/%zu bytes for sk\n", sig->length_secret_key,
           TRY_MALLOC_MAX);
    goto err;
  }
  msg = try_malloc(msglen);
  if (!msg) {
    printf("Requested %zu/%zu bytes for msg\n", msglen, TRY_MALLOC_MAX);
    goto err;
  }
  sigma = try_malloc(sig->length_signature);
  if (!sigma) {
    printf("Requested %zu/%zu bytes for signature\n", sig->length_signature,
           TRY_MALLOC_MAX);
    goto err;
  }

  uint32_t cyccnt_before, cyccnt_after;
  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  rc = sig->keypair(pk, sk);
  cyccnt_after = read_cyccnt();
  printf("%s,%s,%" PRIu32 ",%d\n", sig->method_name, "keypair",
         cyccnt_after - cyccnt_before, rc);

  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  rc = sig->sign(sigma, &sigmalen, msg, msglen, sk);
  cyccnt_after = read_cyccnt();
  printf("%s,%s,%" PRIu32 ",%d\n", sig->method_name, "sign",
         cyccnt_after - cyccnt_before, rc);

  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  rc = sig->verify(msg, msglen, sigma, sigmalen, pk);
  cyccnt_after = read_cyccnt();
  printf("%s,%s,%" PRIu32 ",%d\n", sig->method_name, "verify",
         cyccnt_after - cyccnt_before, rc);
  goto cleanup;

err:
  ret = OQS_ERROR;

cleanup:
  if (sk)
    OQS_MEM_secure_free(sk, sig->length_secret_key);
  if (pk)
    OQS_MEM_insecure_free(pk);
  if (msg)
    OQS_MEM_insecure_free(msg);
  if (sigma)
    OQS_MEM_insecure_free(sigma);
  OQS_SIG_free(sig);
}

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
  printf("%s,init,0,0\n", kem->method_name);
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
    printf("algorithm,routine,cycles,retcode\n");
    for (int alg_id = 0; alg_id < OQS_SIG_alg_count(); alg_id++) {
      const char *alg_name = OQS_SIG_alg_identifier(alg_id);
      if (
        (strncmp(alg_name, "SPHINCS", strlen("SPHINCS")) == 0)
        || (strncmp(alg_name, "MAYO", strlen("MAYO")) == 0)
        || (strncmp(alg_name, "cross", strlen("cross")) == 0)
        || (strncmp(alg_name, "OV", strlen("OV")) == 0)
      ) {
        printf("WARNING: Skipping %s\n", alg_name);
        continue;
      }
      printf("DEBUG: %s\n", alg_name);
      if (!OQS_SIG_alg_is_enabled(alg_name)) {
        printf("ERROR: SIG algorithm %s not enabled\n", alg_name);
        continue;
      }
      bench_sig(alg_name, ESTIMATED_TLS_TRANSCRIPT_SIZE);
    }

    for (int alg_id = 0; alg_id < OQS_KEM_alg_count(); alg_id++) {
      const char *alg_name = OQS_KEM_alg_identifier(alg_id);
      if (!OQS_KEM_alg_is_enabled(alg_name)) {
        printf("ERROR: KEM algorithm %s not enabled!\n", alg_name);
        continue;
      }
      if (strncmp(alg_name, "Classic", 7) == 0) {
        printf("WARNING: Skipping %s\n", alg_name);
        continue;
      }
      bench_kem(alg_name);
    }

    // sleep_ms(1000);
  }
}

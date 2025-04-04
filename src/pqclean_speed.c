/**
 * Benchmarking PQClean's implementations
 */
#include <inttypes.h>
#include <pico/stdio.h>
#include <pico/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_kem/hqc-128/clean/api.h"
#include "crypto_kem/hqc-192/clean/api.h"
#include "crypto_kem/hqc-256/clean/api.h"
// #include "crypto_kem/mceliece348864f/clean/api.h"
#include "crypto_kem/ml-kem-1024/clean/api.h"
#include "crypto_kem/ml-kem-512/clean/api.h"
#include "crypto_kem/ml-kem-768/clean/api.h"
#include "crypto_sign/ml-dsa-44/clean/api.h"
#include "crypto_sign/ml-dsa-65/clean/api.h"
#include "crypto_sign/ml-dsa-87/clean/api.h"
#include "crypto_sign/falcon-512/clean/api.h"
#include "crypto_sign/falcon-1024/clean/api.h"
#include "cyccnt.h"

#define ESTIMATE_TLS_TRANSCRIPT_SIZE 4096

static void println_csv(const char *alg, const char *routine, uint32_t cycles,
                        int ret) {
  printf("%s,%s,%" PRIu32 ",%d\n", alg, routine, cycles, ret);
}

static void
bench_kem(size_t pksize, size_t sksize, size_t ctsize, size_t sssize,
          int (*crypto_kem_keypair)(uint8_t *, uint8_t *),
          int (*crypto_kem_enc)(uint8_t *, uint8_t *, const uint8_t *),
          int (*crypto_kem_dec)(uint8_t *, const uint8_t *, const uint8_t *),
          const char *method_name) {
  uint8_t *pk = malloc(pksize);
  if (!pk)
    printf("ERROR: failed to allocate %s pk %zu bytes\n", method_name, pksize);
  uint8_t *sk = malloc(sksize);
  if (!sk)
    printf("ERROR: failed to allocate %s sk %zu bytes\n", method_name, sksize);
  uint8_t *ct = malloc(ctsize);
  if (!ct)
    printf("ERROR: failed to allocate %s ct %zu bytes\n", method_name, ctsize);
  uint8_t *ss = malloc(sssize);
  if (!ss)
    printf("ERROR: failed to allocate %s ss %zu bytes\n", method_name, sssize);
  uint8_t *ss_cmp = malloc(sssize);
  if (!ss_cmp)
    printf("ERROR: failed to allocate %s ss %zu bytes\n", method_name, sssize);
  int keypair_status, encap_status, decap_status;
  uint32_t cyccnt_start, cyccnt_stop;

  reset_cyccnt();
  cyccnt_start = read_cyccnt();
  keypair_status = crypto_kem_keypair(pk, sk);
  cyccnt_stop = read_cyccnt();
  println_csv(method_name, "keypair", cyccnt_stop - cyccnt_start,
              keypair_status);
  if (keypair_status != 0) {
    printf("ERROR: %s keypair failed\n", method_name);
    goto cleanup;
  }

  reset_cyccnt();
  cyccnt_start = read_cyccnt();
  encap_status = crypto_kem_enc(ct, ss, pk);
  cyccnt_stop = read_cyccnt();
  println_csv(method_name, "encap", cyccnt_stop - cyccnt_start, keypair_status);
  if (encap_status != 0) {
    printf("ERROR: %s encap failed\n", method_name);
    goto cleanup;
  }

  reset_cyccnt();
  cyccnt_start = read_cyccnt();
  decap_status = crypto_kem_dec(ss_cmp, ct, sk);
  cyccnt_stop = read_cyccnt();
  println_csv(method_name, "decap", cyccnt_stop - cyccnt_start, keypair_status);
  if (decap_status != 0) {
    printf("ERROR: %s decap failed\n", method_name);
    goto cleanup;
  }
  if (memcmp(ss, ss_cmp, sizeof(sssize)) != 0) {
    printf("ERROR: %s decap incorrect\n", method_name);
    goto cleanup;
  }
  // printf("DEBUG: %s Ok.\n", method_name);

cleanup:
  if (pk)
    free(pk);
  if (sk) {
    memset(sk, 0, sizeof(sksize));
    free(sk);
  }
  if (ct)
    free(ct);
  if (ss) {
    memset(ss, 0, sizeof(sssize));
    free(ss);
  }
  if (ss_cmp) {
    memset(ss_cmp, 0, sizeof(sssize));
    free(ss_cmp);
  }
}

static void
bench_sign(size_t pksize, size_t sksize, size_t msgsize, size_t sigsize,
           int (*crypto_sign_keypair)(uint8_t *, uint8_t *),
           int (*crypto_sign_sign_signature)(uint8_t *, size_t *, const uint8_t *,
                                             size_t, const uint8_t *),
           int (*crypto_sign_verify)(const uint8_t *sig, size_t siglen,
                                     const uint8_t *, size_t, const uint8_t *),
           const char *method_name) {
  uint8_t *pk, *sk, *msg, *sig;
  // The actual size of the signature
  size_t siglen;
  uint32_t cyccnt_before, cyccnt_after;
  int retcode;

  pk = malloc(pksize);
  if (!pk) {
    printf("ERROR: failed to allocate %s pk %zu bytes\n", method_name, pksize);
  }
  sk = malloc(sksize);
  if (!sk) {
    printf("ERROR: failed to allocate %s sk %zu bytes\n", method_name, sksize);
  }
  msg = malloc(msgsize);
  if (!msg) {
    printf("ERROR: failed to allocate %s msg %zu bytes\n", method_name,
           msgsize);
  }
  sig = malloc(sigsize);
  if (!sig) {
    printf("ERROR: failed to allocate %s sig %zu bytes\n", method_name,
           sigsize);
  }

  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  retcode = crypto_sign_keypair(pk, sk);
  cyccnt_after = read_cyccnt();
  println_csv(method_name, "keypair", cyccnt_after - cyccnt_before, retcode);
  if (retcode != 0) {
    printf("ERROR: %s keypair failed\n", method_name);
    goto cleanup;
  }

  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  retcode = crypto_sign_sign_signature(sig, &siglen, msg, msgsize, sk);
  cyccnt_after = read_cyccnt();
  println_csv(method_name, "sign", cyccnt_after - cyccnt_before, retcode);
  if (retcode != 0) {
    printf("ERROR: %s sign failed\n", method_name);
    goto cleanup;
  }

  reset_cyccnt();
  cyccnt_before = read_cyccnt();
  retcode = crypto_sign_verify(sig, siglen, msg, msgsize, pk);
  cyccnt_after = read_cyccnt();
  println_csv(method_name, "verify", cyccnt_after - cyccnt_before, retcode);
  if (retcode != 0) {
    printf("ERROR: %s verify failed\n", method_name);
    goto cleanup;
  }

cleanup:
  if (pk)
    free(pk);
  if (sk)
    free(sk);
  if (msg)
    free(msg);
  if (sig)
    free(sig);
}

int main(void) {
  stdio_init_all();
  enable_dwt();

  while (1) {
    bench_kem(PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
              PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
              PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
              PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES,
              PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair,
              PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc,
              PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec,
              PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME);
    bench_kem(PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
              PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES,
              PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
              PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES,
              PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair,
              PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc,
              PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec,
              PQCLEAN_MLKEM768_CLEAN_CRYPTO_ALGNAME);
    bench_kem(PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
              PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
              PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
              PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES,
              PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair,
              PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc,
              PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec,
              PQCLEAN_MLKEM1024_CLEAN_CRYPTO_ALGNAME);
    bench_kem(PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES,
              PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES,
              PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
              PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES,
              PQCLEAN_HQC128_CLEAN_crypto_kem_keypair,
              PQCLEAN_HQC128_CLEAN_crypto_kem_enc,
              PQCLEAN_HQC128_CLEAN_crypto_kem_dec,
              PQCLEAN_HQC128_CLEAN_CRYPTO_ALGNAME);
    bench_kem(PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES,
              PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES,
              PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES,
              PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES,
              PQCLEAN_HQC192_CLEAN_crypto_kem_keypair,
              PQCLEAN_HQC192_CLEAN_crypto_kem_enc,
              PQCLEAN_HQC192_CLEAN_crypto_kem_dec,
              PQCLEAN_HQC192_CLEAN_CRYPTO_ALGNAME);
    bench_kem(PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES,
              PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES,
              PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES,
              PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES,
              PQCLEAN_HQC256_CLEAN_crypto_kem_keypair,
              PQCLEAN_HQC256_CLEAN_crypto_kem_enc,
              PQCLEAN_HQC256_CLEAN_crypto_kem_dec,
              PQCLEAN_HQC256_CLEAN_CRYPTO_ALGNAME);
    bench_sign(PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
               PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
               ESTIMATE_TLS_TRANSCRIPT_SIZE, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
               PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
               PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_inline,
               PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_inline,
               PQCLEAN_MLDSA44_CLEAN_CRYPTO_ALGNAME);
    bench_sign(PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
               PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
               ESTIMATE_TLS_TRANSCRIPT_SIZE, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES,
               PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
               PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_inline,
               PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_inline,
               PQCLEAN_MLDSA65_CLEAN_CRYPTO_ALGNAME);
    bench_sign(PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
               PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES,
               ESTIMATE_TLS_TRANSCRIPT_SIZE, PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES,
               PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
               PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_inline,
               PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_inline,
               PQCLEAN_MLDSA87_CLEAN_CRYPTO_ALGNAME);
    bench_sign(PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
               PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES,
               ESTIMATE_TLS_TRANSCRIPT_SIZE, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES,
               PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair,
               PQCLEAN_FALCON512_CLEAN_crypto_sign_signature,
               PQCLEAN_FALCON512_CLEAN_crypto_sign_verify,
               PQCLEAN_FALCON512_CLEAN_CRYPTO_ALGNAME);
    bench_sign(PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
               PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES,
               ESTIMATE_TLS_TRANSCRIPT_SIZE, PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES,
               PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair,
               PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature,
               PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify,
               PQCLEAN_FALCON1024_CLEAN_CRYPTO_ALGNAME);

    // TODO: why does mceliece348864 run out of memory?
    // bench_kem(
    //   PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    //   PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES,
    //   PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    //   PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES,
    //   PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair,
    //   PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc,
    //   PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec,
    //   PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_ALGNAME
    // );
  }
}

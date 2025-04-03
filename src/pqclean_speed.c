/**
 * Benchmarking PQClean's implementations
 */
#include <inttypes.h>
#include <pico/stdio.h>
#include <pico/time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto_kem/ml-kem-512/clean/api.h"
#include "cyccnt.h"

static void println_csv(const char *alg, const char *routine, uint32_t cycles,
                        int ret) {
  printf("%s,%s,%" PRIu32 ",%d\n", alg, routine, cycles, ret);
}

static void bench_ml_kem_512(void) {
  uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
  uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
  uint8_t ss_cmp[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
  int keypair_status, encap_status, decap_status;
  uint32_t cyccnt_start, cyccnt_stop;

  reset_cyccnt();
  cyccnt_start = read_cyccnt();
  keypair_status = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
  cyccnt_stop = read_cyccnt();
  println_csv(PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME, "keypair",
              cyccnt_stop - cyccnt_start, keypair_status);
  if (keypair_status != 0) {
    printf("ERROR: ML-KEM-512 keypair failed\n");
    goto cleanup;
  }

  reset_cyccnt();
  cyccnt_start = read_cyccnt();
  encap_status = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
  cyccnt_stop = read_cyccnt();
  println_csv(PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME, "encap",
              cyccnt_stop - cyccnt_start, keypair_status);
  if (encap_status != 0) {
    printf("ERROR: ML-KEM-512 encap failed\n");
    goto cleanup;
  }

  reset_cyccnt();
  cyccnt_start = read_cyccnt();
  decap_status = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss_cmp, ct, sk);
  cyccnt_stop = read_cyccnt();
  println_csv(PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME, "decap",
              cyccnt_stop - cyccnt_start, keypair_status);
  if (decap_status != 0) {
    printf("ERROR: ML-KEM-512 decap failed\n");
    goto cleanup;
  }
  if (memcmp(ss, ss_cmp, sizeof(ss)) != 0) {
    printf("ERROR: ML-KEM-512 decap incorrect\n");
    goto cleanup;
  }
  printf("DEBUG: ML-KEM-512 Ok.\n");

cleanup:
  memset(sk, 0, sizeof(sk));
  memset(ss, 0, sizeof(ss));
  memset(ss_cmp, 0, sizeof(ss_cmp));
}

int main(void) {
  stdio_init_all();
  enable_dwt();

  while (1) {
    bench_ml_kem_512();
    sleep_ms(1000);
  }
}

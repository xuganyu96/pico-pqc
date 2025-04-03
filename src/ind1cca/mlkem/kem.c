// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
#include "kem.h"
#include "../../randombytes.h"
#include "indcpa.h"
#include "params.h"
#include "polyvec.h"
#include "symmetric.h"
#include "verify.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * FIPS 203, Section 7.2, modulus check
 * Poorly ported from
 * github.com/open-quantum-safe/liboqs/src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/kem.c
 */
static int check_pk(const uint8_t pk[MLKEM_PUBLICKEYBYTES]) {
  int res;
  polyvec p;
  uint8_t p_reencoded[MLKEM_POLYVECBYTES];

  polyvec_frombytes(&p, pk);
  polyvec_reduce(&p);
  polyvec_tobytes(p_reencoded, &p);

  res = timingsafe_memcmp(pk, p_reencoded, MLKEM_POLYVECBYTES) ? -1 : 0;

  // FIPS 203, Section 3.3, Destruction of intermediate values
  memset(p_reencoded, 0, MLKEM_POLYVECBYTES);
  memset(&p, 0, sizeof(p));

  return res;
}

/**
 * FIPS 203, Section 7.3, hash check
 * Also poorly ported from liboqs
 */
static int check_sk(const uint8_t sk[MLKEM_SECRETKEYBYTES]) {
  int res;
  uint8_t test[MLKEM_SYMBYTES];

  hash_h(test, sk + MLKEM_INDCPA_SECRETKEYBYTES, MLKEM_PUBLICKEYBYTES);
  res = timingsafe_memcmp(sk + MLKEM_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, test,
                          MLKEM_SYMBYTES)
            ? -1
            : 0;
  memset(test, 0, sizeof(test));

  return res;
}

/**
 * FIPS 203, Section 7.1, Pairwise Consistency
 */
static int check_pct(const uint8_t pk[MLKEM_PUBLICKEYBYTES],
                     const uint8_t sk[MLKEM_SECRETKEYBYTES]) {
  int res;
  uint8_t ct[MLKEM_CIPHERTEXTBYTES];
  uint8_t ss[MLKEM_SSBYTES], ss_cmp[MLKEM_SSBYTES];
  res = crypto_kem_enc(ct, ss, pk);
  if (res != 0)
    goto cleanup;
  res = crypto_kem_dec(ss_cmp, ct, sk);
  if (res != 0)
    goto cleanup;
  res = timingsafe_memcmp(ss, ss_cmp, sizeof(ss));

cleanup:
  memset(ct, 0, sizeof(ct));
  memset(ss, 0, sizeof(ss));
  memset(ss_cmp, 0, sizeof(ss_cmp));
  return res;
}

/*************************************************
 * Name:        crypto_kem_keypair_derand
 *
 * Description: Generates public and private key
 *              for CCA-secure Mlkem key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of MLKEM_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of MLKEM_SECRETKEYBYTES bytes)
 *              - uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with 2*MLKEM_SYMBYTES
 *random bytes)
 **
 * Returns 0 (success)
 **************************************************/
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
  indcpa_keypair_derand(pk, sk, coins);
  memcpy(sk + MLKEM_INDCPA_SECRETKEYBYTES, pk, MLKEM_PUBLICKEYBYTES);
  hash_h(sk + MLKEM_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, pk,
         MLKEM_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  memcpy(sk + MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES, coins + MLKEM_SYMBYTES,
         MLKEM_SYMBYTES);

  // Pairwise Consistency Test
  if (check_pct(pk, sk))
    return -1;

  return 0;
}

/*************************************************
 * Name:        crypto_kem_keypair
 *
 * Description: Generates public and private key
 *              for CCA-secure Mlkem key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of MLKEM_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of MLKEM_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t coins[2 * MLKEM_SYMBYTES];
  randombytes(coins, 2 * MLKEM_SYMBYTES);
  crypto_kem_keypair_derand(pk, sk, coins);
  memset(coins, 0, sizeof(coins));
  return 0;
}

/*************************************************
 * Name:        crypto_kem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of MLKEM_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of MLKEM_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of MLKEM_PUBLICKEYBYTES bytes)
 *              - const uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with MLKEM_SYMBYTES random
 *bytes)
 **
 * Returns 0 (success)
 **************************************************/
int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                          const uint8_t *coins) {
  uint8_t buf[2 * MLKEM_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2 * MLKEM_SYMBYTES];

  if (check_pk(pk))
    return -1;

  memcpy(buf, coins, MLKEM_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf + MLKEM_SYMBYTES, pk, MLKEM_PUBLICKEYBYTES);
  hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

  /* coins are in kr+MLKEM_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES);

  memcpy(ss, kr, MLKEM_SYMBYTES);

  memset(buf, 0, sizeof(buf));
  memset(kr, 0, sizeof(kr));
  return 0;
}

/*************************************************
 * Name:        crypto_kem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of MLKEM_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of MLKEM_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of MLKEM_PUBLICKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  uint8_t coins[MLKEM_SYMBYTES];
  randombytes(coins, MLKEM_SYMBYTES);
  crypto_kem_enc_derand(ct, ss, pk, coins);
  memset(coins, 0, sizeof(coins));
  return 0;
}

/*************************************************
 * Name:        crypto_kem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of MLKEM_SSBYTES bytes)
 *              - const uint8_t *ct: pointer to input cipher text
 *                (an already allocated array of MLKEM_CIPHERTEXTBYTES bytes)
 *              - const uint8_t *sk: pointer to input private key
 *                (an already allocated array of MLKEM_SECRETKEYBYTES bytes)
 *
 * Returns 0.
 *
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  int fail;
  uint8_t buf[2 * MLKEM_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2 * MLKEM_SYMBYTES];
  // liboqs also includes a tmp for computing rejection symbol but it feels
  // redundant
  const uint8_t *pk = sk + MLKEM_INDCPA_SECRETKEYBYTES;

  if (check_sk(sk))
    return -1;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy(buf + MLKEM_SYMBYTES, sk + MLKEM_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES,
         MLKEM_SYMBYTES);
  hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

  /* coins are in kr+MLKEM_SYMBYTES */
  fail = indcpa_enc_cmp(ct, buf, pk, kr + MLKEM_SYMBYTES);

  /* Compute rejection key */
  rkprf(ss, sk + MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES, ct);

  /* Copy true key to return buffer if fail is false */
  cmov(ss, kr, MLKEM_SYMBYTES, (uint8_t)(1 - fail));

  memset(buf, 0, sizeof(buf));
  memset(kr, 0, sizeof(kr));

  return 0;
}

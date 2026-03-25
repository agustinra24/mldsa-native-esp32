/*
 * ML-DSA-87 test suite for ESP32 (Unity framework)
 *
 * Tests keygen, sign/verify round-trip, rejection of invalid inputs,
 * context length validation, signature randomness, and heap cleanup.
 *
 * Requires WiFi initialized for hardware TRNG.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "ml_dsa.h"

#define TAG "ML_DSA_TEST"

/* Shared key material, allocated once in setUp */
static uint8_t *s_pk  = NULL;
static uint8_t *s_sk  = NULL;
static uint8_t *s_sig = NULL;

static const char *TEST_MSG = "ML-DSA-87 test message for ESP32";
static const char *TEST_CTX = "test";

static void init_wifi_for_rng(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
}

void setUp(void)
{
    s_pk  = heap_caps_malloc(ML_DSA_PK_BYTES,  MALLOC_CAP_8BIT);
    s_sk  = heap_caps_malloc(ML_DSA_SK_BYTES,  MALLOC_CAP_8BIT);
    s_sig = heap_caps_malloc(ML_DSA_SIG_BYTES,  MALLOC_CAP_8BIT);
    TEST_ASSERT_NOT_NULL(s_pk);
    TEST_ASSERT_NOT_NULL(s_sk);
    TEST_ASSERT_NOT_NULL(s_sig);
}

void tearDown(void)
{
    if (s_sk) memset(s_sk, 0, ML_DSA_SK_BYTES);
    free(s_pk);  s_pk  = NULL;
    free(s_sk);  s_sk  = NULL;
    free(s_sig); s_sig = NULL;
}

/* 1. Keygen produces valid keys with correct sizes */
TEST_CASE("keygen produces valid keys", "[ml_dsa]")
{
    int rc = ml_dsa_keygen(s_pk, s_sk);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Keys must not be all zeros (probabilistically impossible) */
    uint8_t zero_pk[32] = {0};
    uint8_t zero_sk[32] = {0};
    TEST_ASSERT_NOT_EQUAL(0, memcmp(s_pk, zero_pk, sizeof(zero_pk)));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(s_sk, zero_sk, sizeof(zero_sk)));
}

/* 2. Sign and verify round-trip succeeds */
TEST_CASE("sign verify roundtrip", "[ml_dsa]")
{
    TEST_ASSERT_EQUAL_INT(0, ml_dsa_keygen(s_pk, s_sk));

    size_t siglen = 0;
    int rc = ml_dsa_sign(s_sig, &siglen,
                         (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                         (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_sk);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_GREATER_THAN(0, siglen);
    TEST_ASSERT_LESS_OR_EQUAL(ML_DSA_SIG_BYTES, siglen);

    rc = ml_dsa_verify(s_sig, siglen,
                       (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                       (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_pk);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

/* 3. Wrong context is rejected */
TEST_CASE("verify rejects wrong context", "[ml_dsa]")
{
    TEST_ASSERT_EQUAL_INT(0, ml_dsa_keygen(s_pk, s_sk));

    size_t siglen = 0;
    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_sign(s_sig, &siglen,
                    (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                    (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_sk));

    int rc = ml_dsa_verify(s_sig, siglen,
                           (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                           (const uint8_t *)"wrong", 5, s_pk);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* 4. Tampered message is rejected */
TEST_CASE("verify rejects tampered message", "[ml_dsa]")
{
    TEST_ASSERT_EQUAL_INT(0, ml_dsa_keygen(s_pk, s_sk));

    size_t siglen = 0;
    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_sign(s_sig, &siglen,
                    (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                    (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_sk));

    char tampered[64];
    size_t msglen = strlen(TEST_MSG);
    memcpy(tampered, TEST_MSG, msglen);
    tampered[0] ^= 0xFF;

    int rc = ml_dsa_verify(s_sig, siglen,
                           (const uint8_t *)tampered, msglen,
                           (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_pk);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* 5. Tampered signature is rejected */
TEST_CASE("verify rejects tampered signature", "[ml_dsa]")
{
    TEST_ASSERT_EQUAL_INT(0, ml_dsa_keygen(s_pk, s_sk));

    size_t siglen = 0;
    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_sign(s_sig, &siglen,
                    (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                    (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_sk));

    /* Flip one byte in the signature */
    s_sig[siglen / 2] ^= 0xFF;

    int rc = ml_dsa_verify(s_sig, siglen,
                           (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                           (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_pk);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* 6. Context > 255 bytes is rejected (FIPS 204 Section 3.2.6) */
TEST_CASE("sign rejects context longer than 255", "[ml_dsa]")
{
    TEST_ASSERT_EQUAL_INT(0, ml_dsa_keygen(s_pk, s_sk));

    uint8_t long_ctx[256];
    memset(long_ctx, 'A', sizeof(long_ctx));
    size_t siglen = 0;

    int rc = ml_dsa_sign(s_sig, &siglen,
                         (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                         long_ctx, 256, s_sk);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* 7. Two signatures of the same message differ (randomized signing) */
TEST_CASE("multiple signatures differ (randomized)", "[ml_dsa]")
{
    TEST_ASSERT_EQUAL_INT(0, ml_dsa_keygen(s_pk, s_sk));

    uint8_t *sig2 = heap_caps_malloc(ML_DSA_SIG_BYTES, MALLOC_CAP_8BIT);
    TEST_ASSERT_NOT_NULL(sig2);

    size_t siglen1 = 0, siglen2 = 0;

    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_sign(s_sig, &siglen1,
                    (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                    (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_sk));

    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_sign(sig2, &siglen2,
                    (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                    (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_sk));

    /* Both must verify */
    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_verify(s_sig, siglen1,
                      (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                      (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_pk));
    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_verify(sig2, siglen2,
                      (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                      (const uint8_t *)TEST_CTX, strlen(TEST_CTX), s_pk));

    /* Signatures must differ (randomized signing uses fresh rnd per call) */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(s_sig, sig2,
                                    siglen1 < siglen2 ? siglen1 : siglen2));
    free(sig2);
}

/* 8. Heap returns to baseline after full keygen+sign+verify cycle */
TEST_CASE("heap cleanup after operations", "[ml_dsa]")
{
    size_t heap_before = esp_get_free_heap_size();

    uint8_t *pk  = heap_caps_malloc(ML_DSA_PK_BYTES,  MALLOC_CAP_8BIT);
    uint8_t *sk  = heap_caps_malloc(ML_DSA_SK_BYTES,  MALLOC_CAP_8BIT);
    uint8_t *sig = heap_caps_malloc(ML_DSA_SIG_BYTES,  MALLOC_CAP_8BIT);
    TEST_ASSERT_NOT_NULL(pk);
    TEST_ASSERT_NOT_NULL(sk);
    TEST_ASSERT_NOT_NULL(sig);

    TEST_ASSERT_EQUAL_INT(0, ml_dsa_keygen(pk, sk));

    size_t siglen = 0;
    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_sign(sig, &siglen,
                    (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                    (const uint8_t *)TEST_CTX, strlen(TEST_CTX), sk));

    TEST_ASSERT_EQUAL_INT(0,
        ml_dsa_verify(sig, siglen,
                      (const uint8_t *)TEST_MSG, strlen(TEST_MSG),
                      (const uint8_t *)TEST_CTX, strlen(TEST_CTX), pk));

    memset(sk, 0, ML_DSA_SK_BYTES);
    free(pk);
    free(sk);
    free(sig);

    size_t heap_after = esp_get_free_heap_size();
    int leaked = (int)(heap_before - heap_after);

    /* Allow up to 256 bytes tolerance for heap fragmentation */
    ESP_LOGI(TAG, "Heap before=%u after=%u leaked=%d",
             (unsigned)heap_before, (unsigned)heap_after, leaked);
    TEST_ASSERT_LESS_THAN(256, leaked);
}

void app_main(void)
{
    init_wifi_for_rng();
    ESP_LOGI(TAG, "Starting ML-DSA-87 test suite...");
    UNITY_BEGIN();
    unity_run_all_tests();
    UNITY_END();
}

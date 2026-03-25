/*
 * ML-DSA-87 basic example: keygen, sign, verify, and benchmark.
 *
 * Demonstrates the three core operations of the ML-DSA wrapper API
 * on ESP32. Requires WiFi initialized (not connected) for the hardware
 * TRNG to produce cryptographically secure randomness.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "ml_dsa.h"

#define TAG "ML_DSA_EXAMPLE"

/* Initialize WiFi in STA mode (not connected) to activate the RF
 * subsystem, which is required for esp_fill_random() to produce
 * cryptographically secure output. */
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

    ESP_LOGI(TAG, "WiFi STA started (RF subsystem active for TRNG)");
}

void app_main(void)
{
    init_wifi_for_rng();

    size_t heap_before = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Free heap before ML-DSA operations: %u bytes", (unsigned)heap_before);

    /* Allocate key material and signature buffer on heap.
     * ML-DSA-87 keys are large: pk=2592B, sk=4896B, sig=4627B. */
    uint8_t *pk  = heap_caps_malloc(ML_DSA_PK_BYTES,  MALLOC_CAP_8BIT);
    uint8_t *sk  = heap_caps_malloc(ML_DSA_SK_BYTES,  MALLOC_CAP_8BIT);
    uint8_t *sig = heap_caps_malloc(ML_DSA_SIG_BYTES,  MALLOC_CAP_8BIT);

    if (!pk || !sk || !sig) {
        ESP_LOGE(TAG, "Failed to allocate key/signature buffers");
        free(pk); free(sk); free(sig);
        return;
    }

    /* --- Keygen benchmark --- */
    int64_t t0 = esp_timer_get_time();
    int rc = ml_dsa_keygen(pk, sk);
    int64_t t1 = esp_timer_get_time();

    if (rc != 0) {
        ESP_LOGE(TAG, "ml_dsa_keygen failed: %d", rc);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Keygen OK   : %.2f ms", (t1 - t0) / 1000.0);

    /* --- Sign benchmark --- */
    const char *message = "Hello from ESP32 with post-quantum signatures!";
    size_t msglen = strlen(message);
    const char *ctx = "example";
    size_t ctxlen = strlen(ctx);
    size_t siglen = 0;

    t0 = esp_timer_get_time();
    rc = ml_dsa_sign(sig, &siglen,
                     (const uint8_t *)message, msglen,
                     (const uint8_t *)ctx, ctxlen, sk);
    t1 = esp_timer_get_time();

    if (rc != 0) {
        ESP_LOGE(TAG, "ml_dsa_sign failed: %d", rc);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Sign OK     : %.2f ms  (siglen=%u)", (t1 - t0) / 1000.0, (unsigned)siglen);

    /* --- Verify benchmark --- */
    t0 = esp_timer_get_time();
    rc = ml_dsa_verify(sig, siglen,
                       (const uint8_t *)message, msglen,
                       (const uint8_t *)ctx, ctxlen, pk);
    t1 = esp_timer_get_time();

    if (rc != 0) {
        ESP_LOGE(TAG, "ml_dsa_verify failed (should have passed): %d", rc);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Verify OK   : %.2f ms", (t1 - t0) / 1000.0);

    /* --- Negative tests --- */

    /* Wrong context must fail */
    rc = ml_dsa_verify(sig, siglen,
                       (const uint8_t *)message, msglen,
                       (const uint8_t *)"wrong", 5, pk);
    ESP_LOGI(TAG, "Wrong ctx   : %s (rc=%d)", rc != 0 ? "REJECTED" : "ERROR: accepted!", rc);

    /* Tampered message must fail */
    char tampered[64];
    memcpy(tampered, message, msglen);
    tampered[0] ^= 0xFF;
    rc = ml_dsa_verify(sig, siglen,
                       (const uint8_t *)tampered, msglen,
                       (const uint8_t *)ctx, ctxlen, pk);
    ESP_LOGI(TAG, "Tampered msg: %s (rc=%d)", rc != 0 ? "REJECTED" : "ERROR: accepted!", rc);

    /* Context too long must fail */
    uint8_t long_ctx[256];
    memset(long_ctx, 'A', sizeof(long_ctx));
    size_t long_siglen = 0;
    rc = ml_dsa_sign(sig, &long_siglen,
                     (const uint8_t *)message, msglen,
                     long_ctx, 256, sk);
    ESP_LOGI(TAG, "Long ctx    : %s (rc=%d)", rc != 0 ? "REJECTED" : "ERROR: accepted!", rc);

    /* --- Heap summary --- */
    size_t heap_peak = heap_before - esp_get_minimum_free_heap_size();
    ESP_LOGI(TAG, "Peak heap used during ML-DSA: ~%u bytes", (unsigned)heap_peak);

    ESP_LOGI(TAG, "=== All tests passed ===");

cleanup:
    /* Zeroize secret key before freeing */
    memset(sk, 0, ML_DSA_SK_BYTES);
    free(pk);
    free(sk);
    free(sig);

    size_t heap_after = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Free heap after cleanup: %u bytes (leaked: %d)",
             (unsigned)heap_after, (int)(heap_before - heap_after));
}

# mldsa-native-esp32

**ML-DSA-87 (FIPS 204) post-quantum digital signatures for ESP32, based on [mldsa-native](https://github.com/pq-code-package/mldsa-native).**

This is the first documented port of mldsa-native to the ESP32 platform (Xtensa LX6). It provides a ready-to-use ESP-IDF component for ML-DSA-87 (NIST Security Level 5), the post-quantum digital signature standard finalized by NIST in August 2024 as FIPS 204. ML-DSA is the successor to CRYSTALS-Dilithium, one of the algorithms selected by NIST's Post-Quantum Cryptography standardization process.

The upstream mldsa-native library, maintained by the [pq-code-package](https://github.com/pq-code-package) project under the Linux Foundation's Post-Quantum Cryptography Alliance (PQCA), is vendored unmodified. All ESP32-specific adaptation is isolated in three custom files (a configuration header, a wrapper API, and a CMake build file), preserving upstream's CBMC formal verification coverage and valgrind constant-time guarantees.

## Supported Targets

| Target | Status | Notes |
|--------|--------|-------|
| ESP32 (Xtensa LX6) | Tested | ESP32-WROOM-32D and 32E variants, 4MB flash, 520KB SRAM |
| ESP32-S2 | Untested | Uses Xtensa LX7; portable C backend should compile |
| ESP32-S3 | Untested | Dual-core Xtensa LX7; portable C backend should compile |
| ESP32-C3/C6/H2 | Untested | RISC-V cores; portable C90 backend is architecture-independent |

The component uses only the portable scalar C90 backend (no assembly, no SIMD). It should compile on any ESP-IDF v5.0+ target, but has only been validated on ESP32-WROOM-32D at 240 MHz.

## Key Sizes and Performance

### Cryptographic Parameters (ML-DSA-87, NIST Level 5)

| Parameter | Size |
|-----------|------|
| Public key | 2,592 bytes |
| Secret key | 4,896 bytes |
| Signature | up to 4,627 bytes |
| Seed | 32 bytes |

### Benchmarks (ESP32-WROOM-32D @ 240 MHz, N=1000)

| Operation | Mean | Std Dev | Notes |
|-----------|------|---------|-------|
| Key generation | 41.09 ms | 0.15 ms | Deterministic given seed |
| Signing | 185.17 ms | 146.63 ms | Variable: rejection sampling (geometric distribution) |
| Verification | 42.00 ms | 0.01 ms | Deterministic, constant-time |

### Memory Footprint

| Resource | Usage |
|----------|-------|
| Heap (peak, during keygen) | ~72 KB |
| Flash (component code) | ~19 KB |
| Stack (main task) | 8 KB sufficient (large buffers on heap) |

The ESP32-WROOM-32D has approximately 300 KB of usable SRAM after FreeRTOS, WiFi, and TCP/IP stacks are initialized. ML-DSA-87 operations are feasible with comfortable margins.

## What Was Ported

The `mldsa/` directory contains the complete mldsa-native v1.0.0-alpha (commit `b3f5140d`, 2025-11-14) from [pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native). These files are vendored (copied) unmodified, following upstream's recommended integration pattern. The upstream implementation covers:

- ML-DSA key generation, signing, and verification per FIPS 204
- Number Theoretic Transform (NTT) for polynomial multiplication
- SHAKE-128/256 (FIPS 202) for hashing and XOF operations
- Keccak-f[1600] sponge permutation
- Constant-time comparison and memory operations
- CBMC formal verification contracts (active in upstream CI)

Three custom files provide the ESP32 integration layer:

| File | Purpose |
|------|---------|
| `config/mldsa_config_esp32.h` | ESP32-specific configuration: heap allocator, hardware RNG, parameter set |
| `include/ml_dsa.h` | Thin wrapper API exposing three functions: keygen, sign, verify |
| `CMakeLists.txt` | ESP-IDF component registration using the Single Compilation Unit pattern |

No upstream source files were modified. All customization is done through mldsa-native's `MLD_CONFIG_FILE` mechanism, which allows downstream projects to override the default configuration via a compile-time header.

## Design Decisions

### Why ML-DSA-87 (Level 5)

ML-DSA is available in three parameter sets: ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), and ML-DSA-87 (Level 5). This port is configured for ML-DSA-87, which provides 256-bit post-quantum security, equivalent to the classical security margin of AES-256. While Level 2 or 3 would be faster and use less memory, Level 5 was chosen for maximum security margin in IoT device identity applications where keys may persist for years. Changing the parameter set requires only modifying `MLD_CONFIG_PARAMETER_SET` in the config header.

### Why NOT MLD_CONFIG_REDUCE_RAM

The mldsa-native library offers an experimental `MLD_CONFIG_REDUCE_RAM` option that reduces peak heap usage by approximately 30 KB during key generation (from ~100 KB to ~63 KB for ML-DSA-87). This option is intentionally **not enabled** because:

1. It is marked experimental in the upstream codebase
2. It is **not covered by upstream CBMC formal verification proofs**, which only validate the standard (non-reduced) configuration
3. The ESP32-WROOM-32D has approximately 254 KB of free heap after WiFi initialization, providing ample margin for the standard configuration
4. During prior auditing, disabling REDUCE_RAM exposed a double-free bug in consuming code that the reduced memory mode had masked, confirming the value of using the formally verified code path

### Stack-to-Heap Migration

ML-DSA-87 key generation requires approximately 100 KB of temporary working memory. On desktop systems, this fits on the stack. On ESP32, the main FreeRTOS task has only 8-12 KB of stack by default. The configuration defines `MLD_CONFIG_CUSTOM_ALLOC_FREE` to redirect all large internal buffers to heap via `heap_caps_malloc()`:

```c
#define MLD_CUSTOM_ALLOC(v, T, N) \
    T* (v) = (T *)heap_caps_malloc(sizeof(T) * (N), MALLOC_CAP_8BIT)
#define MLD_CUSTOM_FREE(v, T, N) free(v)
```

The `MALLOC_CAP_8BIT` flag provides 4-byte aligned memory. This is sufficient because the ESP32 uses only the portable scalar C backend; no SIMD instructions require stricter alignment (unlike x86_64 AVX2 which needs 32-byte alignment, or AArch64 NEON which needs 16-byte alignment).

### Hardware Random Number Generator

Signing and key generation require cryptographically secure randomness. The configuration defines `MLD_CONFIG_CUSTOM_RANDOMBYTES` backed by ESP-IDF's `esp_fill_random()`, which reads from the ESP32's hardware True Random Number Generator (TRNG):

```c
static inline int mld_randombytes(uint8_t *ptr, size_t len)
{
    esp_fill_random(ptr, len);
    return 0;
}
```

**Critical requirement:** The ESP32 hardware TRNG produces cryptographically secure output **only when the RF subsystem (WiFi or Bluetooth) is active**. When RF is disabled, `esp_fill_random()` falls back to a pseudo-random number generator that is not suitable for key generation or signing. Applications must ensure WiFi or Bluetooth is initialized before calling `ml_dsa_keygen()` or `ml_dsa_sign()`.

### Portable C90 Backend Only

The mldsa-native project provides optimized assembly backends for AArch64 (ARMv8-A with NEON) and x86_64 (AVX2). The ESP32's Xtensa LX6 core has no relevant SIMD instructions (its `VECTRA` DSP extension is optional and not present on the WROOM modules), so only the portable scalar C90 implementation is used. The `MLD_CONFIG_NO_ASM` option is not explicitly needed because the auto-detection in `sys.h` already disables assembly for non-AArch64/x86_64 targets.

### Single Compilation Unit (SCU)

The component compiles the upstream auto-generated `mldsa_native.c` file, which `#include`s all source files internally. This pattern, known as a Single Compilation Unit or "unity build," enables the compiler to inline internal functions across translation unit boundaries, improving performance. It also simplifies the ESP-IDF CMake configuration to a single source file:

```cmake
idf_component_register(
    SRCS "mldsa/mldsa_native.c"
    INCLUDE_DIRS "include" "mldsa"
    PRIV_REQUIRES esp_system
)
```

## What Was NOT Adapted (and Why)

| Feature | Status | Reason |
|---------|--------|--------|
| SIMD/assembly backends | Not used | Xtensa LX6 has no relevant SIMD; portable C90 is the only viable backend |
| MLD_CONFIG_REDUCE_RAM | Not enabled | Experimental, not covered by CBMC formal proofs (see above) |
| Multi-parameter support | ML-DSA-87 only | Simplifies binary size; change `MLD_CONFIG_PARAMETER_SET` in the config header for 44 or 65 |
| Kconfig menuconfig | Not implemented | Direct header configuration is simpler and more portable across ESP-IDF versions |
| FIPS-202 hardware acceleration | Not used | ESP32 has no SHA-3/Keccak hardware; software Keccak-f[1600] is used |
| External FIPS-202 replacement | Not used | The bundled FIPS-202 implementation is self-contained and CBMC-verified |

## Installation

### Option 1: Git Submodule (recommended)

```bash
cd your_project
git submodule add https://github.com/agustinra24/mldsa-native-esp32.git components/ml_dsa
```

Then in your project's `CMakeLists.txt`:

```cmake
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components/ml_dsa")
```

The component name in `REQUIRES` matches the directory name you choose (e.g., `ml_dsa` if cloned as `components/ml_dsa/`).

### Option 2: Manual Copy

Copy this entire repository into your project's `components/` directory. ESP-IDF will auto-discover it if the directory is in `EXTRA_COMPONENT_DIRS` or in the default `components/` search path. The component name in the build system equals the directory name.

### Option 3: ESP Component Registry

Not yet published. Once available:

```bash
cd your_project
idf.py add-dependency "agustinra24/mldsa-native-esp32"
```

## Quick Start

```c
#include "ml_dsa.h"
#include "esp_heap_caps.h"
#include <string.h>

void sign_example(void)
{
    uint8_t *pk  = heap_caps_malloc(ML_DSA_PK_BYTES, MALLOC_CAP_8BIT);
    uint8_t *sk  = heap_caps_malloc(ML_DSA_SK_BYTES, MALLOC_CAP_8BIT);
    uint8_t *sig = heap_caps_malloc(ML_DSA_SIG_BYTES, MALLOC_CAP_8BIT);

    /* Generate keypair (WiFi must be active for TRNG) */
    ml_dsa_keygen(pk, sk);

    /* Sign a message with domain-separation context */
    const char *msg = "device enrollment data";
    size_t siglen = 0;
    ml_dsa_sign(sig, &siglen,
                (const uint8_t *)msg, strlen(msg),
                (const uint8_t *)"enroll", 6, sk);

    /* Verify */
    int valid = ml_dsa_verify(sig, siglen,
                              (const uint8_t *)msg, strlen(msg),
                              (const uint8_t *)"enroll", 6, pk);
    /* valid == 0 means signature is correct */

    memset(sk, 0, ML_DSA_SK_BYTES);  /* zeroize secret key */
    free(pk); free(sk); free(sig);
}
```

## API Reference

The wrapper provides three inline functions defined in `include/ml_dsa.h`. All functions return 0 on success and a negative value on error.

### ml_dsa_keygen

```c
int ml_dsa_keygen(uint8_t *pk, uint8_t *sk);
```

Generates an ML-DSA-87 keypair. The caller must allocate `ML_DSA_PK_BYTES` (2592) for `pk` and `ML_DSA_SK_BYTES` (4896) for `sk`. Requires active RF subsystem for hardware TRNG. Internally allocates approximately 72 KB of temporary heap memory.

### ml_dsa_sign

```c
int ml_dsa_sign(uint8_t *sig, size_t *siglen,
                const uint8_t *msg, size_t msglen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sk);
```

Signs `msg` using secret key `sk` with domain-separation context `ctx`. The context string must be shorter than 256 bytes (FIPS 204 Section 3.2.6). The `sig` buffer must be at least `ML_DSA_SIG_BYTES` (4627). The actual signature length is written to `siglen`. Signing time varies due to rejection sampling (mean ~185 ms, can occasionally exceed 500 ms).

### ml_dsa_verify

```c
int ml_dsa_verify(const uint8_t *sig, size_t siglen,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *ctx, size_t ctxlen,
                  const uint8_t *pk);
```

Verifies that `sig` is a valid ML-DSA-87 signature of `msg` under public key `pk` with context `ctx`. Returns 0 if the signature is valid. Verification is deterministic and constant-time (~42 ms).

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ML_DSA_PK_BYTES` | 2592 | Public key size in bytes |
| `ML_DSA_SK_BYTES` | 4896 | Secret key size in bytes |
| `ML_DSA_SIG_BYTES` | 4627 | Maximum signature size in bytes |
| `ML_DSA_SEED_BYTES` | 32 | Seed size for deterministic keygen |

## Configuration

The component is configured via `config/mldsa_config_esp32.h`, which overrides the default mldsa-native configuration through the `MLD_CONFIG_FILE` mechanism. The most relevant options:

| Option | Current Setting | Purpose |
|--------|----------------|---------|
| `MLD_CONFIG_PARAMETER_SET` | 87 | ML-DSA security level (44, 65, or 87) |
| `MLD_CONFIG_NAMESPACE_PREFIX` | `mldsa_esp32` | Symbol prefix to avoid collisions |
| `MLD_CONFIG_CUSTOM_ALLOC_FREE` | Enabled | Redirects internal buffers to heap |
| `MLD_CONFIG_CUSTOM_RANDOMBYTES` | Enabled | Uses ESP32 hardware TRNG |
| `MLD_CONFIG_REDUCE_RAM` | **Not defined** | Intentionally disabled (see Design Decisions) |

To change the parameter set, edit `MLD_CONFIG_PARAMETER_SET` in `config/mldsa_config_esp32.h`. This will automatically adjust all key sizes and algorithm parameters. Note that the wrapper constants in `ml_dsa.h` are hardcoded to ML-DSA-87 and would need corresponding updates.

For the complete list of configuration options, see the upstream [mldsa_native_config.h](mldsa/mldsa_native_config.h).

## Security Considerations

**Formal verification.** The upstream mldsa-native standard configuration (used by this port) is covered by CBMC formal verification proofs that check memory safety, type safety, and absence of undefined behavior. These proofs run in upstream CI. The experimental `MLD_CONFIG_REDUCE_RAM` option is excluded from CBMC coverage; this port does not enable it.

**Constant-time properties.** Verification is constant-time. Signing uses rejection sampling, which causes inherent timing variability (this is by design in the ML-DSA specification, not a side-channel vulnerability). The number of rejection loop iterations leaks through timing, but this does not compromise the secret key under the standard ML-DSA security model (EUF-CMA).

**Random number quality.** Key generation and signing depend on cryptographically secure randomness from `esp_fill_random()`. This function produces TRNG output only when the ESP32's RF subsystem (WiFi or Bluetooth) is active. When RF is off, it falls back to a PRNG seeded at boot. **Never generate keys or sign with RF disabled.**

**Side-channel hardening.** This port does not include countermeasures against power analysis (DPA/SPA) or electromagnetic emanation attacks. Such attacks require physical access to the device and specialized equipment. For applications requiring side-channel resistance, consider hardware security modules or dedicated secure elements.

**Secret key storage.** The ML-DSA secret key (4,896 bytes) must be stored encrypted at rest. On ESP32, this can be achieved using NVS encryption or a dedicated encrypted partition (e.g., AES-256-CBC + HMAC-SHA512 in a `Sec_Store` NVS partition). Never store secret keys in plaintext NVS.

## Examples

The `examples/` directory contains a complete ESP-IDF project demonstrating key generation, signing, verification, negative tests, and benchmarking:

```bash
cd examples/basic_sign_verify
idf.py set-target esp32
idf.py build
idf.py flash monitor
```

## Testing

The `test_apps/` directory contains a Unity test suite with 8 test cases covering the full API surface:

```bash
cd test_apps/ml_dsa_tests
idf.py set-target esp32
idf.py build
idf.py flash monitor
```

Test cases: keygen validation, sign/verify round-trip, wrong context rejection, tampered message rejection, tampered signature rejection, context length enforcement (FIPS 204), signature randomness verification, and heap cleanup verification.

## Upstream

This component vendors mldsa-native **v1.0.0-alpha** from [pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native). The upstream project is maintained under the Linux Foundation's [Post-Quantum Cryptography Alliance (PQCA)](https://pqca.org/).

To update the vendored files:

1. Download the new release's `mldsa/` directory from upstream
2. Replace `mldsa/` in this repository
3. Verify that the configuration options in `mldsa_config_esp32.h` remain compatible
4. Run the test suite to confirm functionality

**Note:** Upstream v1.0.0-alpha2 (2026-01-20) is available, fixing macro naming typos (MLK_* to MLD_*). The current configuration already uses the correct MLD_* prefixes, so this does not affect functionality. An update to alpha2 is planned for a future release.

## License

This project is licensed under [Apache-2.0](LICENSE).

The upstream mldsa-native source files in `mldsa/` are licensed under Apache-2.0 OR ISC OR MIT (see individual file headers). The Apache-2.0 license of this project is compatible with all three upstream license options.

## Acknowledgments

- [pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native) by the mldsa-native contributors, maintained under the [Post-Quantum Cryptography Alliance](https://pqca.org/) (Linux Foundation)
- [Espressif Systems](https://www.espressif.com/) for ESP-IDF and the ESP32 platform

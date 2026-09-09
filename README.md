
Noise-C Library
===============

**Note**: This is a port of the [noise-c](https://github.com/rweather/noise-c) library to build on microcontroller targets. It ships build support for [PlatformIO](https://platformio.org/), [ESP-IDF](https://github.com/espressif/esp-idf), and plain [CMake](https://cmake.org/), so it can be consumed by any microcontroller (or host) project that builds with CMake, not just ESP8266/ESP32.

Noise-C is a plain C implementation of the
[Noise Protocol](http://noiseprotocol.org), intended as a
reference implementation.  It can also be referred to as "Noisy",
which is what you get when you say "Noise-C" too fast.  The code is
distributed under the terms of the MIT license.

The [documentation](http://rweather.github.io/noise-c/index.html)
contains more information on the library, examples, and how to build it.

Using it in a CMake project
---------------------------

The top-level `CMakeLists.txt` detects which build it is running under:

* Under ESP-IDF (`ESP_PLATFORM` set) it registers itself as an IDF component,
  requiring the `esphome__libsodium` component.
* Anywhere else it defines a static library target `noise_c`, also available as
  `esphome::noise_c`, with `include/` and `src/` on its public include path.

So any CMake-based project - a vendor SDK, a bare-metal cross-compile toolchain,
Zephyr, or a host build for tests - can pull it in with `add_subdirectory()` (or
`FetchContent`) and link the target:

```cmake
add_subdirectory(third_party/noise-c)
target_link_libraries(my_app PRIVATE esphome::noise_c)
```

The crypto backend is a compile-time choice made through the `NOISE_USE_*`
macros in `include/noise/defines.h`. The default backend is libsodium; if your
project already defines a `sodium` target before `add_subdirectory()`, the
generic build links against it automatically. Otherwise select the reference
backend, or configure with `-DNOISE_C_FIND_LIBSODIUM=ON` to find a system
libsodium with pkg-config.

Minimum CMake version for the generic target is 3.13; fetching the libsodium
fork for the tests needs 3.14.

Configuring with `-DNOISE_C_BUILD_TESTS=ON` also builds the unit and vector
tests; `ctest` runs them. They link against ESPHome's libsodium fork, fetched
from GitHub at the version `idf_component.yml` pins with its patches applied,
so the tests exercise the same sources the published packages ship. Add
`-DNOISE_C_FIND_LIBSODIUM=ON` to test against a system libsodium instead. The
unit tests cover
the algorithms this fork ships. The vector runner skips a vector naming an
algorithm the build leaves out and reports how many it skipped.

Size switches for microcontroller builds
----------------------------------------

Three macros in `include/noise/defines.h` trade features for flash and RAM.
All three are on by default, so a build that says nothing gets the library it
always had; define one as 0 to leave that feature out. ESPHome turns all three
off, since it builds its handshake from algorithm ids and never names one.

* `NOISE_USE_PROTOCOL_NAME_TABLE` keeps the tables that turn algorithm names
  into ids and back. With it off, `noise_protocol_name_to_id` and
  `noise_protocol_id_to_name` handle only `Noise_NNpsk0_25519_ChaChaPoly_SHA256`
  and answer `NOISE_ERROR_UNKNOWN_ID` or `NOISE_ERROR_UNKNOWN_NAME` for
  anything else. The rest of the name API stays, and a link with
  `-ffunction-sections -fdata-sections -Wl,--gc-sections`, which the ESP-IDF and
  Arduino builds pass, drops the tables along with whatever no longer reaches
  them. Turning the tables off pins the build to that one protocol, pattern
  included: the switches for AES, SHA512, the two BLAKE2 hashes, Curve448 and
  NewHope must stay off, the ones for SHA256, ChaCha20-Poly1305 and Curve25519
  must stay on, and `NOISE_USE_FALLBACK` must be off as well, since fallback
  needs the XX patterns named. The build stops with an `#error` if any of them
  says otherwise. `noise_handshakestate_new_by_id` likewise accepts only
  `NNpsk0` in that build.
* `NOISE_USE_FALLBACK` and `NOISE_USE_HFS` keep the "fallback" and "hfs" pattern
  modifiers. With them off, a pattern that asks for one is rejected with
  `NOISE_ERROR_UNKNOWN_NAME`, and `noise_handshakestate_fallback` and
  `noise_handshakestate_fallback_to` return `NOISE_ERROR_NOT_APPLICABLE`.

Hashing through the platform's mbedTLS
--------------------------------------

`NOISE_USE_MBEDTLS_SHA256`, off by default, replaces the libsodium backend's
SHA256 with the platform's mbedTLS, through `mbedtls_sha256_*` where that API
is public and through PSA on mbedTLS 4, where it is not. Where mbedTLS is
already in the image that drops the second SHA256 copy from flash. Whether it
is worth turning on depends on how the platform hashes: through PSA, as on
ESP-IDF 6, nothing new is linked and the saving is free; through the ESP32 SHA
peripheral driver on ESP-IDF 5 every hash takes and releases the engine, and a
handshake is many short hashes, so it is slower than software. In the generic
CMake build `-DNOISE_C_MBEDTLS_SHA256=ON` turns it on and links the system
`mbedcrypto`; adding `-DNOISE_SHA256_VIA_PSA` to the C flags forces the PSA
path on an mbedTLS that still has the public API, which is how CI covers it.

This fork is maintained by the [ESPHome](https://esphome.io) project. To report
bugs, contribute, or suggest improvements to it, please open an issue or pull
request on [esphome-libs/noise-c](https://github.com/esphome-libs/noise-c/issues).

The original library was written by Rhys Weatherley; questions about upstream
Noise-C itself belong on [rweather/noise-c](https://github.com/rweather/noise-c).

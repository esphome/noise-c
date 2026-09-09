
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

Minimum CMake version for the generic target is 3.13; building the tests
needs 3.14.

Configuring with `-DNOISE_C_BUILD_TESTS=ON` also builds the unit and vector
tests; `ctest` runs them. They link against ESPHome's libsodium fork, fetched
from GitHub at the version `idf_component.yml` pins with its patches applied,
so the tests exercise the same sources the published packages ship. Add
`-DNOISE_C_FIND_LIBSODIUM=ON` to test against a system libsodium instead. The
unit tests cover
the algorithms this fork ships. The vector runner skips a vector naming an
algorithm the build leaves out and reports how many it skipped.

This fork is maintained by the [ESPHome](https://esphome.io) project. To report
bugs, contribute, or suggest improvements to it, please open an issue or pull
request on [esphome-libs/noise-c](https://github.com/esphome-libs/noise-c/issues).

The original library was written by Rhys Weatherley; questions about upstream
Noise-C itself belong on [rweather/noise-c](https://github.com/rweather/noise-c).

set(NOISE_C_SRCS
  "src/backend/openssl/cipher-aesgcm.c"
  "src/backend/ref/cipher-aesgcm.c"
  "src/backend/ref/cipher-chachapoly.c"
  "src/backend/ref/dh-curve25519.c"
  "src/backend/ref/hash-blake2b.c"
  "src/backend/ref/hash-blake2s.c"
  "src/backend/ref/hash-sha256.c"
  "src/backend/sodium/cipher-aesgcm.c"
  "src/backend/sodium/cipher-chachapoly.c"
  "src/backend/sodium/dh-curve25519.c"
  "src/backend/sodium/hash-blake2b.c"
  "src/backend/sodium/hash-sha256.c"
  "src/crypto/aes/rijndael-alg-fst.c"
  "src/crypto/blake2/blake2b.c"
  "src/crypto/blake2/blake2s.c"
  "src/crypto/chacha/chacha.c"
  "src/crypto/donna/curve25519-donna-c64.c"
  "src/crypto/donna/curve25519-donna.c"
  "src/crypto/donna/poly1305-donna.c"
  "src/crypto/sha2/sha256.c"
  "src/crypto/sha2/sha512.c"
  "src/crypto/x25519/x25519.c"
  "src/protocol/cipherstate.c"
  "src/protocol/dhstate.c"
  "src/protocol/errors.c"
  "src/protocol/handshakestate.c"
  "src/protocol/hashstate.c"
  "src/protocol/internal.c"
  "src/protocol/names.c"
  "src/protocol/patterns.c"
  "src/protocol/rand_os.c"
  "src/protocol/rand_sodium.c"
  "src/protocol/randstate.c"
  "src/protocol/signstate.c"
  "src/protocol/symmetricstate.c"
  "src/protocol/util.c"
)

if(ESP_PLATFORM)
  idf_component_register(
    SRCS ${NOISE_C_SRCS}
    INCLUDE_DIRS "include" "src"
    REQUIRES esphome__libsodium
  )
else()
  cmake_minimum_required(VERSION 3.13)
  project(noise_c C)

  option(NOISE_C_BUILD_TESTS "Build the unit and vector tests" OFF)
  option(NOISE_C_FIND_LIBSODIUM
    "Find libsodium with pkg-config for the default backend" ${NOISE_C_BUILD_TESTS})

  if(NOISE_C_FIND_LIBSODIUM AND NOT TARGET sodium)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)
    add_library(sodium INTERFACE IMPORTED GLOBAL)
    target_link_libraries(sodium INTERFACE PkgConfig::LIBSODIUM)
  endif()

  add_library(noise_c STATIC ${NOISE_C_SRCS})
  add_library(esphome::noise_c ALIAS noise_c)

  target_include_directories(noise_c PUBLIC
    "${CMAKE_CURRENT_LIST_DIR}/include"
    "${CMAKE_CURRENT_LIST_DIR}/src"
  )

  # backend is a compile-time choice made by the consumer via the NOISE_USE_*
  # macros in include/noise/defines.h; the default backend is libsodium, so
  # link a libsodium target if the consumer has already defined one.
  if(TARGET sodium)
    target_link_libraries(noise_c PUBLIC sodium)
  endif()

  if(NOISE_C_BUILD_TESTS)
    enable_testing()
    add_executable(noise-c-test-unit
      "tests/unit/test-cipherstate.c"
      "tests/unit/test-dhstate.c"
      "tests/unit/test-errors.c"
      "tests/unit/test-handshakestate.c"
      "tests/unit/test-hashstate.c"
      "tests/unit/test-main.c"
      "tests/unit/test-names.c"
      "tests/unit/test-patterns.c"
      "tests/unit/test-randstate.c"
      "tests/unit/test-symmetricstate.c"
      "tests/rand-sodium.c"
    )
    target_link_libraries(noise-c-test-unit PRIVATE noise_c)
    target_compile_options(noise-c-test-unit PRIVATE
      $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-Wall>)
    add_test(NAME unit COMMAND noise-c-test-unit)

    add_executable(noise-c-test-vector
      "tests/vector/test-vector.c"
      "tests/vector/json-reader.c"
      "tests/rand-sodium.c"
    )
    target_link_libraries(noise-c-test-vector PRIVATE noise_c)
    target_compile_options(noise-c-test-vector PRIVATE
      $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-Wall>)
    add_test(NAME vectors
      COMMAND noise-c-test-vector
        "${CMAKE_CURRENT_LIST_DIR}/tests/vector/cacophony.txt"
        "${CMAKE_CURRENT_LIST_DIR}/tests/vector/noise-c-basic.txt")
  endif()
endif()

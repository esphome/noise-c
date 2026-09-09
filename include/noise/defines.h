#pragma once

#ifndef NOISE_USE_AES
#define NOISE_USE_AES 0
#endif

#ifndef NOISE_USE_CURVE25519
#define NOISE_USE_CURVE25519 1
#endif

#ifndef NOISE_USE_CURVE448
#define NOISE_USE_CURVE448 0
#endif

#ifndef NOISE_USE_NEWHOPE
#define NOISE_USE_NEWHOPE 0
#endif

#ifndef NOISE_USE_BLAKE2B
#define NOISE_USE_BLAKE2B 0
#endif

#ifndef NOISE_USE_BLAKE2S
#define NOISE_USE_BLAKE2S 0
#endif

#ifndef NOISE_USE_CHACHAPOLY
#define NOISE_USE_CHACHAPOLY 1
#endif

#ifndef NOISE_USE_POLY1305
#define NOISE_USE_POLY1305 1
#endif

#ifndef NOISE_USE_SHA256
#define NOISE_USE_SHA256 1
#endif

#ifndef NOISE_USE_SHA512
#define NOISE_USE_SHA512 0
#endif

#ifndef NOISE_USE_ED25519
#define NOISE_USE_ED25519 0
#endif

#ifndef NOISE_USE_SIGN
#define NOISE_USE_SIGN 0
#endif

#ifndef NOISE_USE_REFERENCE_BACKEND
#define NOISE_USE_REFERENCE_BACKEND 0
#endif
#ifndef NOISE_USE_LIBSODIUM
#define NOISE_USE_LIBSODIUM 1
#endif
#ifndef NOISE_USE_OPENSSL
#define NOISE_USE_OPENSSL 0
#endif

#ifndef NOISE_USE_CUSTOM_RAND
#define NOISE_USE_CUSTOM_RAND 1
#endif

/* Where noise_rand_bytes() comes from when it is not custom: libsodium's
   generator with that backend, otherwise the operating system */
#ifndef NOISE_USE_SODIUM_RAND
#define NOISE_USE_SODIUM_RAND (NOISE_USE_LIBSODIUM && !NOISE_USE_CUSTOM_RAND)
#endif

/* Three switches for builds that want the library smaller, all on by default
   so nothing changes unless the build asks. ESPHome turns them off. */

/* Format protocol names from the id tables. Off, noise_protocol_id_to_name
   knows the one protocol ESPHome speaks and the tables are left out, which
   pins the build to that one set of algorithms. */
#ifndef NOISE_USE_PROTOCOL_NAME_TABLE
#define NOISE_USE_PROTOCOL_NAME_TABLE 1
#endif

/* The "fallback" and "hfs" pattern modifiers, which ESPHome never asks for */
#ifndef NOISE_USE_FALLBACK
#define NOISE_USE_FALLBACK 1
#endif
#ifndef NOISE_USE_HFS
#define NOISE_USE_HFS 1
#endif

/* Hash through the platform's mbedTLS rather than the selected backend's own
   SHA256, which saves the flash that copy takes where mbedTLS is already in
   the image; the build that asks for it supplies the mbedTLS link. Whether it
   pays depends on how the platform hashes. Through PSA, which is where
   mbedTLS 4 puts it, nothing new is linked and the flash is free. Through the
   ESP32 SHA peripheral driver every hash takes and releases the engine, and a
   handshake is many short hashes, so it costs more time than the hardware
   saves. Creating the hash state can fail, with PSA not initialising for
   instance, and that is returned as NOISE_ERROR_NO_MEMORY. A hash the
   platform refuses once the state exists, which takes the platform running
   out of memory, is reported as a zero digest for that hash; the layers
   above then produce a wrong result rather than an error, so a handshake
   fails on the peer's MAC and noise_hashstate_pbkdf2 hands back a wrong
   key. */
#ifndef NOISE_USE_MBEDTLS_SHA256
#define NOISE_USE_MBEDTLS_SHA256 0
#endif
/* Which backend provides the SHA256 hash state: mbedTLS when asked for,
   otherwise libsodium with that backend */
#ifndef NOISE_USE_MBEDTLS_SHA256_STATE
#define NOISE_USE_MBEDTLS_SHA256_STATE (NOISE_USE_MBEDTLS_SHA256 && NOISE_USE_SHA256)
#endif
#ifndef NOISE_USE_SODIUM_SHA256_STATE
#define NOISE_USE_SODIUM_SHA256_STATE \
    (NOISE_USE_LIBSODIUM && NOISE_USE_SHA256 && !NOISE_USE_MBEDTLS_SHA256)
#endif
#if NOISE_USE_REFERENCE_BACKEND

#ifndef NOISE_USE_REFERENCE_CHACHA
#define NOISE_USE_REFERENCE_CHACHA NOISE_USE_CHACHAPOLY
#endif

#ifndef NOISE_USE_REFERENCE_POLY1305
#define NOISE_USE_REFERENCE_POLY1305 NOISE_USE_CHACHAPOLY
#endif

#ifndef NOISE_USE_REFERENCE_SHA256
#define NOISE_USE_REFERENCE_SHA256 NOISE_USE_SHA256
#endif
/* The reference SHA256 is its own copy that the mbedTLS switch cannot
   replace, so the two together would add a copy rather than drop one */
#if NOISE_USE_MBEDTLS_SHA256 && NOISE_USE_REFERENCE_SHA256
#error "NOISE_USE_MBEDTLS_SHA256 replaces a backend's SHA256; turn NOISE_USE_REFERENCE_SHA256 off"
#endif

#ifndef NOISE_USE_REFERENCE_DONNA_CURVE25519
#define NOISE_USE_REFERENCE_DONNA_CURVE25519 0
#endif

#ifndef NOISE_USE_REFERENCE_STROBE_CURVE25519
#define NOISE_USE_REFERENCE_STROBE_CURVE25519 1-NOISE_USE_REFERENCE_DONNA_CURVE25519
#endif

#ifndef NOISE_USE_REFERENCE_BLAKE2B
#define NOISE_USE_REFERENCE_BLAKE2B NOISE_USE_BLAKE2B
#endif

#ifndef NOISE_USE_REFERENCE_BLAKE2S
#define NOISE_USE_REFERENCE_BLAKE2S NOISE_USE_BLAKE2S
#endif

#ifndef NOISE_USE_PTHREAD
#define NOISE_USE_PTHREAD 0
#endif

#endif  // NOISE_USE_REFERENCE_BACKEND


/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* SHA256 through the platform's mbedTLS; see NOISE_USE_MBEDTLS_SHA256 */

#include "noise/defines.h"
#if NOISE_USE_MBEDTLS_SHA256_STATE
#include "protocol/internal.h"
#include <string.h>

/* mbedTLS 4, which arrives with ESP-IDF 6, made the sha256 API private, so
   the hash is reached through PSA there. Everything below is written against
   one small shim so the hash functions themselves carry no version tests.
   The nesting is deliberate: #if parses both sides of an &&, so a compiler
   without __has_include cannot be spared by putting defined() in front. */
#ifdef __has_include
#if !__has_include(<mbedtls/sha256.h>)
#if !__has_include(<psa/crypto.h>)
#error "NOISE_USE_MBEDTLS_SHA256 needs mbedTLS on the include path"
#endif
#ifndef NOISE_SHA256_VIA_PSA
#define NOISE_SHA256_VIA_PSA
#endif
#endif
#elif !defined(NOISE_SHA256_VIA_PSA)
/* Without __has_include, go by the version: 4 made the sha256 API private */
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
#define NOISE_SHA256_VIA_PSA
#endif
#endif

#ifdef NOISE_SHA256_VIA_PSA

#include <psa/crypto.h>
#if !defined(PSA_WANT_ALG_SHA_256)
#error "NOISE_USE_MBEDTLS_SHA256 needs a PSA crypto built with SHA256"
#endif
typedef psa_hash_operation_t noise_sha256_ctx;

static void noise_sha256_ctx_init(noise_sha256_ctx *ctx)
{
    *ctx = psa_hash_operation_init();
}

static int noise_sha256_ctx_start(noise_sha256_ctx *ctx)
{
    psa_hash_abort(ctx);
    return psa_hash_setup(ctx, PSA_ALG_SHA_256) != PSA_SUCCESS;
}

static int noise_sha256_ctx_update
    (noise_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    return psa_hash_update(ctx, data, len) != PSA_SUCCESS;
}

static int noise_sha256_ctx_finish(noise_sha256_ctx *ctx, uint8_t *hash)
{
    size_t hash_len = 0;
    if (psa_hash_finish(ctx, hash, PSA_HASH_LENGTH(PSA_ALG_SHA_256),
                        &hash_len) != PSA_SUCCESS)
        return 1;
    /* A digest of any other length is not the one asked for */
    return hash_len != PSA_HASH_LENGTH(PSA_ALG_SHA_256);
}

static void noise_sha256_ctx_free(noise_sha256_ctx *ctx)
{
    psa_hash_abort(ctx);
}

#else

#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#if !defined(MBEDTLS_SHA256_C)
#error "NOISE_USE_MBEDTLS_SHA256 needs an mbedTLS built with SHA256, or NOISE_SHA256_VIA_PSA to hash through PSA"
#endif
typedef mbedtls_sha256_context noise_sha256_ctx;

/* 2.7 renamed the three calls to _ret when they gained a return value, and
   3.0 gave the plain names back; before 2.7 they could not fail */
#if MBEDTLS_VERSION_NUMBER >= 0x02070000 && MBEDTLS_VERSION_NUMBER < 0x03000000
#define mbedtls_sha256_starts mbedtls_sha256_starts_ret
#define mbedtls_sha256_update mbedtls_sha256_update_ret
#define mbedtls_sha256_finish mbedtls_sha256_finish_ret
#endif
#if MBEDTLS_VERSION_NUMBER < 0x02070000
#define NOISE_SHA256_CALL(expr) ((expr), 0)
#else
#define NOISE_SHA256_CALL(expr) (expr)
#endif

static void noise_sha256_ctx_init(noise_sha256_ctx *ctx)
{
    mbedtls_sha256_init(ctx);
}

static int noise_sha256_ctx_start(noise_sha256_ctx *ctx)
{
    /* Drop whatever an abandoned hash left behind, as the PSA path does;
       on ESP-IDF with the SHA peripheral that also releases the engine */
    mbedtls_sha256_free(ctx);
    mbedtls_sha256_init(ctx);
    return NOISE_SHA256_CALL(mbedtls_sha256_starts(ctx, 0)) != 0;
}

static int noise_sha256_ctx_update
    (noise_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    return NOISE_SHA256_CALL(mbedtls_sha256_update(ctx, data, len)) != 0;
}

static int noise_sha256_ctx_finish(noise_sha256_ctx *ctx, uint8_t *hash)
{
    return NOISE_SHA256_CALL(mbedtls_sha256_finish(ctx, hash)) != 0;
}

static void noise_sha256_ctx_free(noise_sha256_ctx *ctx)
{
    mbedtls_sha256_free(ctx);
}

#endif

typedef struct
{
    struct NoiseHashState_s parent;
    noise_sha256_ctx sha256;
    /* The hash interface cannot report a failure, so a failed step is
       remembered here and finalize writes random bytes rather than leaving
       key material unset; random rather than zero, so two peers refused the
       same way cannot agree on a digest. Reset clears it, so an HMAC whose
       inner hash failed still finishes with a digest, just a wrong one; the
       handshake then fails on the peer's MAC and pbkdf2 hands back a wrong
       key. */
    int failed;

} NoiseSHA256State;

static void noise_sha256_reset(NoiseHashState *state)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    st->failed = noise_sha256_ctx_start(&(st->sha256));
}

static void noise_sha256_update(NoiseHashState *state, const uint8_t *data, size_t len)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    if (noise_sha256_ctx_update(&(st->sha256), data, len))
        st->failed = 1;
}

static void noise_sha256_finalize(NoiseHashState *state, uint8_t *hash)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    if (noise_sha256_ctx_finish(&(st->sha256), hash))
        st->failed = 1;
    if (st->failed)
        noise_rand_bytes(hash, state->hash_len);
}

static void noise_sha256_destroy(NoiseHashState *state)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    /* Not just zeroing, which noise_free already does: this releases the
       driver operation, or the ESP32 SHA engine lock, for an abandoned hash */
    noise_sha256_ctx_free(&(st->sha256));
}

NoiseHashState *noise_sha256_new(void)
{
    NoiseSHA256State *state;
#ifdef NOISE_SHA256_VIA_PSA
    /* Idempotent, and the application may not have done it yet */
    if (psa_crypto_init() != PSA_SUCCESS)
        return 0;
#endif
    state = noise_new(NoiseSHA256State);
    if (!state)
        return 0;
    noise_sha256_ctx_init(&(state->sha256));
    state->parent.hash_id = NOISE_HASH_SHA256;
    state->parent.hash_len = 32;
    state->parent.block_len = 64;
    state->parent.reset = noise_sha256_reset;
    state->parent.update = noise_sha256_update;
    state->parent.finalize = noise_sha256_finalize;
    state->parent.destroy = noise_sha256_destroy;
    return &(state->parent);
}

#endif  // NOISE_USE_MBEDTLS_SHA256_STATE

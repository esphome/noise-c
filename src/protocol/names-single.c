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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* The protocol name functions for a build with the name tables switched off;
   the tables and everything that walks them live in names.c. */

#include "protocol/internal.h"
#include <string.h>

#if !NOISE_USE_PROTOCOL_NAME_TABLE

/* On the ESP8266 read only data sits in DRAM unless it is asked to live in
   flash, so the name is kept there and read through the pgmspace helpers.
   Everywhere else those are plain memcpy and memcmp. */
#if (defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)) && \
    defined(__has_include) && __has_include(<pgmspace.h>)
#include <pgmspace.h>
#define NOISE_NAME_IN_FLASH PROGMEM
#define noise_name_copy(dst, src, len) memcpy_P((dst), (src), (len))
#define noise_name_cmp(str, name, len) memcmp_P((str), (name), (len))
#else
#define NOISE_NAME_IN_FLASH
#define noise_name_copy(dst, src, len) memcpy((dst), (src), (len))
#define noise_name_cmp(str, name, len) memcmp((str), (name), (len))
#endif

/* ESPHome speaks exactly one protocol, so its name is a constant. A shared
   const NoiseProtocolId to compare against would cost more DRAM on the
   ESP8266 than the field by field checks below cost in flash.

   These answer as the table versions do for every id this build can name. An
   id it cannot name, handed a buffer too small to hold any name, reports the
   length rather than the id; the table version reports whichever it meets
   first as it formats. Both fail, and both clear the buffer. */
static const char noise_single_protocol_name[] NOISE_NAME_IN_FLASH =
    "Noise_NNpsk0_25519_ChaChaPoly_SHA256";

int noise_protocol_name_to_id
    (NoiseProtocolId *id, const char *name, size_t name_len)
{
    if (!id || !name)
        return NOISE_ERROR_INVALID_PARAM;
    memset(id, 0, sizeof(NoiseProtocolId));
    if (name_len != sizeof(noise_single_protocol_name) - 1 ||
            noise_name_cmp(name, noise_single_protocol_name, name_len) != 0)
        return NOISE_ERROR_UNKNOWN_NAME;
    id->prefix_id = NOISE_PREFIX_STANDARD;
    id->pattern_id = NOISE_PATTERN_NN;
    id->modifier_ids[0] = NOISE_MODIFIER_PSK0;
    id->dh_id = NOISE_DH_CURVE25519;
    id->cipher_id = NOISE_CIPHER_CHACHAPOLY;
    id->hash_id = NOISE_HASH_SHA256;
    return NOISE_ERROR_NONE;
}

int noise_protocol_id_to_name
    (char *name, size_t name_len, const NoiseProtocolId *id)
{
    size_t slot;

    if (!id) {
        if (name && name_len)
            *name = '\0';
        return NOISE_ERROR_INVALID_PARAM;
    }
    if (!name)
        return NOISE_ERROR_INVALID_PARAM;
    if (name_len < sizeof(noise_single_protocol_name)) {
        if (name_len)
            *name = '\0';
        return NOISE_ERROR_INVALID_LENGTH;
    }
    if (id->prefix_id != NOISE_PREFIX_STANDARD ||
            id->pattern_id != NOISE_PATTERN_NN ||
            id->modifier_ids[0] != NOISE_MODIFIER_PSK0 ||
            id->dh_id != NOISE_DH_CURVE25519 ||
            id->cipher_id != NOISE_CIPHER_CHACHAPOLY ||
            id->hash_id != NOISE_HASH_SHA256 ||
            id->hybrid_id != NOISE_DH_NONE) {
        *name = '\0';
        return NOISE_ERROR_UNKNOWN_ID;
    }
    /* psk0 is the only modifier; every other slot must be empty */
    for (slot = 1; slot < NOISE_MAX_MODIFIER_IDS; ++slot) {
        if (id->modifier_ids[slot] != NOISE_MODIFIER_NONE) {
            *name = '\0';
            return NOISE_ERROR_UNKNOWN_ID;
        }
    }
    for (slot = 0; slot < sizeof(id->reserved) / sizeof(id->reserved[0]); ++slot) {
        if (id->reserved[slot]) {
            *name = '\0';
            return NOISE_ERROR_UNKNOWN_ID;
        }
    }
    noise_name_copy(name, noise_single_protocol_name,
                    sizeof(noise_single_protocol_name));
    return NOISE_ERROR_NONE;
}

#endif /* !NOISE_USE_PROTOCOL_NAME_TABLE */

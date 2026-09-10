/*
 * Copyright (C) 2026 ESPHome
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

/* Without the name tables a build can use exactly one pattern, NN with
   psk0, so its expansion is a constant, which is a few hundred bytes of
   flash and DRAM less than expanding it. patterns.c keeps the base patterns
   and the modifier machinery for the tests and for builds with the tables;
   nothing here refers to them, so a link with gc-sections leaves them out.
   The configuration guard in names-single.c is what pins the build to this
   one pattern. */

#include "protocol/internal.h"

#if !NOISE_USE_PROTOCOL_NAME_TABLE

#define NOISE_NNPSK0_FLAGS \
    (NOISE_PAT_FLAG_LOCAL_EPHEMERAL | NOISE_PAT_FLAG_REMOTE_EPHEMERAL)

int noise_pattern_expand
    (uint8_t pattern[NOISE_MAX_TOKENS], int pattern_id,
     const int *modifiers, size_t num_modifiers)
{
    if (pattern_id != NOISE_PATTERN_NN || num_modifiers != 1 ||
            modifiers[0] != NOISE_MODIFIER_PSK0)
        return NOISE_ERROR_UNKNOWN_NAME;
    /* noise_pattern_expand(NN, {psk0}) as the table version produces it:
       the flag word, "psk, e", the direction flip, "e, ee", the end marker.
       Stores rather than a constant array, which the ESP8266 would keep in
       DRAM; they are also smaller than the array plus the copy. */
    pattern[0] = (uint8_t)(NOISE_NNPSK0_FLAGS & 0xFF);
    pattern[1] = (uint8_t)(NOISE_NNPSK0_FLAGS >> 8);
    pattern[2] = NOISE_TOKEN_PSK;
    pattern[3] = NOISE_TOKEN_E;
    pattern[4] = NOISE_TOKEN_FLIP_DIR;
    pattern[5] = NOISE_TOKEN_E;
    pattern[6] = NOISE_TOKEN_EE;
    pattern[7] = NOISE_TOKEN_END;
    return NOISE_ERROR_NONE;
}

#endif /* !NOISE_USE_PROTOCOL_NAME_TABLE */

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
   psk0, so its expansion is a constant. patterns.c keeps the base patterns
   and the modifier machinery for the tests; nothing here refers to them,
   so a link with gc-sections leaves them out. */

#include "protocol/internal.h"
#include <string.h>

#if !NOISE_USE_PROTOCOL_NAME_TABLE

/* noise_pattern_expand(NN, {psk0}) as the table version produces it: the
   flag word, then "psk, e", the direction flip, "e, ee" and the end marker */
#define NOISE_NNPSK0_FLAGS \
    (NOISE_PAT_FLAG_LOCAL_EPHEMERAL | NOISE_PAT_FLAG_REMOTE_EPHEMERAL)
static const uint8_t noise_pattern_NNpsk0[] = {
    (uint8_t)(NOISE_NNPSK0_FLAGS & 0xFF),
    (uint8_t)((NOISE_NNPSK0_FLAGS >> 8) & 0xFF),
    NOISE_TOKEN_PSK,
    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_END
};

int noise_pattern_expand
    (uint8_t pattern[NOISE_MAX_TOKENS], int pattern_id,
     const int *modifiers, size_t num_modifiers)
{
    if (pattern_id != NOISE_PATTERN_NN || num_modifiers != 1 ||
            modifiers[0] != NOISE_MODIFIER_PSK0)
        return NOISE_ERROR_UNKNOWN_NAME;
    memcpy(pattern, noise_pattern_NNpsk0, sizeof(noise_pattern_NNpsk0));
    return NOISE_ERROR_NONE;
}

#endif /* !NOISE_USE_PROTOCOL_NAME_TABLE */

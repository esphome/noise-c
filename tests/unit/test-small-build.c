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

#include "test-helpers.h"
#include "protocol/internal.h"

/* What the library promises once the size switches are off, which is the
   configuration every microcontroller build uses; with the switches on
   there is nothing here to check */
void test_small_build(void)
{
    static const char single[] = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
    NoiseHandshakeState *state = 0;
    NoiseProtocolId id;

#if !NOISE_USE_PROTOCOL_NAME_TABLE
    /* The one protocol still works by name and by id */
    compare(noise_handshakestate_new_by_name
                (&state, single, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_get_protocol_id(state, &id),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_free(state), NOISE_ERROR_NONE);
    compare(noise_handshakestate_new_by_id
                (&state, &id, NOISE_ROLE_RESPONDER),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_free(state), NOISE_ERROR_NONE);

    /* A state made by id starts from the constant digest, one made by name
       from hashing the name; the two must complete a handshake together */
    {
        static const uint8_t psk[32] = { 1, 2, 3 };
        NoiseHandshakeState *initiator = 0;
        NoiseHandshakeState *responder = 0;
        uint8_t message[128];
        uint8_t hash_i[32];
        uint8_t hash_r[32];
        NoiseBuffer buffer;
        compare(noise_handshakestate_new_by_name
                    (&initiator, single, NOISE_ROLE_INITIATOR),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_new_by_id
                    (&responder, &id, NOISE_ROLE_RESPONDER),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_set_pre_shared_key(initiator, psk, 32),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_set_pre_shared_key(responder, psk, 32),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_start(initiator), NOISE_ERROR_NONE);
        compare(noise_handshakestate_start(responder), NOISE_ERROR_NONE);
        noise_buffer_set_output(buffer, message, sizeof(message));
        compare(noise_handshakestate_write_message(initiator, &buffer, 0),
                NOISE_ERROR_NONE);
        noise_buffer_set_input(buffer, message, buffer.size);
        compare(noise_handshakestate_read_message(responder, &buffer, 0),
                NOISE_ERROR_NONE);
        noise_buffer_set_output(buffer, message, sizeof(message));
        compare(noise_handshakestate_write_message(responder, &buffer, 0),
                NOISE_ERROR_NONE);
        noise_buffer_set_input(buffer, message, buffer.size);
        compare(noise_handshakestate_read_message(initiator, &buffer, 0),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_get_action(initiator), NOISE_ACTION_SPLIT);
        compare(noise_handshakestate_get_action(responder), NOISE_ACTION_SPLIT);
        compare(noise_handshakestate_get_handshake_hash(initiator, hash_i, 32),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_get_handshake_hash(responder, hash_r, 32),
                NOISE_ERROR_NONE);
        compare_blocks(hash_i, 32, hash_r, 32);
        compare(noise_handshakestate_free(initiator), NOISE_ERROR_NONE);
        compare(noise_handshakestate_free(responder), NOISE_ERROR_NONE);
    }

    /* Every other protocol is unknown, and the out parameter is cleared */
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_name
                (&state, "Noise_XX_25519_ChaChaPoly_SHA256",
                 NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
    id.modifier_ids[1] = NOISE_MODIFIER_PSK1;
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_id
                (&state, &id, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    id.modifier_ids[0] = NOISE_MODIFIER_PSK1;
    id.modifier_ids[1] = NOISE_MODIFIER_NONE;
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_id
                (&state, &id, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    id.modifier_ids[0] = NOISE_MODIFIER_NONE;
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_id
                (&state, &id, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    /* Those ids are refused one layer up, in names-single.c; the expander
       is what holds the modifier count to one for the constructor */
    {
        uint8_t pattern[NOISE_MAX_TOKENS];
        int mods[2] = { NOISE_MODIFIER_PSK0, NOISE_MODIFIER_PSK1 };
        compare(noise_pattern_expand(pattern, NOISE_PATTERN_NN, mods, 2),
                NOISE_ERROR_UNKNOWN_NAME);
        compare(noise_pattern_expand(pattern, NOISE_PATTERN_NN, mods, 0),
                NOISE_ERROR_UNKNOWN_NAME);
        compare(noise_pattern_expand(pattern, NOISE_PATTERN_NN, mods, 1),
                NOISE_ERROR_NONE);
    }

#if NOISE_SINGLE_PATTERN
    /* The token buffer is cut down to the one pattern, end marker included */
    {
        uint8_t pattern[NOISE_MAX_TOKENS];
        int modifier = NOISE_MODIFIER_PSK0;
        compare(noise_pattern_expand(pattern, NOISE_PATTERN_NN, &modifier, 1),
                NOISE_ERROR_NONE);
        compare(pattern[NOISE_MAX_TOKENS - 1], NOISE_TOKEN_END);
    }
#endif
    id.pattern_id = NOISE_PATTERN_XX;
    id.modifier_ids[0] = NOISE_MODIFIER_NONE;
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_id
                (&state, &id, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
#endif

#if !NOISE_USE_FALLBACK
    /* Fallback is refused rather than attempted */
    compare(noise_handshakestate_new_by_name
                (&state, single, NOISE_ROLE_RESPONDER),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_fallback(state),
            NOISE_ERROR_NOT_APPLICABLE);
    compare(noise_handshakestate_fallback_to(state, "XXfallback"),
            NOISE_ERROR_NOT_APPLICABLE);
    compare(noise_handshakestate_fallback_to(0, "XXfallback"),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_handshakestate_fallback_to(state, 0),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_handshakestate_free(state), NOISE_ERROR_NONE);
#endif

#if !NOISE_USE_HFS
    /* The hfs modifier is unknown to the pattern expander itself, not
       only to a name parser that may have no tables */
    {
        uint8_t pattern[NOISE_MAX_TOKENS];
        int modifier = NOISE_MODIFIER_HFS;
        compare(noise_pattern_expand(pattern, NOISE_PATTERN_NN, &modifier, 1),
                NOISE_ERROR_UNKNOWN_NAME);
        modifier = NOISE_MODIFIER_PSK0;
        compare(noise_pattern_expand(pattern, NOISE_PATTERN_NN, &modifier, 1),
                NOISE_ERROR_NONE);
    }
#endif

    (void)state;
    (void)id;
    (void)single;
}

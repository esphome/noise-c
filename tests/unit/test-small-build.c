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

    /* Every other protocol is unknown, and the out parameter is cleared */
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_name
                (&state, "Noise_XX_25519_ChaChaPoly_SHA256",
                 NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
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
    /* A pattern that asks for hybrid forward secrecy is unknown */
    {
        static const char hfs[] = "Noise_NNhfs_25519+NewHope_ChaChaPoly_SHA256";
        compare(noise_protocol_name_to_id(&id, hfs, strlen(hfs)),
                NOISE_ERROR_UNKNOWN_NAME);
    }
#endif

    (void)state;
    (void)id;
    (void)single;
}

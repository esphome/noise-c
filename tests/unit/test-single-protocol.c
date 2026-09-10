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

/* Builds the single protocol name functions a second time, under the names
 * below, and checks they answer exactly as the table versions do. The name
 * they return is hashed into the handshake, so the two must not drift. */

#include "test-helpers.h"
#include "protocol/internal.h"

/* The reduced implementations, built a second time under the names below,
   inside a full build its configuration guard would otherwise refuse */
#undef NOISE_USE_PROTOCOL_NAME_TABLE
#define NOISE_USE_PROTOCOL_NAME_TABLE 0
#define NOISE_NAMES_SINGLE_UNGUARDED
#define noise_protocol_id_to_name single_id_to_name
#define noise_protocol_name_to_id single_name_to_id
#define noise_pattern_expand single_pattern_expand
#include "protocol/names-single.c"
#include "protocol/patterns-single.c"
#undef noise_protocol_id_to_name
#undef noise_protocol_name_to_id
#undef noise_pattern_expand

/* On the protocol ESPHome speaks, the two must answer identically */
static void compare_id_to_name(const NoiseProtocolId *id)
{
    char table_name[NOISE_MAX_PROTOCOL_NAME];
    char single_name[NOISE_MAX_PROTOCOL_NAME];
    int table_err, single_err;

    memset(table_name, 0xAA, sizeof(table_name));
    memset(single_name, 0x55, sizeof(single_name));
    table_err = noise_protocol_id_to_name
        (table_name, sizeof(table_name), id);
    single_err = single_id_to_name(single_name, sizeof(single_name), id);
    compare(single_err, table_err);
    verify(!strcmp(single_name, table_name));
}

/* The same, with a buffer of the given length, where the exact fit and one
   short of it must be judged alike */
static void compare_id_to_name_len(const NoiseProtocolId *id, size_t len)
{
    char table_name[NOISE_MAX_PROTOCOL_NAME];
    char single_name[NOISE_MAX_PROTOCOL_NAME];
    int table_err = noise_protocol_id_to_name(table_name, len, id);
    int single_err = single_id_to_name(single_name, len, id);
    compare(single_err, table_err);
    if (table_err == NOISE_ERROR_NONE)
        verify(!strcmp(single_name, table_name));
}

static void compare_name_to_id(const char *name)
{
    NoiseProtocolId table_id;
    NoiseProtocolId single_id;
    int table_err, single_err;

    table_err = noise_protocol_name_to_id(&table_id, name, strlen(name));
    single_err = single_name_to_id(&single_id, name, strlen(name));
    compare(single_err, table_err);
    verify(!memcmp(&single_id, &table_id, sizeof(NoiseProtocolId)));
}

/* An id the table can format but this build does not support */
static void expect_unknown_id(const NoiseProtocolId *id)
{
    char name[NOISE_MAX_PROTOCOL_NAME];

    compare(single_id_to_name(name, sizeof(name), id), NOISE_ERROR_UNKNOWN_ID);
    verify(name[0] == '\0');
}

void test_single_protocol(void)
{
    NoiseProtocolId id;
    char name[NOISE_MAX_PROTOCOL_NAME];

    /* The protocol ESPHome speaks, which both versions must format the same */
    memset(&id, 0, sizeof(id));
    id.prefix_id = NOISE_PREFIX_STANDARD;
    id.pattern_id = NOISE_PATTERN_NN;
    id.modifier_ids[0] = NOISE_MODIFIER_PSK0;
    id.dh_id = NOISE_DH_CURVE25519;
    id.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    id.hash_id = NOISE_HASH_SHA256;
    compare_id_to_name(&id);
    compare(single_id_to_name(name, sizeof(name), &id), NOISE_ERROR_NONE);
    verify(!strcmp(name, "Noise_NNpsk0_25519_ChaChaPoly_SHA256"));
    compare_name_to_id("Noise_NNpsk0_25519_ChaChaPoly_SHA256");

    /* Real protocols this build does not carry, one field at a time */
    id.prefix_id = NOISE_PREFIX_NONE;
    compare_id_to_name(&id);
    id.prefix_id = NOISE_PREFIX_STANDARD;
    id.pattern_id = NOISE_PATTERN_XX;
    expect_unknown_id(&id);
    id.pattern_id = NOISE_PATTERN_NN;
    id.modifier_ids[0] = NOISE_MODIFIER_NONE;
    expect_unknown_id(&id);
    id.modifier_ids[0] = NOISE_MODIFIER_PSK0;
    for (size_t slot = 1; slot < NOISE_MAX_MODIFIER_IDS; slot++) {
        id.modifier_ids[slot] = NOISE_MODIFIER_PSK1;
        expect_unknown_id(&id);
        id.modifier_ids[slot] = NOISE_MODIFIER_NONE;
    }
    id.hybrid_id = NOISE_DH_CURVE25519;
    expect_unknown_id(&id);
    id.hybrid_id = NOISE_DH_NONE;
    for (size_t slot = 0; slot < sizeof(id.reserved) / sizeof(id.reserved[0]); slot++) {
        id.reserved[slot] = 1;
        expect_unknown_id(&id);
        id.reserved[slot] = 0;
    }

    /* Ids the table rejects too, where the error must match */
    id.hash_id = NOISE_HASH_NONE;
    compare_id_to_name(&id);
    id.hash_id = NOISE_HASH_SHA256;
    id.cipher_id = NOISE_CIPHER_NONE;
    compare_id_to_name(&id);
    id.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    id.dh_id = NOISE_DH_NONE;
    compare_id_to_name(&id);
    id.dh_id = NOISE_DH_CURVE25519;

    /* The name is 36 characters: a 37 byte buffer fits, a 36 byte one does
       not, and both versions must say so */
    compare_id_to_name_len(&id, 37);
    compare_id_to_name_len(&id, 36);

    /* Bad parameters, which both versions treat alike */
    compare_id_to_name(0);
    compare(single_id_to_name(0, sizeof(name), &id), NOISE_ERROR_INVALID_PARAM);
    compare(single_id_to_name(name, 4, &id), NOISE_ERROR_INVALID_LENGTH);
    verify(name[0] == '\0');
    /* A buffer too small for any name is reported as the length, whatever
       the id says; the table version may reach the id first */
    id.pattern_id = NOISE_PATTERN_XX;
    compare(single_id_to_name(name, 4, &id), NOISE_ERROR_INVALID_LENGTH);
    id.pattern_id = NOISE_PATTERN_NN;
    /* A zero length buffer must not be written to at all */
    name[0] = 'x';
    compare(single_id_to_name(name, 0, &id), NOISE_ERROR_INVALID_LENGTH);
    verify(name[0] == 'x');
    compare(single_name_to_id(0, "Noise_NNpsk0_25519_ChaChaPoly_SHA256", 36),
            NOISE_ERROR_INVALID_PARAM);
    compare(single_name_to_id(&id, 0, 0), NOISE_ERROR_INVALID_PARAM);

    /* Names for other protocols, and for nothing at all */
    compare_name_to_id("");
    compare_name_to_id("Noise_NNpsk0_25519_ChaChaPoly_SHA256 ");
    compare(single_name_to_id(&id, "Noise_XX_25519_ChaChaPoly_SHA256",
                              strlen("Noise_XX_25519_ChaChaPoly_SHA256")),
            NOISE_ERROR_UNKNOWN_NAME);
    /* The fixed NNpsk0 expansion must be what the table version builds,
       the whole buffer included: both clear the bytes past the end marker,
       so different poisons must come out identical */
    {
        uint8_t table_tokens[NOISE_MAX_TOKENS];
        uint8_t single_tokens[NOISE_MAX_TOKENS];
        int psk0 = NOISE_MODIFIER_PSK0;
        int psk0_psk1[2] = { NOISE_MODIFIER_PSK0, NOISE_MODIFIER_PSK1 };
        int psk1 = NOISE_MODIFIER_PSK1;
        memset(table_tokens, 0xAA, sizeof(table_tokens));
        memset(single_tokens, 0x55, sizeof(single_tokens));
        compare(noise_pattern_expand(table_tokens, NOISE_PATTERN_NN, &psk0, 1),
                NOISE_ERROR_NONE);
        compare(single_pattern_expand(single_tokens, NOISE_PATTERN_NN, &psk0, 1),
                NOISE_ERROR_NONE);
        compare(table_tokens[7], NOISE_TOKEN_END);
        compare_blocks(single_tokens, NOISE_MAX_TOKENS, table_tokens, NOISE_MAX_TOKENS);
        compare(single_pattern_expand(single_tokens, NOISE_PATTERN_NN, &psk1, 1),
                NOISE_ERROR_UNKNOWN_NAME);
        compare(single_pattern_expand(single_tokens, NOISE_PATTERN_NN, psk0_psk1, 2),
                NOISE_ERROR_UNKNOWN_NAME);
        compare(single_pattern_expand(single_tokens, NOISE_PATTERN_XX, &psk0, 1),
                NOISE_ERROR_UNKNOWN_NAME);
    }
}

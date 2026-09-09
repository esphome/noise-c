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

#include "test-helpers.h"

#define MAX_HASH_INPUT  128
#define MAX_HASH_OUTPUT 64
#define MAX_BLOCK_LEN   128

/* Check raw hash output against test vectors */
static void check_hash(int id, size_t hash_len, size_t block_len,
                       const char *name, const char *data, const char *hash)
{
    NoiseHashState *state;
    uint8_t input[MAX_HASH_INPUT];
    uint8_t output[MAX_HASH_OUTPUT];
    uint8_t temp[MAX_HASH_OUTPUT];
    size_t input_len;
    size_t index;

    /* Convert the test strings into binary data */
    input_len = string_to_data(input, sizeof(input), data);
    compare(string_to_data(output, sizeof(output), hash), hash_len);

    /* Create the hash object and check its properties */
    compare(noise_hashstate_new_by_id(&state, id), NOISE_ERROR_NONE);
    compare(noise_hashstate_get_hash_id(state), id);
    compare(noise_hashstate_get_hash_length(state), hash_len);
    compare(noise_hashstate_get_block_length(state), block_len);
    verify(hash_len <= noise_hashstate_get_max_hash_length());
    verify(block_len <= noise_hashstate_get_max_block_length());

    /* Check hashing all data in one hit */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_hashstate_hash_one(state, input, input_len, temp, hash_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, output, hash_len));

    /* Check hashing the data split into two separate parts */
    for (index = 0; index < input_len; ++index) {
        memset(temp, 0xAA, sizeof(temp));
        compare(noise_hashstate_hash_two
            (state, input, index, input + index, input_len - index,
             temp, hash_len),
            NOISE_ERROR_NONE);
        verify(!memcmp(temp, output, hash_len));
    }

    /* Check hashing the data with reset/update/finalize */
    for (index = 0; index < input_len; ++index) {
        memset(temp, 0xAA, sizeof(temp));
        compare(noise_hashstate_reset(state), NOISE_ERROR_NONE);
        if (index) {
            compare(noise_hashstate_update(state, input, index),
                    NOISE_ERROR_NONE);
        }
        compare(noise_hashstate_update(state, input + index, input_len - index),
                NOISE_ERROR_NONE);
        compare(noise_hashstate_finalize(state, temp, hash_len),
                NOISE_ERROR_NONE);
        verify(!memcmp(temp, output, hash_len));
    }

    /* Check parameter error conditions */
    compare(noise_hashstate_hash_one(0, input, input_len, temp, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_one(state, 0, input_len, temp, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_one(state, input, input_len, 0, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_one(state, input, input_len, temp, hash_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hash_one(state, input, input_len, temp, hash_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hash_two(0, input, 10, input + 10, 13, temp, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(state, 0, 10, input + 10, 13, temp, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(state, input, 10, 0, 13, temp, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(state, input, 10, input + 10, 13, 0, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(state, input, 10, input + 10, 13, temp, hash_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hash_two(state, input, 10, input + 10, 13, temp, hash_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_reset(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_update(0, input, 10), NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_update(state, 0, 10), NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_finalize(0, temp, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_finalize(state, 0, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_finalize(state, temp, hash_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_finalize(state, temp, hash_len + 1),
            NOISE_ERROR_INVALID_LENGTH);

    /* Re-create the object by name and check its properties again */
    compare(noise_hashstate_free(state), NOISE_ERROR_NONE);
    compare(noise_hashstate_new_by_name(&state, name), NOISE_ERROR_NONE);
    compare(noise_hashstate_get_hash_id(state), id);
    compare(noise_hashstate_get_hash_length(state), hash_len);
    compare(noise_hashstate_get_block_length(state), block_len);

    /* Make sure that it is still the same object by checking hash outputs */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_hashstate_hash_one(state, input, input_len, temp, hash_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, output, hash_len));

    /* Clean up */
    compare(noise_hashstate_free(state), NOISE_ERROR_NONE);
}

/* Check against test vectors from the various specifications
   to validate that the algorithms work as low level primitives */
static void hashstate_check_test_vectors(void)
{

    /* SHA256 */
    check_hash
        (NOISE_HASH_SHA256, 32, 64, "SHA256",
         "",
         "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_hash
        (NOISE_HASH_SHA256, 32, 64, "SHA256",
         "abc",
         "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_hash
        (NOISE_HASH_SHA256, 32, 64, "SHA256",
         "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

}

/* Formats a key for the simple implementation of HMAC */
static void format_hmac_key(NoiseHashState *state, uint8_t *block,
                            const uint8_t *key, size_t key_len, uint8_t pad)
{
    size_t hash_len = noise_hashstate_get_hash_length(state);
    size_t block_len = noise_hashstate_get_block_length(state);
    if (key_len <= block_len) {
        memcpy(block, key, key_len);
        memset(block + key_len, 0, block_len - key_len);
    } else {
        noise_hashstate_hash_one(state, key, key_len, block, hash_len);
        memset(block + hash_len, 0, block_len - hash_len);
    }
    while (block_len > 0) {
        --block_len;
        block[block_len] ^= pad;
    }
}

/* Simple implementation of HMAC for cross-checking the library */
static void hmac(NoiseHashState *state, uint8_t *hash,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len)
{
    size_t hash_len = noise_hashstate_get_hash_length(state);
    size_t block_len = noise_hashstate_get_block_length(state);
    uint8_t block[MAX_BLOCK_LEN];
    format_hmac_key(state, block, key, key_len, 0x36);
    noise_hashstate_hash_two(state, block, block_len, data, data_len, hash, hash_len);
    format_hmac_key(state, block, key, key_len, 0x5C);
    noise_hashstate_hash_two(state, block, block_len, hash, hash_len, hash, hash_len);
}

/* Simple implementation of HKDF for cross-checking the library */
static void hkdf(NoiseHashState *state, uint8_t *output1,
                 uint8_t *output2, uint8_t *output3,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len)
{
    size_t hash_len = noise_hashstate_get_hash_length(state);
    uint8_t temp_key[MAX_HASH_OUTPUT];
    uint8_t output[MAX_HASH_OUTPUT + 1];
    hmac(state, temp_key, key, key_len, data, data_len);
    output[0] = 0x01;
    hmac(state, output, temp_key, hash_len, output, 1);
    memcpy(output1, output, hash_len);
    output[hash_len] = 0x02;
    hmac(state, output, temp_key, hash_len, output, hash_len + 1);
    memcpy(output2, output, hash_len);
    output[hash_len] = 0x03;
    hmac(state, output, temp_key, hash_len, output, hash_len + 1);
    memcpy(output3, output, hash_len);
}

/* Check the behaviour of the noise_hashstate_hkdf() function */
static void hashstate_check_hkdf_algorithm(int id)
{
    NoiseHashState *state;
    size_t hash_len, index;
    uint8_t key[MAX_HASH_OUTPUT];
    uint8_t data[MAX_HASH_INPUT];
    uint8_t expected1[MAX_HASH_OUTPUT];
    uint8_t expected2[MAX_HASH_OUTPUT];
    uint8_t expected3[MAX_HASH_OUTPUT];
    uint8_t output1[MAX_HASH_OUTPUT];
    uint8_t output2[MAX_HASH_OUTPUT];
    uint8_t output3[MAX_HASH_OUTPUT];

    /* Create a hash object */
    compare(noise_hashstate_new_by_id(&state, id), NOISE_ERROR_NONE);
    hash_len = noise_hashstate_get_hash_length(state);

    /* Calculate the expected HKDF output with the simple implementation */
    memset(key, 0xAA, sizeof(key));
    memset(data, 0x66, sizeof(data));
    hkdf(state, expected1, expected2, expected3,
         key, sizeof(key), data, sizeof(data));

    /* Compare against what noise_hashstate_hkdf() produces */
    memset(output1, 0xE6, sizeof(output1));
    memset(output2, 0x6E, sizeof(output2));
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(output1, expected1, hash_len));
    verify(!memcmp(output2, expected2, hash_len));

    /* Call noise_hashstate_hkdf() again, but ask it to truncate the output */
    memset(output1, 0xE6, sizeof(output1));
    memset(output2, 0x6E, sizeof(output2));
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len / 2, output2, hash_len / 2),
            NOISE_ERROR_NONE);
    verify(!memcmp(output1, expected1, hash_len / 2));
    verify(!memcmp(output2, expected2, hash_len / 2));
    for (index = (hash_len / 2); index < hash_len; ++index) {
        /* Check that the function didn't write beyond our requested length */
        compare(output1[index], 0xE6);
        compare(output2[index], 0x6E);
    }

    /* Compare against what noise_hashstate_hkdf3() produces */
    memset(output1, 0xE6, sizeof(output1));
    memset(output2, 0x6E, sizeof(output2));
    memset(output3, 0x66, sizeof(output3));
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len,
                                 output3, hash_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(output1, expected1, hash_len));
    verify(!memcmp(output2, expected2, hash_len));
    verify(!memcmp(output3, expected3, hash_len));

    /* Call noise_hashstate_hkdf3() again, but ask it to truncate the output */
    memset(output1, 0xE6, sizeof(output1));
    memset(output2, 0x6E, sizeof(output2));
    memset(output3, 0x66, sizeof(output3));
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                  output1, hash_len / 2, output2, hash_len / 2,
                                  output3, hash_len / 2),
            NOISE_ERROR_NONE);
    verify(!memcmp(output1, expected1, hash_len / 2));
    verify(!memcmp(output2, expected2, hash_len / 2));
    verify(!memcmp(output3, expected3, hash_len / 2));
    for (index = (hash_len / 2); index < hash_len; ++index) {
        /* Check that the function didn't write beyond our requested length */
        compare(output1[index], 0xE6);
        compare(output2[index], 0x6E);
        compare(output3[index], 0x66);
    }

    /* Check parameter error conditions */
    compare(noise_hashstate_hkdf(0, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, 0, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), 0, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 0, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, 0, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len + 1, output2, hash_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hkdf3(0, key, sizeof(key), data, sizeof(data),
                                  output1, hash_len, output2, hash_len,
                                  output3, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf3(state, 0, sizeof(key), data, sizeof(data),
                                  output1, hash_len, output2, hash_len,
                                  output3, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), 0, sizeof(data),
                                  output1, hash_len, output2, hash_len,
                                  output3, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                  0, hash_len, output2, hash_len,
                                  output3, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                  output1, hash_len, 0, hash_len,
                                  output3, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                  output1, hash_len, output2, hash_len,
                                  0, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                  output1, hash_len + 1, output2, hash_len,
                                  output3, hash_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                  output1, hash_len, output2, hash_len + 1,
                                  output3, hash_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hkdf3(state, key, sizeof(key), data, sizeof(data),
                                  output1, hash_len, output2, hash_len,
                                  output3, hash_len + 1),
            NOISE_ERROR_INVALID_LENGTH);

    /* Clean up */
    compare(noise_hashstate_free(state), NOISE_ERROR_NONE);
}

/* Check the behaviour of the noise_hashstate_hkdf() function */
static void hashstate_check_hkdf(void)
{
    hashstate_check_hkdf_algorithm(NOISE_HASH_SHA256);
}

/* Check the behaviour of the noise_hashstate_pbkdf2() function */
static void check_pbkdf2(const char *name, const char *passphrase,
                         const char *salt, size_t iterations,
                         const char *result)
{
    uint8_t passphrase_bytes[32];
    uint8_t salt_bytes[32];
    uint8_t result_bytes[64];
    uint8_t hash[64];
    size_t passphrase_len;
    size_t salt_len;
    size_t result_len;
    NoiseHashState *state;

    /* Convert the test strings from hex into binary */
    passphrase_len = string_to_data
        (passphrase_bytes, sizeof(passphrase_bytes), passphrase);
    salt_len = string_to_data
        (salt_bytes, sizeof(salt_bytes), salt);
    result_len = string_to_data
        (result_bytes, sizeof(result_bytes), result);
    verify(result_len <= sizeof(hash));

    /* Construct a SHA256 hashing object */
    compare(noise_hashstate_new_by_id
                (&state, NOISE_HASH_SHA256), NOISE_ERROR_NONE);

    /* Run PBKDF2 and check the output */
    compare(noise_hashstate_pbkdf2
                (state, passphrase_bytes, passphrase_len,
                 salt_bytes, salt_len, iterations, hash, result_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(hash, result_bytes, result_len));

    /* Test error conditions */
    compare(noise_hashstate_pbkdf2
                (0, passphrase_bytes, passphrase_len,
                 salt_bytes, salt_len, iterations, hash, result_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_pbkdf2
                (state, 0, passphrase_len,
                 salt_bytes, salt_len, iterations, hash, result_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_pbkdf2
                (state, passphrase_bytes, passphrase_len,
                 0, salt_len, iterations, hash, result_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_pbkdf2
                (state, passphrase_bytes, passphrase_len,
                 salt_bytes, salt_len, iterations, 0, result_len),
            NOISE_ERROR_INVALID_PARAM);
    if (sizeof(size_t) > 4) {
        result_len = (size_t)(((uint64_t)0xFFFFFFFF) * 32 + 1);
        compare(noise_hashstate_pbkdf2
                    (state, passphrase_bytes, passphrase_len,
                     salt_bytes, salt_len, iterations, hash, result_len),
                NOISE_ERROR_INVALID_LENGTH);
    }

    /* Clean up */
    noise_hashstate_free(state);
}

/* Check the behaviour of the noise_hashstate_pbkdf2() function */
static void hashstate_check_pbkdf2(void)
{
    /* Test vectors for PBKDF2-HMAC-SHA-256 from section 11 of
       https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-05 */
    check_pbkdf2("PBKDF2 #1", "passwd", "salt", 1,
                 "0x55ac046e56e3089fec1691c22544b605"
                   "f94185216dde0465e68b9d57c20dacbc"
                   "49ca9cccf179b645991664b39d77ef31"
                   "7c71b845b1e30bd509112041d3a19783");
    check_pbkdf2("PBKDF2 #2", "Password", "NaCl", 80000,
                 "0x4ddcd8f60b98be21830cee5ef22701f9"
                   "641a4418d04c0414aeff08876b34ab56"
                   "a1d425a1225833549adb841b51c9b317"
                   "6a272bdebba1d078478f62b397f33c8d");
}

/* Check other error conditions that can be reported by the functions */
static void hashstate_check_errors(void)
{
    NoiseHashState *state;

    /* NULL parameters in various positions */
    compare(noise_hashstate_free(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_get_hash_id(0), NOISE_HASH_NONE);
    compare(noise_hashstate_get_hash_length(0), 0);
    compare(noise_hashstate_get_block_length(0), 0);
    compare(noise_hashstate_new_by_id(0, NOISE_HASH_SHA256),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_new_by_name(0, "SHA256"),
            NOISE_ERROR_INVALID_PARAM);

    /* If the id/name is unknown, the state parameter should be set to NULL */
    state = (NoiseHashState *)8;
    compare(noise_hashstate_new_by_id(&state, NOISE_CIPHER_CHACHAPOLY),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseHashState *)8;
    compare(noise_hashstate_new_by_name(&state, 0),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseHashState *)8;
    compare(noise_hashstate_new_by_name(&state, "BLAKE3s"),
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
}

void test_hashstate(void)
{
    hashstate_check_test_vectors();
    hashstate_check_hkdf();
    hashstate_check_pbkdf2();
    hashstate_check_errors();
}

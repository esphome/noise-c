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

int test_count = 0;
int test_failures = 0;
jmp_buf test_jump_back;
const char *data_name = 0;
int verbose = 0;

/* Names given on the command line, and which of them matched a test */
static int names_given = 0;
static int names_matched = 0;

/* True when the test was named on the command line, or none were */
static int test_selected(int argc, char *argv[], const char *name)
{
    int index;
    int any = 0;
    int selected = 0;
    for (index = 1; index < argc; ++index) {
        if (!strcmp(argv[index], "--verbose"))
            continue;
        any = 1;
        /* Every occurrence counts, so a name given twice is not stale */
        if (!strcmp(argv[index], name)) {
            ++names_matched;
            selected = 1;
        }
    }
    return any ? selected : 1;
}

#define run(func) \
    do { \
        if (test_selected(argc, argv, #func)) \
            test(func); \
    } while (0)

int main(int argc, char *argv[])
{
    /* Parse the command-line arguments; --verbose may sit anywhere */
    int index;
    for (index = 1; index < argc; ++index) {
        if (!strcmp(argv[index], "--verbose"))
            verbose = 1;
        else
            ++names_given;
    }

    if (noise_init_framework() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    /* Run all tests */
    run(cipherstate);
    run(dhstate);
    run(errors);
    run(handshakestate);
    run(handshakestate_preset_ephemeral);
    run(hashstate);
    run(names);
    run(patterns);
    run(randstate);
    run(single_protocol);
    run(small_build);
    run(symmetricstate);

    /* Report the results; every name given must have been a test */
    if (names_matched < names_given) {
        fprintf(stderr, "%d of the names given matched no test\n",
                names_given - names_matched);
        return 1;
    }
    if (!test_failures) {
        printf("All tests succeeded\n");
    } else {
        printf("%d test%s failed\n", test_failures, test_failures == 1 ? "" : "s");
    }
    return test_failures ? 1 : 0;
}

static int from_hex(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    else if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    verify(0);
    return 0;
}

size_t string_to_data(uint8_t *data, size_t max_len, const char *str)
{
    size_t len;
    if (str[0] == '0' && str[1] == 'x') {
        /* Hexadecimal string */
        len = 0;
        str += 2;
        while (str[0] != '\0') {
            if (str[0] == ' ') {
                /* Skip spaces in the hexadecimal string */
                ++str;
                continue;
            }
            verify(str[1] != '\0');
            verify(len < max_len);
            data[len++] = from_hex(str[0]) * 16 + from_hex(str[1]);
            str += 2;
        }
        return len;
    } else {
        /* ASCII string */
        len = strlen(str);
        verify(len <= max_len);
        memcpy(data, str, len);
        return len;
    }
}

void print_block(const char *tag, const uint8_t *data, size_t size)
{
    printf("%s:", tag);
    while (size > 0) {
        printf(" %02x", *data);
        ++data;
        --size;
    }
    printf("\n");
}

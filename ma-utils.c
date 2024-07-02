// MIT License

// Copyright (c) 2024 ramsy0dev

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "ma-utils.h"

#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <stdint.h>

// ------------------------------------------------------------------------- //
//                      Costum memory allocation pool                        //
// ------------------------------------------------------------------------- //

// Vector memory pool
static MemoryPoolVector *ma_vector_memory_pool_create(size_t size) {
    if (size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Memory pool size cannot be zero.\n");
        #endif
        return NULL;
    }

    MemoryPoolVector *pool = malloc(sizeof(MemoryPoolVector));
    if (!pool) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Failed to allocate memory for MemoryPoolVector structure.\n");
        #endif
        return NULL;
    }

    pool->pool = malloc(size);
    if (!pool->pool) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Failed to allocate memory for memory pool of size %zu.\n", size);
        #endif
        free(pool);
        return NULL;
    }

    pool->poolSize = size;
    pool->used = 0;

    return pool;
}

static void *ma_vector_memory_pool_allocate(MemoryPoolVector *pool, size_t size) {
    if (!pool) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Memory pool is not initialized.\n");
        #endif
        return NULL;
    }
    if (size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Cannot allocate zero size.\n");
        #endif
        return NULL;
    }
    if (pool->used + size > pool->poolSize) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Memory pool out of space. Cannot allocate %zu bytes.\n", size);
        #endif
        return NULL; // Pool is out of memory
    }

    void *mem = (char *)pool->pool + pool->used;
    pool->used += size;

    return mem;
}

static void ma_vector_memory_pool_destroy(MemoryPoolVector *pool) {
    if (!pool) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Attempted to destroy a non-initialized memory pool.\n");
        #endif
        return;
    }
    free(pool->pool); // Free the allocated pool memory
    free(pool); // Free the pool structure itself
}

// ------------------------------------------------------------------------- //
//                             Encoding                                      //
// ------------------------------------------------------------------------- //

bool (*b58_sha256_impl)(void *, const void *, size_t) = NULL;

#define UNI_REPLACEMENT_CHAR (uint32_t)0x0000FFFD
#define UNI_SUR_HIGH_START  (unsigned int)0xD800
#define UNI_SUR_HIGH_END    (unsigned int)0xDBFF
#define UNI_SUR_LOW_START   (unsigned int)0xDC00
#define UNI_SUR_LOW_END     (unsigned int)0xDFFF
#define UNI_MAX_BMP (unsigned int)0x0000FFFF
#define UNI_MAX_UTF16 (unsigned int)0x0010FFFF
#define UNI_MAX_UTF32 (unsigned int)0x7FFFFFFF
#define UNI_MAX_LEGAL_UTF32 (unsigned int)0x0010FFFF
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define b58_almostmaxint_bits (sizeof(uint32_t) * 8)
#define CHAR_BIT 8

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
static const char base16_chars[] = "0123456789ABCDEF";
static const int halfShift  = 10; /* used for shifting by 10 bits */
static const uint8_t firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
static const char trailingBytesForUTF8[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
};
static const uint32_t offsetsFromUTF8[6] = { 0x00000000UL, 0x00003080UL, 0x000E2080UL,
                     0x03C82080UL, 0xFA082080UL, 0x82082080UL };
static const unsigned int halfBase = 0x0010000UL;
static const unsigned int halfMask = 0x3FFUL;
static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};
static const char BASE91_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

static int base91_decode_value(char c) {
    for (int i = 0; i < 91; ++i) {
        if (BASE91_ALPHABET[i] == c) {
            return i;
        }
    }
    return -1; // Character not found
}

bool ma_encoding_is_utf8(const uint8_t* input, size_t length) {
    uint8_t a;
    const uint8_t *srcptr = input+length;

    switch (length) {
    default:
        return false;
        /* Everything else falls through when "true"... */
    case 4:
        if ((a = (*--srcptr)) < 0x80 || a > 0xBF) {
            return false;
        }
    /* fall through */
    case 3:
        if ((a = (*--srcptr)) < 0x80 || a > 0xBF) {
            return false;
        }
   /* fall through */
    case 2:
        if ((a = (*--srcptr)) < 0x80 || a > 0xBF) {
            return false;
        }
    /* fall through */


        switch (*input) {
            case 0xE0:
                if (a < 0xA0) {
                    return false;
                }
                break;
            case 0xED:
                if (a > 0x9F) {
                    return false;
                }
                break;
            case 0xF0:
                if (a < 0x90) {
                    return false;
                }
                break;
            case 0xF4:
                if (a > 0x8F) {
                    return false;
                }
                break;
            default:
                if (a < 0x80) {
                    return false;
                }
            /* fall through */
        }
    /* fall through */
    case 1:
        if (*input >= 0x80 && *input < 0xC2) {
            return false;
        }
    }

    if (*input > 0xF4) {
        return false;
    }
    return true;
}

static ConversionResult ConvertUTF16toUTF8 (
        const uint16_t** sourceStart, const uint16_t* sourceEnd,
        uint8_t** targetStart, uint8_t* targetEnd, ConversionFlags flags) {

    ConversionResult result = conversionOK;
    const uint16_t* source = *sourceStart;
    uint8_t* target = *targetStart;

    while (source < sourceEnd) {
        uint32_t ch;
        unsigned short bytesToWrite = 0;
        const uint32_t byteMask = 0xBF;
        const uint32_t byteMark = 0x80;
        const uint16_t* oldSource = source; /* In case we have to back up because of target overflow. */
        ch = *source++;
        /* If we have a surrogate pair, convert to UTF32 first. */
        if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
            /* If the 16 bits following the high surrogate are in the source buffer... */
            if (source < sourceEnd) {
                uint32_t ch2 = *source;
                /* If it's a low surrogate, convert to UTF32. */
                if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
                    ch = ((ch - UNI_SUR_HIGH_START) << halfShift)
                        + (ch2 - UNI_SUR_LOW_START) + halfBase;
                    ++source;
                }
                else if (flags == strictConversion) { /* it's an unpaired high surrogate */
                    --source; /* return to the illegal value itself */
                    result = sourceIllegal;
                    break;
                }
            }
            else { /* We don't have the 16 bits following the high surrogate. */
                --source; /* return to the high surrogate */
                result = sourceExhausted;
                break;
            }
        }
        else if (flags == strictConversion) {
            /* UTF-16 surrogate values are illegal in UTF-32 */
            if (ch >= UNI_SUR_LOW_START && ch <= UNI_SUR_LOW_END) {
                --source; /* return to the illegal value itself */
                result = sourceIllegal;
                break;
            }
        }
        /* Figure out how many bytes the result will require */
        if (ch < (uint32_t)0x80) {
            bytesToWrite = 1;
        }
        else if (ch < (uint32_t)0x800) {
            bytesToWrite = 2;
        }
        else if (ch < (uint32_t)0x10000) {
            bytesToWrite = 3;
        }
        else if (ch < (uint32_t)0x110000) {
            bytesToWrite = 4;
        }
        else {
            bytesToWrite = 3;
            ch = UNI_REPLACEMENT_CHAR;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            source = oldSource; /* Back up source pointer! */
            target -= bytesToWrite; result = targetExhausted; break;
        }
        switch (bytesToWrite) { /* note: everything falls through. */
            case 4:
            *--target = (uint8_t)((ch | byteMark) & byteMask); ch >>= 6;
            // fall through
            case 3:
            *--target = (uint8_t)((ch | byteMark) & byteMask); ch >>= 6;
            // fall through
            case 2:
            *--target = (uint8_t)((ch | byteMark) & byteMask); ch >>= 6;
            // fall through
            case 1:
            *--target =  (uint8_t)(ch | firstByteMark[bytesToWrite]);
            // fall through
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;

    return result;
}

static ConversionResult ConvertUTF32toUTF8 (
        const uint32_t** sourceStart, const uint32_t* sourceEnd,
        uint8_t** targetStart, uint8_t* targetEnd, ConversionFlags flags) {

    ConversionResult result = conversionOK;
    const uint32_t* source = *sourceStart;
    uint8_t* target = *targetStart;

    while (source < sourceEnd) {
        uint32_t ch;
        unsigned short bytesToWrite = 0;
        const uint32_t byteMask = 0xBF;
        const uint32_t byteMark = 0x80;
        ch = *source++;
        if (flags == strictConversion ) {
            /* UTF-16 surrogate values are illegal in UTF-32 */
            if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_LOW_END) {
                --source; /* return to the illegal value itself */
                result = sourceIllegal;
                break;
            }
        }
        /*
         * Figure out how many bytes the result will require. Turn any
         * illegally large UTF32 things (> Plane 17) into replacement chars.
         */
        if (ch < (uint32_t)0x80) {
            bytesToWrite = 1;
        }
        else if (ch < (uint32_t)0x800) {
            bytesToWrite = 2;
        }
        else if (ch < (uint32_t)0x10000) {
            bytesToWrite = 3;
        }
        else if (ch <= UNI_MAX_LEGAL_UTF32) {
            bytesToWrite = 4;
        }
        else {
            bytesToWrite = 3;
            ch = UNI_REPLACEMENT_CHAR;
            result = sourceIllegal;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            --source; /* Back up source pointer! */
            target -= bytesToWrite; result = targetExhausted; break;
        }
        switch (bytesToWrite) { /* note: everything falls through. */
            case 4:
                *--target = (uint8_t)((ch | byteMark) & byteMask); ch >>= 6;
            // fall through
            case 3:
                *--target = (uint8_t)((ch | byteMark) & byteMask); ch >>= 6;
            // fall through
            case 2:
                *--target = (uint8_t)((ch | byteMark) & byteMask); ch >>= 6;
            // fall through
            case 1:
                *--target = (uint8_t) (ch | firstByteMark[bytesToWrite]);
            // fall through
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;

    return result;
}

static ConversionResult ConvertUTF8toUTF16 (
        const uint8_t** sourceStart, const uint8_t* sourceEnd,
        uint16_t** targetStart, uint16_t* targetEnd, ConversionFlags flags) {
    ConversionResult result = conversionOK;
    const uint8_t* source = *sourceStart;
    uint16_t* target = *targetStart;

    while (source < sourceEnd) {
        uint32_t ch = 0;
        unsigned short extraBytesToRead = trailingBytesForUTF8[*source];

        if (extraBytesToRead >= sourceEnd - source) {
            result = sourceExhausted; break;
        }
        /* Do this check whether lenient or strict */
        if (!ma_encoding_is_utf8(source, extraBytesToRead+1)) {
            result = sourceIllegal;
            break;
        }
        /*
         * The cases all fall through. See "Note A" below.
         */
        switch (extraBytesToRead) {
            case 5:
                ch += *source++; ch <<= 6; /* remember, illegal UTF-8 */
            // fall through
            case 4:
                ch += *source++; ch <<= 6; /* remember, illegal UTF-8 */
                // fall through
            case 3:
                ch += *source++; ch <<= 6;
                // fall through
            case 2:
                ch += *source++; ch <<= 6;
                // fall through
            case 1:
                ch += *source++; ch <<= 6;
                // fall through
            case 0:
                ch += *source++;
                // fall through
        }
        ch -= offsetsFromUTF8[extraBytesToRead];

        if (target >= targetEnd) {
            source -= (extraBytesToRead+1); /* Back up source pointer! */
            result = targetExhausted; break;
        }
        if (ch <= UNI_MAX_BMP) { /* Target is a character <= 0xFFFF */
            /* UTF-16 surrogate values are illegal in UTF-32 */
            if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_LOW_END) {
                if (flags == strictConversion) {
                    source -= (extraBytesToRead+1); /* return to the illegal value itself */
                    result = sourceIllegal;
                    break;
                }
                else {
                    *target++ = UNI_REPLACEMENT_CHAR;
                }
            }
            else {
                *target++ = (uint16_t)ch; /* normal case */
            }
        }
        else if (ch > UNI_MAX_UTF16) {
            if (flags == strictConversion) {
                result = sourceIllegal;
                source -= (extraBytesToRead+1); /* return to the start */
                break; /* Bail out; shouldn't continue */
            }
            else {
                *target++ = UNI_REPLACEMENT_CHAR;
            }
        }
        else {
            /* target is a character in range 0xFFFF - 0x10FFFF. */
            if (target + 1 >= targetEnd) {
                source -= (extraBytesToRead+1); /* Back up source pointer! */
                result = targetExhausted; break;
            }
            ch -= halfBase;
            *target++ = (uint16_t)((ch >> halfShift) + UNI_SUR_HIGH_START);
            *target++ = (uint16_t)((ch & halfMask) + UNI_SUR_LOW_START);
        }
    }
    *sourceStart = source;
    *targetStart = target;

    return result;
}

ConversionResult ConvertUTF8toUTF32 (
        const uint8_t** sourceStart, const uint8_t* sourceEnd,
        uint32_t** targetStart, uint32_t* targetEnd, ConversionFlags flags) {
    ConversionResult result = conversionOK;
    const uint8_t* source = *sourceStart;
    uint32_t* target = *targetStart;

    while (source < sourceEnd) {
        uint32_t ch = 0;
        unsigned short extraBytesToRead = trailingBytesForUTF8[*source];
        if (extraBytesToRead >= sourceEnd - source) {
            result = sourceExhausted; break;
        }
        /* Do this check whether lenient or strict */
        if (!ma_encoding_is_utf8(source, extraBytesToRead+1)) {
            result = sourceIllegal;
            break;
        }
        /*
         * The cases all fall through. See "Note A" below.
         */
        switch (extraBytesToRead) {
            case 5:
                ch += *source++; ch <<= 6;
                // fall through
            case 4:
                ch += *source++; ch <<= 6;
                // fall through
            case 3:
                ch += *source++; ch <<= 6;
                // fall through
            case 2:
                ch += *source++; ch <<= 6;
                // fall through
            case 1:
                ch += *source++; ch <<= 6;
                // fall through
            case
                0: ch += *source++;
                // fall through
        }
        ch -= offsetsFromUTF8[extraBytesToRead];

        if (target >= targetEnd) {
            source -= (extraBytesToRead+1); /* Back up the source pointer! */
            result = targetExhausted; break;
        }
        if (ch <= UNI_MAX_LEGAL_UTF32) {
            /*
             * UTF-16 surrogate values are illegal in UTF-32, and anything
             * over Plane 17 (> 0x10FFFF) is illegal.
             */
            if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_LOW_END) {
                if (flags == strictConversion) {
                    source -= (extraBytesToRead+1); /* return to the illegal value itself */
                    result = sourceIllegal;
                    break;
                } else {
                    *target++ = UNI_REPLACEMENT_CHAR;
                }
            } else {
                *target++ = ch;
            }
        } else { /* i.e., ch > UNI_MAX_LEGAL_UTF32 */
            result = sourceIllegal;
            *target++ = UNI_REPLACEMENT_CHAR;
        }
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}

static int decode_char(unsigned char c) {
	char retval = -1;

	if (c >= 'A' && c <= 'Z') {
		retval = c - 'A';
    }
	if (c >= '2' && c <= '7') {
		retval = c - '2' + 26;
    }

	assert(retval == -1 || ((retval & 0x1F) == retval));
	return  retval;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return the index of
 * the octet in which this block starts. For example, given 3 it will return 1
 * because block 3 starts in octet 1:
 *
 * +--------+--------+
 * | ......<|.3 >....|
 * +--------+--------+
 *  octet 1 | octet 2
 */
static int get_octet(int block) {
	assert(block >= 0 && block < 8);
	return (block*5) / 8;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return how many bits
 * we can drop at the end of the octet in which this block starts.
 * For example, given block 0 it will return 3 because there are 3 bits
 * we don't care about at the end:
 *
 *  +--------+-
 *  |< 0 >...|
 *  +--------+-
 *
 * Given block 1, it will return -2 because there
 * are actually two bits missing to have a complete block:
 *
 *  +--------+-
 *  |.....< 1|..
 *  +--------+-
 **/
static int get_offset(int block) {
	assert(block >= 0 && block < 8);
	return (8 - 5 - (5*block) % 8);
}

/**
 * Like "b >> offset" but it will do the right thing with negative offset.
 * We need this as bitwise shifting by a negative offset is undefined
 * behavior.
 */
static unsigned char shift_right(unsigned char byte, signed char offset) {
	if (offset > 0) {
		return byte >>  offset;
    } else {
		return byte << -offset;
    }
}

static unsigned char shift_left(unsigned char byte, signed char offset) {
	return shift_right(byte, - offset);
}

static int decode_sequence(const unsigned char *coded, unsigned char *plain) {
	assert(CHAR_BIT == 8);
	assert(coded && plain);

	plain[0] = 0;
	for (int block = 0; block < 8; block++) {
		int offset = get_offset(block);
		int octet = get_octet(block);

		int c = decode_char(coded[block]);
		if (c < 0) {
			return octet;
        }

		plain[octet] |= shift_left(c, offset);
		if (offset < 0) {  // does this block overflows to next octet?
			assert(octet < 4);
			plain[octet+1] = shift_left(c, 8 + offset);
		}
	}
	return 5;
}

char* ma_encoding_base64_encode(const char* input, size_t length) {
    size_t output_length = 4 * ((length + 2) / 3);
    char* encoded = malloc(output_length + 1); // +1 for null terminator
    if (!encoded) {
        printf("Error: Can not allocate memory for encoded in encoding_base64_encode.\n");
        return NULL;
    }

    size_t i, j;
    for (i = 0, j = 0; i < length;) {
        uint32_t octet_a = i < length ? (unsigned char)input[i++] : 0;
        uint32_t octet_b = i < length ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = i < length ? (unsigned char)input[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded[j++] = base64_chars[(triple >> 18) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 12) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 6) & 0x3F];
        encoded[j++] = base64_chars[triple & 0x3F];
    }

    for (size_t k = 0; k < (3 - length % 3) % 3; k++) {
        encoded[output_length - 1 - k] = '=';
    }

    encoded[output_length] = '\0';
    return encoded;
}

char* ma_encoding_base64_decode(const char* input, size_t length) {
    if (length % 4 != 0) {
        printf("Error: Invalid input length in encoding_base64_decode. Length must be a multiple of 4.\n");
        return NULL;
    }

    size_t output_length = length / 4 * 3;
    if (input[length - 1] == '=')  {
        output_length--;
    }

    if (input[length - 2] == '=') {
        output_length--;
    }

    char* decoded = malloc(output_length + 1);
    if (!decoded) {
        printf("Error: Memory allocation failed in encoding_base64_decode.\n");
        return NULL;
    }

    static const unsigned char d[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0,
        0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };

    for (size_t i = 0, j = 0; i < length;) {
        uint32_t sextet_a = input[i] == '=' ? 0 & i++ : d[(unsigned char)input[i++]];
        uint32_t sextet_b = input[i] == '=' ? 0 & i++ : d[(unsigned char)input[i++]];
        uint32_t sextet_c = input[i] == '=' ? 0 & i++ : d[(unsigned char)input[i++]];
        uint32_t sextet_d = input[i] == '=' ? 0 & i++ : d[(unsigned char)input[i++]];
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < output_length) {
            decoded[j++] = (triple >> 16) & 0xFF;
        }
        if (j < output_length) {
            decoded[j++] = (triple >> 8) & 0xFF;
        }
        if (j < output_length) {
            decoded[j++] = triple & 0xFF;
        }
    }

    decoded[output_length] = '\0';

    return decoded;
}

char* ma_encoding_url_encode(const char* input, size_t length) {
    char* result = malloc(3 * length + 1); // Worst case scenario, every character needs encoding
    if (!result) {
        printf("Error: Memory allocation failed in encoding_url_encode.\n");
        return NULL;
    }

    size_t result_index = 0;
    for (size_t i = 0; i < length; ++i) {
        char ch = input[i];
        if (isalnum(ch) || ch == '-' || ch == '.' || ch == '_' || ch == '~') {
            result[result_index++] = ch;
        }
        else {
            static const char hex[] = "0123456789ABCDEF";
            result[result_index++] = '%';
            result[result_index++] = hex[(ch >> 4) & 0x0F];
            result[result_index++] = hex[ch & 0x0F];
        }
    }
    result[result_index] = '\0';

    return result;
}

char* ma_encoding_url_decode(const char* input, size_t length) {
    char* result = malloc(length + 1); // Decoded string will be equal or smaller in size
    if (!result) {
        printf("Error: Memory allocation failed in encoding_url_decode.\n");
        return NULL;
    }

    size_t result_index = 0;
    for (size_t i = 0; i < length; ++i) {
        char ch = input[i];
        if (ch == '%') {
            if (i + 2 >= length) {
                printf("Error: Incomplete percent-encoding in encoding_url_decode.\n");
                free(result);
                return NULL;
            }

            static const char hex[] = "0123456789ABCDEF";
            char hi = input[++i];
            char lo = input[++i];
            int hi_index = strchr(hex, toupper(hi)) - hex;
            int lo_index = strchr(hex, toupper(lo)) - hex;

            if (hi_index < 0 || hi_index >= 16 || lo_index < 0 || lo_index >= 16) {
                printf("Error: Invalid hex characters in percent-encoding in encoding_url_decode.\n");
                free(result);
                return NULL;
            }

            result[result_index++] = (char)((hi_index << 4) + lo_index);
        }
        else if (ch == '+') {
            result[result_index++] = ' ';
        }
        else {
            result[result_index++] = ch;
        }
    }
    result[result_index] = '\0';
    return result;
}

char* ma_encoding_base32_encode(const char* input, size_t length) {
    size_t output_length = ((length + 4) / 5) * 8; // Output length including padding
    char* encoded = malloc(output_length + 1);

    if (!encoded) {
        printf("Error: Memory allocation failed in encoding_base32_encode.\n");
        return NULL;
    }

    size_t input_index = 0;
    size_t output_index = 0;
    size_t bit_count = 0;
    uint32_t buffer = 0;

    while (input_index < length) {
        // Fill the buffer with up to 5 bytes
        buffer = (buffer << 8) | (uint8_t)input[input_index++];
        bit_count += 8;

        // While we have more than 5 bits, process the buffer
        while (bit_count >= 5) {
            encoded[output_index++] = base32[(buffer >> (bit_count - 5)) & 0x1F];
            bit_count -= 5;
        }
    }

    // Process any remaining bits in the buffer
    if (bit_count > 0) {
        encoded[output_index++] = base32[(buffer << (5 - bit_count)) & 0x1F];
    }

    // Add padding
    while (output_index < output_length) {
        encoded[output_index++] = '=';
    }

    encoded[output_index] = '\0';

    return encoded;
}

char* ma_encoding_base32_decode(const char* input, size_t length) {
    if (length % 8 != 0) {
        printf("Error: Invalid input length in encoding_base32_decode. Length must be a multiple of 8.\n");
        return NULL;
    }

    size_t olength = (length / 8) * 5;
    unsigned char* result = malloc(olength + 1);
    if (!result) {
        printf("Error: Memory allocation failed in encoding_base32_decode.\n");
        return NULL;
    }

    size_t i = 0, j = 0;
    while (i < length) {
        if (input[i] == '=') {
            break; // Padding character
        }

        int n = decode_sequence((const unsigned char*)&input[i], &result[j]);
        if (n < 5) { // Less than 5 bytes decoded, indicates padding or end of input
            j += n;
            break;
        }

        i += 8;
        j += 5;
    }

    result[j] = '\0';

    return (char*)result;
}

char* ma_encoding_base16_encode(const char* input, size_t length) {
    size_t output_length = length * 2;
    char* encoded = malloc(output_length + 1);

    if (!encoded) {
        printf("Error: Memory allocation failed in encoding_base16_encode.\n");
        return NULL;
    }

    for (size_t i = 0, j = 0; i < length; ++i) {
        uint8_t ch = (uint8_t)input[i];
        encoded[j++] = base16_chars[(ch & 0xF0) >> 4];
        encoded[j++] = base16_chars[ch & 0x0F];
    }

    encoded[output_length] = '\0';

    return encoded;
}

char* ma_encoding_base16_decode(const char* input, size_t length) {
    if (input == NULL) {
        printf("Error: Invalid input param in encoding_base16_decode.\n");
        return NULL;
    }
    static const unsigned char base16_decode[128] ={
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
     };

    if (length % 2 != 0) {
        printf("Error: Invalid input length in encoding_base16_decode.\n");
        return NULL; // Invalid input length
    }

    size_t olength = length / 2;
    char* decoded = malloc(olength + 1);

    if (!decoded) {
        printf("Error: Cannot allocate memory for Base16 decoded string in encoding_base16_decode.\n");
        return NULL;
    }

    for (size_t i = 0, j = 0; i < length;) {
        uint8_t a = base16_decode[(unsigned char)input[i++]];
        uint8_t b = base16_decode[(unsigned char)input[i++]];

        if (a == 0xFF || b == 0xFF) {
            printf("Error: Invalid Character in encoding_base16_decode.\n");
            free(decoded);
            return NULL; // Invalid character
        }

        decoded[j++] = (a << 4) | b;
    }

    decoded[olength] = '\0';

    return decoded;
}

uint16_t* ma_encoding_utf32_to_utf16(const uint32_t* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encoding_utf32_to_utf16.\n");
        return NULL;
    }

    // Allocate maximum possible size (each UTF-32 character might become two UTF-16 characters)
    uint16_t* output = malloc(sizeof(uint16_t) * (length * 2 + 1));
    if (!output) {
        printf("Error: Memory allocation failed in encoding_utf32_to_utf16.\n");
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < length; ++i) {
        uint32_t ch = input[i];

        if (ch > UNI_MAX_LEGAL_UTF32) {
            printf("Error: Invalid Character in encoding_utf32_to_utf16.\n");
            free(output);
            return NULL;
        }

        if (ch <= UNI_MAX_BMP) {
            // Character can be directly converted to single UTF-16 unit
            output[j++] = (uint16_t)ch;
        }
        else if (ch > UNI_MAX_BMP && ch <= UNI_MAX_UTF16) {
            // Convert character to surrogate pair
            ch -= halfBase;
            output[j++] = (uint16_t)((ch >> halfShift) + UNI_SUR_HIGH_START);
            output[j++] = (uint16_t)((ch & halfMask) + UNI_SUR_LOW_START);
        }
    }

    // Null-terminate the UTF-16 string
    output[j] = 0;

    return output;
}

uint32_t* ma_encoding_utf16_to_utf32(const uint16_t* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encoding_utf16_to_utf32.\n");
        return NULL;
    }

    // Allocate memory for the worst-case scenario (all characters are non-surrogates)
    uint32_t* output = malloc(sizeof(uint32_t) * (length + 1));
    if (!output) {
        printf("Error: Memory allocation failed in encoding_utf16_to_utf32.\n");
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < length; ++i) {
        uint32_t ch = input[i];

        // Check for high surrogate
        if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
            // Ensure there's a following character for the low surrogate
            if (i + 1 < length) {
                uint32_t ch2 = input[i + 1];
                // Check for low surrogate and construct the full code point
                if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
                    ch = ((ch - UNI_SUR_HIGH_START) << 10) + (ch2 - UNI_SUR_LOW_START) + 0x10000;
                    i++; // Skip the low surrogate
                }
                else {
                    printf("Error: Invalid surrogate pair in encoding_utf16_to_utf32.\n");
                    free(output);
                    return NULL;
                }
            }
            else {
                printf("Error: Lone high surrogate without a low surrogate in encoding_utf16_to_utf32.\n");
                free(output);
                return NULL;
            }
        }
        output[j++] = ch;
    }

    // Null-terminate the output
    output[j] = 0;

    return output;
}

uint8_t* ma_encoding_utf16_to_utf8(const uint16_t* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encoding_utf16_to_utf8.\n");
        return NULL;
    }
    // Estimate maximum output size (4 bytes per UTF-16 character)
    size_t maxOutLength = length * 4;
    uint8_t* output = (uint8_t*)malloc(maxOutLength);
    if (!output) {
        printf("Error: Memory allocation failed in encoding_utf16_to_utf8.\n");
        return NULL;
    }

    const uint16_t* sourceStart = input;
    const uint16_t* sourceEnd = input + length;
    uint8_t* targetStart = output;
    uint8_t* targetEnd = output + maxOutLength;

    ConversionResult result = ConvertUTF16toUTF8(&sourceStart, sourceEnd, &targetStart, targetEnd, lenientConversion);

    if (result != conversionOK) {
        printf("Error: Conversion from UTF-16 to UTF-8 failed in encoding_utf16_to_utf8.\n");
        free(output);
        return NULL;
    }

    // Resize the output to the actual UTF-8 string length
    size_t actualLength = targetStart - output;
    uint8_t* resizedOutput = (uint8_t*)realloc(output, actualLength + 1);
    // if (resizedOutput) {
    //     resizedOutput[actualLength] = '\0';
    //     return resizedOutput;
    // }

    // return output;

    if (!resizedOutput) {
        printf("Error: Reallocation failed in encoding_utf16_to_utf8.\n");
        free(output);
        return NULL;
    }
    resizedOutput[actualLength] = '\0';

    return resizedOutput;
}

uint8_t* ma_encoding_utf32_to_utf8(const uint32_t* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encoding_utf32_to_utf8.\n");
        return NULL;
    }

    // Estimate maximum output size (4 bytes per UTF-32 character)
    size_t maxOutLength = length * 4;
    uint8_t* output = (uint8_t*)malloc(maxOutLength);
    if (!output) {
        printf("Error: Memory allocation failed in encoding_utf32_to_utf8.\n");
        return NULL;
    }

    const uint32_t* sourceStart = input;
    const uint32_t* sourceEnd = input + length;
    uint8_t* targetStart = output;
    uint8_t* targetEnd = output + maxOutLength;

    ConversionResult result = ConvertUTF32toUTF8(&sourceStart, sourceEnd, &targetStart, targetEnd, lenientConversion);

    if (result != conversionOK) {
        printf("Error: Conversion from UTF-32 to UTF-8 failed in encoding_utf32_to_utf8.\n");
        free(output);
        return NULL;
    }

    // Resize the output to the actual UTF-8 string length
    size_t actualLength = targetStart - output;
    uint8_t* resizedOutput = (uint8_t*)realloc(output, actualLength + 1);
    // if (resizedOutput) {
    //     resizedOutput[actualLength] = '\0';
    //     return resizedOutput;
    // }

    // return output;

    if (!resizedOutput) {
        printf("Error: Reallocation failed in encoding_utf32_to_utf8.\n");
        free(output);
        return NULL;
    }
    resizedOutput[actualLength] = '\0';

    return resizedOutput;
}

bool ma_encoding_is_utf8_string(const uint8_t** input, size_t length) {
    if (input == NULL || *input == NULL || length == 0) {
        printf("Error: Invalid input or length in encoding_is_utf8_string.\n");
        return false;
    }

    const uint8_t* source = *input;
    const uint8_t* sourceEnd = source + length;

    while (source < sourceEnd) {
        int trailLength = trailingBytesForUTF8[*source] + 1;
        if (trailLength > sourceEnd - source || !ma_encoding_is_utf8(source, trailLength)) {
            printf("Error: Invalid UTF-8 encoding detected in encoding_is_utf8_string.\n");
            return false;
        }
        source += trailLength;
    }

    *input = source; // Update the input pointer to the end of the string
    return true;
}

uint16_t* ma_encoding_utf8_to_utf16(const uint8_t* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encoding_utf8_to_utf16.\n");
        return NULL;
    }
    // Estimate maximum output size (each UTF-8 character can be at most 4 bytes,
    // but can translate to at most 2 UTF-16 characters)
    size_t maxOutLength = length * 2;
    uint16_t* output = (uint16_t*)malloc(maxOutLength * sizeof(uint16_t));
    if (!output) {
        printf("Error: Memory allocation failed for output in encoding_utf8_to_utf16.\n");
        return NULL;
    }

    const uint8_t* sourceStart = input;
    const uint8_t* sourceEnd = input + length;
    uint16_t* targetStart = output;
    uint16_t* targetEnd = output + maxOutLength;

    ConversionResult result = ConvertUTF8toUTF16(&sourceStart, sourceEnd, &targetStart, targetEnd, lenientConversion);

    if (result != conversionOK) {
        printf("Error: Conversion from UTF-8 to UTF-16 failed in encoding_utf8_to_utf16.\n");
        free(output);
        return NULL;
    }
    // Resize the output to the actual UTF-16 string length
    size_t actualLength = targetStart - output;
    uint16_t* resizedOutput = (uint16_t*)realloc(output, actualLength * sizeof(uint16_t) + 1);
    if (!resizedOutput) {
        printf("Error: Reallocation failed in encoding_utf8_to_utf16.\n");
        free(output);
        return NULL;
    }
    resizedOutput[actualLength] = '\0'; // Null-terminate the UTF-16 string

    return resizedOutput;
}

uint32_t* ma_encoding_utf8_to_utf32(const uint8_t* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encododing_utf8_to_utf32.\n");
        return NULL;
    }

    // Estimate maximum output size (each UTF-8 character can be at most 4 bytes,
    // translating to a single UTF-32 character)
    size_t maxOutLength = length;
    uint32_t* output = (uint32_t*)malloc(maxOutLength * sizeof(uint32_t));
    if (!output) {
        printf("Error: Can not Allocate memory in encoding_utf8_to_utf32.\n");
        return NULL; // Memory allocation failed
    }

    const uint8_t* sourceStart = input;
    const uint8_t* sourceEnd = input + length;
    uint32_t* targetStart = output;
    uint32_t* targetEnd = output + maxOutLength;

    ConversionResult result = ConvertUTF8toUTF32(&sourceStart, sourceEnd, &targetStart, targetEnd, lenientConversion);

    if (result != conversionOK) {
        printf("Error: Failed Convertion to UTF32 in encoding_utf8_to_utf32.\n");
        free(output);
        return NULL;
    }

    // Resize the output to the actual UTF-32 string length
    size_t actualLength = targetStart - output;
    uint32_t* resizedOutput = (uint32_t*)realloc(output, (actualLength + 1) * sizeof(uint32_t));
    if (resizedOutput) {
        resizedOutput[actualLength] = 0; // Null-terminate the UTF-32 string
        return resizedOutput;
    }
    return output;
}

void encoding_hex_dump(const void *data, size_t size) {
    const unsigned char *byte = (const unsigned char *)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i); // Print the offset

        // Print hex values
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02x ", byte[i + j]);
            } else {
                printf("   "); // Fill space if less than 16 bytes in a line
            }
        }
        printf(" |");

        // Print ASCII representation
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%c", isprint(byte[i + j]) ? byte[i + j] : '.');
            }
        }
        printf("|\n");
    }
}

char* ma_encododing_base85_encode(const uint8_t* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encododing_base85_encode.\n");
        return NULL;
    }

    // Calculate the maximum possible length of the encoded string
    size_t encoded_max_length = ((length + 3) / 4) * 5 + 2; // +2 for potential padding and null terminator
    char* encoded = malloc(encoded_max_length);
    if (!encoded) {
        printf("Error: Memory allocation failed for encoded string in encododing_base85_encode.\n");
        return NULL;
    }

    size_t input_index = 0;
    size_t encoded_index = 0;
    while (input_index < length) {
        uint32_t acc = 0;
        size_t chunk_len = (length - input_index < 4) ? (length - input_index) : 4;

        for (size_t i = 0; i < chunk_len; ++i) {
            acc = (acc << 8) | input[input_index++];
        }

        if (chunk_len < 4) {
            acc <<= (4 - chunk_len) * 8; // Padding
        }
        if (acc == 0 && chunk_len == 4) {
            encoded[encoded_index++] = 'z';
        }
        else {
            for (int i = 4; i >= 0; --i) {
                encoded[encoded_index + i] = (acc % 85) + 33;
                acc /= 85;
            }
            encoded_index += 5;

            if (chunk_len < 4) {
                encoded_index -= (4 - chunk_len);  // Adjust for padding
                break;
            }
        }
    }

    encoded[encoded_index] = '\0';

    return encoded;
}

uint8_t* ma_encododing_base85_decode(const char* input, size_t length) {
    if (input == NULL || length == 0) {
        printf("Error: Invalid input or length in encododing_base85_decode.\n");
        return NULL;
    }

    // Calculate the maximum possible length of the decoded string
    size_t decoded_max_length = (length / 5) * 4;
    uint8_t* decoded = malloc(decoded_max_length);
    if (!decoded) {
        printf("Error: Memory allocation failed for decoded string in encododing_base85_decode.\n");
        return NULL;
    }

    size_t input_index = 0;
    size_t decoded_index = 0;
    while (input_index < length) {
        if (isspace(input[input_index])) {
            input_index++;   // Skip whitespace
            continue;
        }
        if (input[input_index] == 'z') {
            // Special case: 'z' represents four zero bytes
            memset(decoded + decoded_index, 0, 4);
            decoded_index += 4;
            input_index++;
            continue;
        }

        uint32_t acc = 0;
        int count = 0;
        for (int i = 0; i < 5 && input_index < length; ++i) {
            if (isspace(input[input_index])) {
                // Skip whitespace within the group
                input_index++;
                continue;
            }

            char ch = input[input_index++];
            if (ch < 33 || ch > 117) {
                printf("Error: Invalid character encountered in encododing_base85_decode.\n");
                free(decoded);
                return NULL; // Invalid character
            }

            acc = acc * 85 + (ch - 33);
            count++;
        }

        int padding = 0;
        if (count < 5) {
            padding = 5 - count;
            for (int i = 0; i < padding; i++) {
                acc = acc * 85 + 84; // Assume 'u' for padding, which is the highest value (84)
            }
        }

        for (int i = 3; i >= 0; --i) {
            if (i < padding) {
                break; // Ignore padding bytes
            }
            decoded[decoded_index++] = (acc >> (i * 8)) & 0xFF;
        }

        if (count < 5) {
            break; // End of data
        }
    }

    // Resize the output buffer to the actual decoded data length
    uint8_t* resized_decoded = realloc(decoded, decoded_index + 1); // +1 for null terminator, if needed
    if (!resized_decoded) {
        printf("Error: Reallocation failed in encododing_base85_decode.\n");
        free(decoded);
        return NULL;
    }

    resized_decoded[decoded_index] = '\0'; // Null-terminate if treating as a C-style string

    return resized_decoded;
}

char* ma_encoding_base58_encode(const void *data, size_t binsz) {
    if (!data) {
        printf("Error: Invalid input data in encoding_base58_encode.\n");
        return NULL;
    }

    const uint8_t *bin = data;
    int carry;
    size_t i, j, high, zcount = 0;
    size_t size;

    while (zcount < binsz && !bin[zcount]) {
        ++zcount;
    }

    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t *buf = malloc(size * sizeof(uint8_t));
    if (!buf) {
        printf("Error: Memory allocation failed for buffer in encoding_base58_encode.\n");
        return NULL;
    }
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
        for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;

            if (!j) {
                break;
            }
        }
    }

    for (j = 0; j < size && !buf[j]; ++j) {
        // Skip leading zeros in binary
    }

    size_t b58sz = zcount + size - j + 1;
    char *b58 = malloc(b58sz);
    if (!b58) {
        printf("Error: Memory allocation failed for Base58 encoding in encoding_base58_encode.\n");
        free(buf);
        return NULL;
    }
    if (zcount) {
        memset(b58, '1', zcount);
    }
    for (i = zcount; j < size; ++i, ++j) {
        b58[i] = b58digits_ordered[buf[j]];
    }
    b58[i] = '\0';

    free(buf);

    return b58;
}

char* ma_encoding_base58_decode(const char *b58, size_t *binszp) {
    if (b58 == NULL || binszp == NULL) {
        printf("Error: Invalid input or binszp pointer in encoding_base58_decode.\n");
        return NULL;
    }

    size_t b58sz = strlen(b58);
    size_t binsz = b58sz * 733 / 1000 + 1; // Rough estimate of binary size
    uint8_t *bin = malloc(binsz);
    if (!bin) {
        printf("Error: Memory allocation failed in encoding_base58_decode.\n");
        return NULL;
    }
    memset(bin, 0, binsz);

    size_t i, j;
    int carry;
    size_t high = binsz - 1;

    // Process the Base58 string
    for (i = 0; i < b58sz; ++i) {
        if (b58[i] & 0x80 || b58digits_map[(unsigned char)b58[i]] == -1) {
            printf("Error: Invalid Base58 character encountered in encoding_base58_decode.\n");
            free(bin);
            return NULL; // Invalid Base58 character
        }

        for (carry = b58digits_map[(unsigned char)b58[i]], j = binsz - 1; (j > high) || carry; --j) {
            carry += 58 * bin[j];
            bin[j] = carry % 256;
            carry /= 256;

            if (!j) {
                break; // Avoid wraparound
            }
        }
        high = j;
    }

    for (j = 0; j < binsz && !bin[j]; ++j) {
        // Skip leading zeros in binary
    }

    *binszp = binsz - j;
    char *result = malloc(*binszp);

    if (!result) {
        printf("Error: Memory allocation failed for result in encoding_base58_decode.\n");
        free(bin);
        return NULL;
    }
    memcpy(result, bin + j, *binszp);

    free(bin);
    return result;
}

uint8_t* ma_encoding_base91_decode(const char* encoded, size_t* decoded_length) {
    if (!encoded || !decoded_length) {
        printf("Error: Invalid input or decoded_length pointer in encoding_base91_decode.\n");
        return NULL;
    }

    size_t len = strlen(encoded);
    *decoded_length = 0;
    uint8_t* decoded = malloc(len); // Max possible size
    if (!decoded) {
        printf("Error: Memory allocation failed in encoding_base91_decode.\n");
        return NULL;
    }

    int v = -1;
    int b = 0;
    int n = 0;
    size_t index = 0;

    for (size_t i = 0; i < len; ++i) {
        int c = base91_decode_value(encoded[i]);
        if (c == -1) {
            printf("Error: Invalid character encountered in encoding_base91_decode.\n");
            free(decoded);
            return NULL; // Invalid character
        }

        if (v < 0) {
            v = c;
        }
        else {
            v += c * 91;
            b |= v << n;
            n += (v & 8191) > 88 ? 13 : 14;

            while (n > 7) {
                decoded[index++] = (uint8_t)(b & 255);
                b >>= 8;
                n -= 8;
            }
            v = -1;
        }
    }

    if (v != -1) {
        if (index >= len) {
            printf("Error: Decoded index out of bounds in encoding_base91_decode.\n");
            free(decoded);
            return NULL;
        }
        decoded[index++] = (uint8_t)((b | v << n) & 255);
    }

    *decoded_length = index;

    return decoded;
}

char* ma_encoding_base91_encode(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        printf("Error: Invalid input data or length in encoding_base91_encode.\n");
        return NULL;
    }

    size_t estimated_length = length * 1.23 + 2; // +2 for padding and null terminator
    char* encoded = malloc(estimated_length);
    if (!encoded) {
        printf("Error: Memory allocation failed in encoding_base91_encode.\n");
        return NULL;
    }

    size_t index = 0;
    int b = 0;
    int n = 0;
    int v;

    for (size_t i = 0; i < length; ++i) {
        b |= (data[i] << n);
        n += 8;

        if (n > 13) {
            v = b & 8191;

            if (v > 88) {
                b >>= 13;
                n -= 13;
            }
            else {
                v = b & 16383;
                b >>= 14;
                n -= 14;
            }

            if (index + 2 < estimated_length) {
                encoded[index++] = BASE91_ALPHABET[v % 91];
                encoded[index++] = BASE91_ALPHABET[v / 91];
            }
            else {
                printf("Error: Encoding index out of bounds in encoding_base91_encode.\n");
                free(encoded);
                return NULL;
            }
        }
    }

    if (n) {
        if (index + 1 < estimated_length) {
            encoded[index++] = BASE91_ALPHABET[b % 91];
        }
        if (n > 7 || b > 90) {
            if (index + 1 < estimated_length) {
                encoded[index++] = BASE91_ALPHABET[b / 91];
            }
        }
    }

    encoded[index] = '\0';

    return encoded;
}

#if defined(_WIN32) || defined(_WIN64)
    // Function to convert UTF-8 string to wchar_t string (Windows only)
    wchar_t* encoding_utf8_to_wchar(const char* utf8Str) {
        if (utf8Str == NULL) {
            printf("Error: Input string is NULL\n");
            return NULL;
        }

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, NULL, 0);
        if (size_needed == 0) {
        printf("Error: MultiByteToWideChar failed to calculate size. Error: %lu\n", GetLastError());
            return NULL;
        }

        wchar_t* wstr = (wchar_t*)malloc(size_needed * sizeof(wchar_t));
        if (!wstr) {
            printf("Error: Cannot allocate memory for wchar\n");
            return NULL;
        }

        int result = MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, wstr, size_needed);
        if (result == 0) {
            printf("Error: Conversion from UTF-8 to wchar failed\n");
            free(wstr);
            return NULL;
        }

        return wstr;
    }

    char* ma_encoding_wchar_to_utf8(const wchar_t* wstr) {
        if (wstr == NULL) {
            printf("Error: Input wchar string is NULL\n");
            return NULL;
        }

        // Get the length of the required buffer
        int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
        if (utf8Length == 0) {
            printf("Error: WideCharToMultiByte failed to calculate length\n");
            return NULL;
        }

        char* utf8Str = malloc(utf8Length * sizeof(char));
        if (!utf8Str) {
            printf("Error: Cannot allocate memory for UTF-8 string\n");
            return NULL;
        }
        // Convert the wide-character string to UTF-8
        if (WideCharToMultiByte(CP_UTF8, 0, wstr, -1, utf8Str, utf8Length, NULL, NULL) == 0) {
            printf("Error: Conversion from wchar to UTF-8 failed\n");
            free(utf8Str);
            return NULL;
        }

        return utf8Str;
    }
#endif

void ma_encoding_initialize(void) {
    setlocale(LC_ALL, "");
}

// ------------------------------------------------------------------------- //
//                              String                                       //
// ------------------------------------------------------------------------- //

const char* STRING_ASCII_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char* STRING_ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const char* STRING_ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char* STRING_DIGITS = "0123456789";
const char* STRING_HEXDIGITS = "0123456789abcdefABCDEF";
const char* STRING_WHITESPACE = " \t\n\r\f\v";
const char* STRING_PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

MemoryPoolString* global_pool = NULL;
bool memoryPoolCreated = false;

void ma_string_init_global_memory_pool(size_t size) {
    if (global_pool == NULL) {
        global_pool = ma_string_memory_pool_create(size);
        memoryPoolCreated = true;
    }
}

void ma_string_destroy_global_memory_pool() {
    if (global_pool != NULL && memoryPoolCreated) {
        ma_string_memory_pool_destroy(global_pool);
        global_pool = NULL;
    }
}

MemoryPoolString* ma_string_memory_pool_create(size_t size) {
    MemoryPoolString *pool = malloc(sizeof(MemoryPoolString));
    if (pool) {
        pool->pool = malloc(size);
        if (!pool->pool) {
            free(pool);
            return NULL;
        }

        pool->poolSize = size;
        pool->used = 0;
    }
    return pool;
}

void* ma_string_memory_pool_allocate(MemoryPoolString *pool, size_t size) {
    if (pool == NULL) {
        printf("Error: Memory pool is NULL in memory_pool_allocate.\n");
        return NULL;
    }
    if (pool->used + size > pool->poolSize) {
        printf("Error: Memory pool out of memory in memory_pool_allocate.\n");
        return NULL; // Pool is out of memory
    }

    void *mem = (char *)pool->pool + pool->used;
    pool->used += size;

    return mem;
}

void ma_string_memory_pool_destroy(MemoryPoolString *pool) {
    if (pool == NULL) {
        printf("Warning: Attempt to destroy a NULL memory pool in memory_pool_destroy.\n");
        return;
    }
    free(pool->pool);
    free(pool);
}

//static const char *base64_chars =
//    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
//    "abcdefghijklmnopqrstuvwxyz"
//    "0123456789+/";


String* ma_string_create(const char* initialStr) {
    String* str = (String*)malloc(sizeof(String));
    if (!str) {
        printf("Error: Memory allocation failed for String object in string_create.\n");
        exit(-1);
    }

    size_t initialSize = initialStr ? strlen(initialStr) : 0;
    str->size = initialSize;
    str->capacitySize = 32 + initialSize; // +1 for null terminator

    // Initialize memory pool for strings with a smaller size
    size_t initialPoolSize = 1000000; // 1KB
    str->pool = ma_string_memory_pool_create(initialPoolSize);
    if (!str->pool) {
        printf("Error: Memory pool creation failed in string_create.\n");
        free(str);
        exit(-1);
    }

    str->dataStr = ma_string_memory_pool_allocate(str->pool, str->capacitySize);
    if (!str->dataStr) {
        printf("Error: Memory pool allocation failed in string_create.\n");
        ma_string_memory_pool_destroy(str->pool);
        free(str);
        exit(-1);
    }

    if (initialStr) {
        strcpy(str->dataStr, initialStr);
    }
    return str;
}

String* ma_string_create_with_pool(size_t size) {
    static int counter = 0;

    if (!counter) {
        ma_string_init_global_memory_pool(size);
        counter++;
    }
    // Ensure global memory pool is initialized
    if (global_pool == NULL) {
        printf("Error: Failed to initialize global memory pool in string_create_with_pool.\n");
        exit(-1);  // Consider handling the error without exiting
    }

    String* str = (String*)malloc(sizeof(String));
    if (!str) {
        printf("Error: Memory allocation failed for String object in string_create_with_pool.\n");
        exit(-1);
    }

    str->size = 0;
    str->capacitySize = 1;
    str->dataStr = NULL; // Data is not allocated yet (lazy allocation)
    str->pool = global_pool; // Use the global pool

    return str;
}

String* ma_string_substr(String* str, size_t pos, size_t len) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_substr.\n");
        return NULL;
    }
    if (pos >= str->size) {
        printf("Error: Position out of bounds in string_substr.\n");
        return NULL;
    }

    // Adjust len if it goes beyond the end of the string
    if (pos + len > str->size) {
        len = str->size - pos;
    }

    String* substr = ma_string_create(NULL); // Allocate memory for the substring
    if (substr == NULL) {
        printf("Error: Memory allocation failed for substring in string_substr.\n");
        return NULL;
    }

    substr->size = len;
    substr->capacitySize = len + 1;
    substr->dataStr = (char*)malloc(substr->capacitySize * sizeof(char));

    if (substr->dataStr == NULL) {
        printf("Error: Memory allocation failed for dataStr in substring in string_substr.\n");
        free(substr);
        return NULL;
    }

    strncpy(substr->dataStr, str->dataStr + pos, len); // Copy the substring
    substr->dataStr[len] = '\0';  // Null terminate the substring

    return substr;
}

bool ma_string_empty(String* str) {
    return (str == NULL) ? true : (str->size == 0);
}

bool ma_string_contains(String* str, const char* substr) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_contains.\n");
        return false;
    }
    if (substr == NULL) {
        printf("Error: The substring is NULL in string_contains.\n");
        return false;
    }
    return strstr(str->dataStr, substr) != NULL;
}

int ma_string_compare(const String* str1, const String* str2) {
    if (str1 == NULL || str2 == NULL) {
        if (str1 == str2) {
            return 0;  // Both are NULL, considered equal
        }
        printf("Error: One or both String objects are NULL in string_compare.\n");
        return (str1 == NULL) ? -1 : 1;  // NULL is considered less than non-NULL
    }
    return strcmp(str1->dataStr, str2->dataStr);
}

bool ma_string_is_equal(String* str1, String* str2) {
    return ma_string_compare(str1, str2) == 0;
}

bool ma_string_is_less(String* str1, String* str2) {
    return ma_string_compare(str1, str2) < 0;
}

bool ma_string_is_greater(String* str1, String* str2) {
    return ma_string_compare(str1, str2) > 0;
}

bool ma_string_is_less_or_equal(String* str1, String* str2) {
    return ma_string_compare(str1, str2) <= 0;
}

bool ma_string_is_greater_or_equal(String* str1, String* str2) {
    return ma_string_compare(str1, str2) >= 0;
}

bool ma_string_is_not_equal(String* str1, String* str2) {
    return ma_string_compare(str1, str2) != 0;
}

bool ma_string_is_alpha(String* str) {
    if (str != NULL){
        for (size_t index = 0; index < str->size; index++){
            if (!(str->dataStr[index] >= 'a' && str->dataStr[index] <= 'z') &&
                !(str->dataStr[index] >= 'A' && str->dataStr[index] <= 'Z')) {
                return false;
            }
        }
        return true;
    }

    return false;
}

bool ma_string_is_digit(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_is_digit.\n");
        return false;
    }

    for (size_t index = 0; index < str->size; index++) {
        if (!(str->dataStr[index] >= '0' && str->dataStr[index] <= '9')) {
            return false;
        }
    }

    return true;
}

bool ma_string_is_upper(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_is_upper.\n");
        return false;
    }
    for (size_t index = 0; index < str->size; index++) {
        if (str->dataStr[index] >= 'a' && str->dataStr[index] <= 'z') {
            return false;
        }
    }
    return true;
}

bool ma_string_is_lower(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_is_lower.\n");
        return false;
    }
    for (size_t index = 0; index < str->size; index++) {
        if (str->dataStr[index] >= 'A' && str->dataStr[index] <= 'Z') {
            return false;
        }
    }
    return true;
}

void ma_string_reverse(String* str) {
    if (str != NULL && str->dataStr != NULL) {
        char* reverse = (char*) malloc(sizeof(char) * (str->size + 1));
        if (!reverse) {
            printf("Error: Memory allocation failed in string_reverse.\n");
            return;
        }

        for (int index = str->size - 1, j = 0; index >= 0; index--, j++) {
            reverse[j] = str->dataStr[index];
        }
        reverse[str->size] = '\0';
        ma_string_replace(str, ma_string_c_str(str), reverse);

        free(reverse);
    }
    else {
        printf("Error: The String object or its data is NULL in string_reverse.\n");
        return;
    }
}

void ma_string_resize(String *str, size_t newSize) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_resize.\n");
        return;
    }
    if (newSize < str->size) {
        str->size = newSize;
        str->dataStr[newSize] = '\0';
    }
    else if (newSize > str->size) {
        if (newSize >= str->capacitySize) {
            size_t newCapacity = newSize + 1;
            char *newData = ma_string_memory_pool_allocate(str->pool, newCapacity);

            if (!newData) {
                printf("Error: Memory allocation failed in string_resize.\n");
                return;
            }
            memcpy(newData, str->dataStr, str->size);
            str->dataStr = newData;
            str->capacitySize = newCapacity;
        }

        memset(str->dataStr + str->size, '\0', newSize - str->size);
        str->size = newSize;
    }
}

void ma_string_shrink_to_fit(String *str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_shrink_to_fit.\n");
        return;
    }
    if (str->size + 1 == str->capacitySize) {
        return; // No need to shrink if already at optimal size
    }
    // Check if the string is using the memory pool
    if (str->dataStr != NULL) {
        // Allocate new space from the memory pool
        size_t newCapacity = str->size + 1; // +1 for null terminator
        char *newData = ma_string_memory_pool_allocate(str->pool, newCapacity);

        if (newData == NULL) {
            printf("Error: Memory allocation failed in string_shrink_to_fit.\n");
            return;
        }
        // Copy existing data to the new space
        memcpy(newData, str->dataStr, str->size);
        newData[str->size] = '\0'; // Null-terminate the string

        // Update the string's metadata
        str->dataStr = newData;
        str->capacitySize = newCapacity;
    }
}

void ma_string_append(String *str, const char *strItem) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_append.\n");
        return;
    }
    if (strItem == NULL) {
        printf("Error: The strItem is NULL in string_append.\n");
        return;
    }
    size_t strItemLength = strlen(strItem);
    if (strItemLength == 0) {
        return;
    }

    if (str->size + strItemLength >= str->capacitySize) {
        size_t newCapacity = str->size + strItemLength + 1;
        char *newData = ma_string_memory_pool_allocate(str->pool, newCapacity);

        if (!newData) {
            printf("Error: Memory allocation failed in string_append.\n");
            return;
        }

        memcpy(newData, str->dataStr, str->size);
        str->dataStr = newData;
        str->capacitySize = newCapacity;
    }

    strcpy(str->dataStr + str->size, strItem);
    str->size += strItemLength;
}

void ma_string_push_back(String* str, char chItem) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_push_back.\n");
        return;
    }
    if (str->size + 1 >= str->capacitySize) {
        // static int counter = 0;
        size_t newCapacity = str->capacitySize * 2;
        char* newData = ma_string_memory_pool_allocate(str->pool, newCapacity);  // Allocate new space from the memory pool

        if (!newData) {
            printf("Error: Memory allocation failed in string_push_back.\n");
            return;
        }

        // Copy existing string to the new space
        if (str->dataStr) {
            memcpy(newData, str->dataStr, str->size);
        }
        str->dataStr = newData;
        str->capacitySize = newCapacity;
    }
    // Append the character
    str->dataStr[str->size] = chItem;
    str->size++;
    str->dataStr[str->size] = '\0'; // Null-terminate the string
}

void ma_string_assign(String *str, const char *newStr) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_assign.\n");
        return;
    }
    if (newStr == NULL) {
        printf("Error: The newStr is NULL in string_assign.\n");
        return;
    }

    size_t newStrLength = strlen(newStr);
    if (newStrLength + 1 > str->capacitySize) {
        char *newData = ma_string_memory_pool_allocate(str->pool, newStrLength + 1);
        if (!newData) {
            printf("Error: Memory allocation failed in string_assign.\n");
            return;
        }


        str->dataStr = newData;
        str->capacitySize = newStrLength + 1;
    }

    strcpy(str->dataStr, newStr);
    str->size = newStrLength;
}

void ma_string_insert(String *str, size_t pos, const char *strItem) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_insert.\n");
        return;
    }
    if (strItem == NULL) {
        printf("Error: The strItem is NULL in string_insert.\n");
        return;
    }
    if (pos > str->size) {
        printf("Error: Position out of bounds in string_insert.\n");
        return;
    }

    size_t strItemLength = strlen(strItem);
    size_t newTotalLength = str->size + strItemLength;

    if (newTotalLength + 1 > str->capacitySize) {
        size_t newCapacity = newTotalLength + 1;
        char *newData = ma_string_memory_pool_allocate(str->pool, newCapacity);
        if (!newData) {
            printf("Error: Memory allocation failed in string_insert.\n");
            return;
        }

        memcpy(newData, str->dataStr, pos);
        memcpy(newData + pos + strItemLength, str->dataStr + pos, str->size - pos);
        str->dataStr = newData;
        str->capacitySize = newCapacity;
    }
    else {
        memmove(str->dataStr + pos + strItemLength, str->dataStr + pos, str->size - pos);
    }

    memcpy(str->dataStr + pos, strItem, strItemLength);
    str->size = newTotalLength;
}

void ma_string_erase(String *str, size_t pos, size_t len) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_erase.\n");
        return;
    }
    if (pos >= str->size) {
        printf("Error: Position out of bounds in string_erase.\n");
        return;
    }
    if (pos + len > str->size) {
        len = str->size - pos;  // Adjust len to not go beyond the string end
    }

    memmove(str->dataStr + pos, str->dataStr + pos + len, str->size - pos - len + 1);
    str->size -= len;
}

void ma_string_replace(String *str1, const char *oldStr, const char *newStr) {
    if (str1 == NULL) {
        printf("Error: The String object (str1) is NULL in string_replace.\n");
        return;
    }
    if (oldStr == NULL) {
        printf("Error: The oldStr is NULL in string_replace.\n");
        return;
    }
    if (newStr == NULL) {
        printf("Error: The newStr is NULL in string_replace.\n");
        return;
    }

    char *position = strstr(str1->dataStr, oldStr);
    if (position == NULL) {
        printf("Warning: oldStr not found in str1 in string_replace.\n");
        return;  // oldStr not found in str1
    }

    size_t oldLen = strlen(oldStr);
    size_t newLen = strlen(newStr);
    size_t tailLen = strlen(position + oldLen);
    size_t newSize = (position - str1->dataStr) + newLen + tailLen;

    if (newSize + 1 > str1->capacitySize) {
        size_t newCapacity = newSize + 1;
        char *newData = ma_string_memory_pool_allocate(str1->pool, newCapacity);
        if (!newData) {
            return;  // Handle allocation error
        }

        memcpy(newData, str1->dataStr, position - str1->dataStr);
        memcpy(newData + (position - str1->dataStr) + newLen, position + oldLen, tailLen);
        str1->dataStr = newData;
        str1->capacitySize = newCapacity;
    }
    else {
        memmove(position + newLen, position + oldLen, tailLen);
    }
    memcpy(position, newStr, newLen);
    str1->size = newSize;
}

void ma_string_swap(String *str1, String *str2) {
    if (str1 == NULL || str2 == NULL) {
        printf("Error: One or both String objects are NULL in string_swap.\n");
        return;
    }

    String temp = *str1;
    *str1 = *str2;
    *str2 = temp;
}

void ma_string_pop_back(String *str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_pop_back.\n");
        return;
    }

    if (str->size == 0) {
        printf("Warning: Attempt to pop back from an empty string in string_pop_back.\n");
        return;
    }

    str->dataStr[str->size - 1] = '\0';
    str->size--;
}

void ma_string_deallocate(String *str) {
    if (str == NULL) {
        printf("Warning: Attempt to deallocate a NULL String object in string_deallocate.\n");
        return;
    }
    // Destroy the memory pool associated with the string
    if (str->pool != NULL) {
        ma_string_memory_pool_destroy(str->pool);
        str->pool = NULL;
    }
    // Since dataStr is managed by the memory pool, no separate free call is needed for it
    free(str);
    if (memoryPoolCreated) {
        ma_string_destroy_global_memory_pool();
    }
}

char ma_string_at(String* str, size_t index) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_at.\n");
        return '\0';  // Return a default character
    }

    if (index >= str->size) {
        printf("Error: Index out of range in string_at.\n");
        return '\0';  // Return a default character
    }

    return str->dataStr[index]; // (const char)
}

char* ma_string_back(String *str) {
    if (str == NULL || str->size == 0) {
        return NULL;
    }

    return &str->dataStr[str->size - 1];
}

char* ma_string_front(String *str) {
    if (str == NULL || str->size == 0) {
        return NULL;
    }

    return &str->dataStr[0];
}

size_t ma_string_length(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_length.\n");
        return 0;
    }

    return str->size;
}

size_t ma_string_capacity(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_capacity.\n");
        return 0;
    }

    return str->capacitySize;
}

size_t ma_string_max_size(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_max_size.\n");
        return 0;  // Or a special value indicating error
    }

    return (size_t)-1;  // You may want to define a more realistic maximum size
}


size_t ma_string_copy(String *str, char *buffer, size_t pos, size_t len) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: The String object or its data is NULL in string_copy.\n");
        return 0;
    }

    if (buffer == NULL) {
        printf("Error: The buffer is NULL in string_copy.\n");
        return 0;
    }

    if (pos >= str->size) {
        printf("Error: Position out of bounds in string_copy.\n");
        return 0;
    }

    size_t copyLen = len;
    if (pos + len > str->size || len == 0) {
        copyLen = str->size - pos;  // Adjust copy length if it goes beyond the string end
    }

    strncpy(buffer, str->dataStr + pos, copyLen);
    buffer[copyLen] = '\0';

    return copyLen;  // Return the number of characters copied
}

int ma_string_find(String *str, const char *buffer, size_t pos) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: The String object or its data is NULL in string_find.\n");
        return -1;
    }

    if (buffer == NULL) {
        printf("Error: The buffer is NULL in string_find.\n");
        return -1;
    }

    if (pos >= str->size) {
        printf("Error: Position out of bounds in string_find.\n");
        return -1;
    }

    const char *found = strstr(str->dataStr + pos, buffer);
    if (found == NULL) {
        return -1;  // Substring not found
    }

    return (int)(found - str->dataStr);  // Return the position of the substring
}

int ma_string_rfind(String *str, const char *buffer, size_t pos) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: The String object or its data is NULL in string_rfind.\n");
        return -1;
    }

    if (buffer == NULL) {
        printf("Error: The buffer is NULL in string_rfind.\n");
        return -1;
    }

    size_t bufferLen = strlen(buffer);
    if (bufferLen == 0) {
        printf("Error: The buffer is empty in string_rfind.\n");
        return -1;
    }

    if (pos < bufferLen - 1) {
        printf("Error: Position is too small in string_rfind.\n");
        return -1;
    }

    pos = (pos < str->size) ? pos : str->size - 1;  // Adjust pos to be within bounds
    for (int i = (int)pos; i >= 0; --i) {
        if (strncmp(str->dataStr + i, buffer, bufferLen) == 0) {
            return i;  // Found the substring
        }
    }

    return -1;  // Substring not found
}

int ma_string_find_first_of(String *str, const char *buffer, size_t pos) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: The String object or its data is NULL in string_find_first_of.\n");
        return -1;
    }

    if (buffer == NULL) {
        printf("Error: The buffer is NULL in string_find_first_of.\n");
        return -1;
    }

    if (pos >= str->size) {
        printf("Error: Position out of bounds in string_find_first_of.\n");
        return -1;
    }

    const char *found = strstr(str->dataStr + pos, buffer);
    if (found != NULL) {
        return (int)(found - str->dataStr);
    }

    return -1;  // Buffer string not found
}

int ma_string_find_last_of(String *str, const char *buffer, size_t pos) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: The String object or its data is NULL in string_find_last_of.\n");
        return -1;
    }

    if (buffer == NULL) {
        printf("Error: The buffer is NULL in string_find_last_of.\n");
        return -1;
    }

    if (pos >= str->size) {
        printf("Error: Position out of bounds in string_find_last_of.\n");
        return -1;
    }

    int lastFound = -1;
    const char *currentFound = strstr(str->dataStr, buffer);

    while (currentFound != NULL && (size_t)(currentFound - str->dataStr) <= pos) {
        lastFound = (int)(currentFound - str->dataStr);
        currentFound = strstr(currentFound + 1, buffer);
    }

    return lastFound;
}

int ma_string_find_first_not_of(String *str, const char *buffer, size_t pos) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: The String object or its data is NULL in string_find_first_not_of.\n");
        return -1;
    }

    if (buffer == NULL) {
        printf("Error: The buffer is NULL in string_find_first_not_of.\n");
        return -1;
    }

    if (pos >= str->size) {
        printf("Error: Position out of bounds in string_find_first_not_of.\n");
        return -1;
    }

    size_t bufferLen = strlen(buffer);
    if (bufferLen == 0) {
        return (int)pos;  // If buffer is empty, return pos
    }

    for (size_t i = pos; i <= str->size - bufferLen; ++i) {
        if (strncmp(str->dataStr + i, buffer, bufferLen) != 0) {
            return (int)i;
        }
    }
    return -1;  // No non-matching position found
}

int ma_string_find_last_not_of(String *str, const char *buffer, size_t pos) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: The String object or its data is NULL in string_find_last_not_of.\n");
        return -1;
    }

    if (buffer == NULL) {
        printf("Error: The buffer is NULL in string_find_last_not_of.\n");
        return -1;
    }

    size_t bufferLen = strlen(buffer);
    if (bufferLen == 0) {
        printf("Error: The buffer is empty in string_find_last_not_of.\n");
        return -1;
    }
    if (pos < bufferLen - 1) {
        printf("Error: Position is too small in string_find_last_not_of.\n");
        return -1;
    }

    pos = (pos < str->size - bufferLen) ? pos : str->size - bufferLen;
    for (int i = (int)pos; i >= 0; --i) {
        if (strncmp(str->dataStr + i, buffer, bufferLen) != 0) {
            return i;
        }
    }
    return -1;
}

const char* ma_string_data(String *str) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: Invalid input or uninitialized String in string_data function.\n");
        return NULL;
    }

    return str->dataStr;
}

const char* ma_string_c_str(const String *str) {
    if (str == NULL) {
        printf("Error: Invalid input in string_c_str function.\n");
        return "";  // Return empty string for null String
    }

    if (str->dataStr == NULL) {
        printf("Error: Uninitialized String in string_c_str function.\n");
        return "";  // Return empty string for uninitialized String
    }

    return str->dataStr;
}

char* ma_string_begin(String *str) {
    if (str == NULL) {
        printf("Error: Invalid input in string_begin function.\n");
        return "";  // Return empty string for null String
    }

    if (str->dataStr == NULL) {
        printf("Error: Uninitialized String in string_begin function.\n");
        return "";  // Return empty string for uninitialized String
    }

    return str->dataStr;  // The beginning of the string
}

char* ma_string_end(String *str) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: Invalid input or uninitialized String in string_end function.\n");
        return NULL;  // Return NULL for null or uninitialized String
    }

    return str->dataStr + str->size;  // The end of the string
}

char* ma_string_rbegin(String *str) {
    if (str == NULL || str->dataStr == NULL || str->size == 0) {
        printf("Error: Invalid input, uninitialized, or empty String in string_rbegin function.\n");
        return NULL;
    }

    return str->dataStr + str->size - 1;
}

char* ma_string_rend(String *str) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: Invalid input or uninitialized String in string_rend function.\n");
        return NULL;
    }

    return str->dataStr - 1;
}

const char* ma_string_cbegin(String *str) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: Invalid input or uninitialized String in string_cbegin function.\n");
        return NULL;  // Return NULL for null or uninitialized String
    }

    return str->dataStr;  // The beginning of the string
}

const char* ma_string_cend(String *str) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: Invalid input or uninitialized String in string_cend function.\n");
        return NULL;  // Return NULL for null or uninitialized String
    }

    return str->dataStr + str->size;  // The end of the string
}

const char* ma_string_crbegin(String *str) {
    if (str == NULL || str->dataStr == NULL || str->size == 0) {
        printf("Error: Invalid input, uninitialized, or empty String in string_crbegin function.\n");
        return NULL;  // Return NULL for null, uninitialized, or empty String
    }

    return str->dataStr + str->size - 1;  // Pointer to the last character
}

const char* ma_string_crend(String *str) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: Invalid input or uninitialized String in string_crend function.\n");
        return NULL;  // Return NULL for null or uninitialized String
    }

    return str->dataStr - 1;  // Pointer to one before the first character
}

void ma_string_clear(String* str) {
    if (str != NULL) {
        str->size = 0;  // Reset the size to 0, indicating the string is now empty

        // Set the first character to the null terminator.
        // This ensures that the string is considered empty when accessed.
        if (str->dataStr != NULL) {
            str->dataStr[0] = '\0';
        }
    }
    printf("Info : String object is null no need to clear in string_clear.\n");
}

char* string_to_upper(String* str) {
    if (str != NULL) {
        char* upper = (char*) malloc(sizeof(char) * (str->size + 1));
        if (!upper) {
            printf("Error: Failed to allocate memory for string_to_upper function.\n");
            exit(-1);
        }

        for (size_t index = 0; index < str->size; index++) {
            if (isalpha(str->dataStr[index]) && (str->dataStr[index] >= 'a' && str->dataStr[index] <= 'z')) {
                upper[index] = toupper(str->dataStr[index]);
            }
            else {
                upper[index] = str->dataStr[index];
            }
        }
        upper[str->size] = '\0';
        return upper;
    }

    printf("Error: Input 'str' is NULL in string_to_upper function.\n");
    return NULL;
}

char* string_to_lower(String* str) {
    if (str != NULL) {
        char* lower = (char*) malloc(sizeof(char) * (str->size + 1));
        if (!lower) {
            printf("Error: Failed to allocate memory for string_to_lower function.\n");
            exit(-1);
        }

        for (size_t index = 0; index < str->size; index++) {
            if (isalpha(str->dataStr[index]) && (str->dataStr[index] >= 'A' && str->dataStr[index] <= 'Z')) {
                lower[index] = tolower(str->dataStr[index]);
            }
            else {
                lower[index] = str->dataStr[index];
            }
        }
        lower[str->size] = '\0';
        return lower;
    }

    printf("Error: Input 'str' is NULL in string_to_lower function.\n");
    return NULL;
}

bool ma_string_set_pool_size(String* str, size_t newSize) {
    if (!str) {
        printf("Error: Invalid input - 'str' is NULL in string_set_pool_size.\n");
        return false;
    }

    if (newSize == 0) {
        printf("Error: Invalid input - 'newSize' is zero in string_set_pool_size.\n");
        return false;
    }
    // If a memory pool already exists, destroy it first
    if (str->pool) {
        ma_string_memory_pool_destroy(str->pool);
        str->pool = NULL;
    }

    // Create a new memory pool with the specified size
    str->pool = ma_string_memory_pool_create(newSize);
    if (!str->pool) {
        printf("Error: Failed to create a new memory pool in string_set_pool_size.\n");
        return false; // Return false if memory pool creation fails
    }
    // If the string already has data, reallocate it in the new pool
    if (str->size > 0 && str->dataStr) {
        char* newData = ma_string_memory_pool_allocate(str->pool, str->size + 1); // +1 for null terminator
        if (!newData) {
            printf("Error: Failed to allocate memory for string data in the new pool in string_set_pool_size.\n");
            ma_string_memory_pool_destroy(str->pool);
            str->pool = NULL;
            return false; // Return false if allocation fails
        }
        memcpy(newData, str->dataStr, str->size);
        newData[str->size] = '\0';
        str->dataStr = newData;
    }
    return true; // Return true on successful pool resize
}

void ma_string_concatenate(String *str1, const String *str2) {
    if (str1 == NULL) {
        printf("Error: Null String object 'str1' in string_concatenate.\n");
        return;
    }

    if (str2 == NULL) {
        printf("Error: Null String object 'str2' in string_concatenate.\n");
        return;
    }
    ma_string_append(str1, str2->dataStr);
}

void ma_string_trim_left(String *str) {
    if (str == NULL) {
        printf("Error: Null String object in string_trim_left.\n");
        return;
    }
    if (str->size == 0) {
        return;
    }

    size_t i = 0;
    while (i < str->size && isspace((unsigned char)str->dataStr[i])) {
        i++;
    }

    if (i > 0) {
        memmove(str->dataStr, str->dataStr + i, str->size - i);
        str->size -= i;
        str->dataStr[str->size] = '\0';
    }
}

void ma_string_trim_right(String *str) {
    if (str == NULL) {
        printf("Error: Null String object in string_trim_right.\n");
        return;
    }
    if (str->size == 0) {
        return;
    }

    size_t i = str->size;
    while (i > 0 && isspace((unsigned char)str->dataStr[i - 1])) {
        i--;
    }

    if (i < str->size) {
        str->dataStr[i] = '\0';
        str->size = i;
    }
}

void ma_string_trim(String *str) {
    if (str == NULL) {
        printf("Error: Null String object in string_trim.\n");
        return;
    }

    ma_string_trim_left(str);
    ma_string_trim_right(str);
}

String** ma_string_split(String *str, const char *delimiter, int *count) {
    if (str == NULL) {
        printf("Error: Null String object in string_split.\n");
        return NULL;
    }
    if (delimiter == NULL) {
        printf("Error: Null delimiter in string_split.\n");
        return NULL;
    }

    size_t num_splits = 0;
    char *temp = ma_string_strdup(str->dataStr);
    if (temp == NULL) {
        printf("Error: Memory allocation failed in string_split.\n");
        return NULL;
    }

    char *token = strtok(temp, delimiter);

    while (token != NULL) {
        num_splits++;
        token = strtok(NULL, delimiter);
    }
    free(temp);

    if (num_splits == 0) {
        return NULL;
    }

    String** splits = malloc(sizeof(String*) * num_splits);
    if (splits == NULL) {
        printf("Error: Memory allocation failed for splits in string_split.\n");
        return NULL;
    }

    temp = ma_string_strdup(str->dataStr);
    if (temp == NULL) {
        printf("Error: Memory allocation failed in string_split.\n");
        free(splits);
        return NULL;
    }

    token = strtok(temp, delimiter);
    size_t index = 0;

    while (token != NULL && index < num_splits) {
        splits[index] = ma_string_create(token);

        if (splits[index] == NULL) {
            printf("Error: Failed to create string in string_split.\n");
            // Free previously allocated strings and array
            for (size_t i = 0; i < index; i++) {
                ma_string_deallocate(splits[i]); // Assuming string_free is defined
            }
            free(splits);
            free(temp);
            return NULL;
        }
        index++;
        token = strtok(NULL, delimiter);
    }
    free(temp);
    *count = num_splits;

    return splits;
}

String* ma_string_join(String **strings, int count, const char *delimiter) {
    if (strings == NULL) {
        printf("Error: Null string array in string_join.\n");
        return NULL;
    }

    if (count <= 0) {
        printf("Error: Invalid count in string_join.\n");
        return NULL;
    }

    if (delimiter == NULL) {
        printf("Error: Null delimiter in string_join.\n");
        return NULL;
    }

    String* result = ma_string_create("");
    if (result == NULL) {
        printf("Error: Memory allocation failed in string_join.\n");
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        ma_string_append(result, strings[i]->dataStr);
        if (i < count - 1) {
            ma_string_append(result, delimiter);
        }
    }
    return result;
}

void ma_string_replace_all(String *str, const char *oldStr, const char *newStr) {
    if (str == NULL) {
        printf("Error: Null String object in string_replace_all.\n");
        return;
    }

    if (oldStr == NULL || newStr == NULL) {
        printf("Error: Null substring in string_replace_all.\n");
        return;
    }

    String* temp = ma_string_create("");
    if (temp == NULL) {
        printf("Error: Memory allocation failed in string_replace_all.\n");
        return;
    }

    char *start = str->dataStr;
    char *end;

    while ((end = strstr(start, oldStr)) != NULL) {
        *end = '\0';
        ma_string_append(temp, start);
        ma_string_append(temp, newStr);
        start = end + strlen(oldStr);
    }

    ma_string_append(temp, start);
    ma_string_assign(str, temp->dataStr);
    ma_string_deallocate(temp);
}

int ma_string_to_int(String *str) {
    if (str == NULL) {
        printf("Error: Null String object in string_to_int.\n");
        return 0;
    }
    if (ma_string_empty(str)) {
        printf("Error: Empty string in string_to_int.\n");
        return 0;
    }
    return atoi(str->dataStr);
}

float ma_string_to_float(String *str) {
    if (str == NULL) {
        printf("Error: Null String object in string_to_float.\n");
        return 0.0f;
    }
    if (ma_string_empty(str)) {
        printf("Error: Empty string in string_to_float.\n");
        return 0.0f;
    }
    return atof(str->dataStr);
}

double ma_string_to_double(String* str) {
    if (str == NULL) {
        printf("Error: Null String object in string_to_double.\n");
        return 0.0;
    }
    if (ma_string_empty(str)) {
        printf("Error: Empty string in string_to_double.\n");
        return 0.0;
    }
    return strtod(str->dataStr, NULL);
}

void ma_string_pad_left(String *str, size_t totalLength, char padChar) {
    if (str == NULL) {
        printf("Error: Null String object in string_pad_left.\n");
        return;
    }
    if (str->size >= totalLength) {
        printf("Error: Size of String object is bigger or equal that total Length in string_pad_left.\n");
        return;
    }
    size_t padSize = totalLength - str->size;
    size_t newSize = str->size + padSize;
    char *newData = (char *)malloc(newSize + 1); // +1 for null terminator

    if (newData == NULL) {
        printf("Error: Failed to allocate memory in string_pad_left.\n");
        return;
    }

    memset(newData, padChar, padSize);
    memcpy(newData + padSize, str->dataStr, str->size);
    newData[newSize] = '\0';

    free(str->dataStr);
    str->dataStr = newData;
    str->size = newSize;
    str->capacitySize = newSize + 1;
}

void ma_string_pad_right(String *str, size_t totalLength, char padChar) {
    if (str == NULL) {
        printf("Error: Null String object in string_pad_right.\n");
        return;
    }
    if (str->size >= totalLength) {
        printf("Error: Size of String object is bigger or equal that total Length in string_pad_right.\n");
        return;
    }

    size_t padSize = totalLength - str->size;
    size_t newSize = str->size + padSize;
    char* newData = (char *)realloc(str->dataStr, newSize + 1); // +1 for null terminator

    if (newData == NULL) {
        printf("Error: Failed to allocate memory in string_pad_right.\n");
        return;
    }

    memset(newData + str->size, padChar, padSize);
    newData[newSize] = '\0';

    str->dataStr = newData;
    str->size = newSize;
    str->capacitySize = newSize + 1;
}

String* ma_string_to_hex(String *str) {
    if (str == NULL) {
        printf("Error: Null String object in string_to_hex.\n");
        return NULL;
    }
    if (ma_string_empty(str)) {
        return ma_string_create(""); // Return an empty string for an empty input.
    }

    String *hexStr = ma_string_create("");
    if (hexStr == NULL) {
        printf("Error: Memory allocation failed in string_to_hex.\n");
        return NULL;
    }

    for (size_t i = 0; i < str->size; ++i) {
        char buffer[3];  // Each char can be represented by max 2 hex digits + null terminator

        sprintf(buffer, "%02x", (unsigned char)str->dataStr[i]);
        ma_string_append(hexStr, buffer);
    }
    return hexStr;
}

String* ma_string_from_hex(String *hexStr) {
    if (hexStr == NULL) {
        printf("Error: Null String object in string_from_hex.\n");
        return NULL;
    }
    if (ma_string_empty(hexStr) || (hexStr->size % 2) != 0) {
        printf("Error: Invalid hex string in string_from_hex.\n");
        return NULL; // Hex string should have an even number of characters
    }

    String *str = ma_string_create("");
    if (str == NULL) {
        printf("Error: Memory allocation failed in string_from_hex.\n");
        return NULL;
    }

    for (size_t i = 0; i < hexStr->size; i += 2) {
        char buffer[3] = {hexStr->dataStr[i], hexStr->dataStr[i + 1], '\0'};
        char ch = (char)strtol(buffer, NULL, 16);

        ma_string_push_back(str, ch);
    }
    return str;
}

size_t ma_string_count(String* str, const char* substr) {
    if (str == NULL) {
        printf("Error: Null String object in string_count.\n");
        return 0;
    }
    if (substr == NULL) {
        printf("Error: Null substring in string_count.\n");
        return 0;
    }
    if (str->dataStr == NULL) {
        printf("Error: Null data string in String object in string_count.\n");
        return 0;
    }
    size_t count = 0;
    const char* temp = str->dataStr;
    const char* found;

    while ((found = strstr(temp, substr)) != NULL) {
        count++;
        temp = found + strlen(substr);
    }
    return count;
}

void ma_string_remove(String* str, const char* substr) {
    if (str == NULL) {
        printf("Error: Null String object in string_remove.\n");
        return;
    }
    if (substr == NULL) {
        printf("Error: Null substring in string_remove.\n");
        return;
    }
    if (str->dataStr == NULL) {
        printf("Error: Null data string in String object in string_remove.\n");
        return;
    }
    if (strlen(substr) == 0) {
        printf("Error: Empty substring in string_remove.\n");
        return;
    }
    size_t len = strlen(substr);
    char* p = str->dataStr;

    while ((p = strstr(p, substr)) != NULL) {
        memmove(p, p + len, strlen(p + len) + 1);
    }
}

void ma_string_remove_range(String* str, size_t startPos, size_t endPos) {
    if (str == NULL || str->dataStr == NULL) {
        printf("Error: Null String object in string_remove_range.\n");
        return;
    }
    if (startPos >= endPos || endPos > str->size) {
        printf("Error: Invalid range in string_remove_range.\n");
        return;
    }
    size_t length = endPos - startPos;

    memmove(str->dataStr + startPos, str->dataStr + endPos, str->size - endPos + 1); // +1 for null terminator
    str->size -= length;
}

String* ma_string_from_int(int value) {
    char buffer[12]; // Enough to hold any 32-bit integer
    sprintf(buffer, "%d", value);

    return ma_string_create(buffer);
}

char* ma_string_from_int_cstr(int value) {
    char buffer[12]; // Enough to hold any 32-bit integer
    sprintf(buffer, "%d", value);

    char* result = malloc(strlen(buffer) + 1); // +1 for null-terminator
    if (result) {
        strcpy(result, buffer);
    }

    return result;
}

String* ma_string_from_float(float value) {
    char buffer[32]; // A general buffer size for a float
    sprintf(buffer, "%f", value);

    return ma_string_create(buffer);
}

String* ma_string_from_double(double value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%f", value);

    return ma_string_create(buffer);
}

String** ma_string_tokenize(String* str, const char* delimiters, int* count) {
    if (str == NULL || delimiters == NULL) {
        printf("Error: Invalid input in string_tokenize.\n");
        return NULL;
    }

    size_t num_tokens = 0;
    char* temp_str = ma_string_strdup(str->dataStr); // strdup
    if (temp_str == NULL) {
        printf("Error: Memory allocation failed in string_tokenize.\n");
        return NULL;
    }

    char* token = strtok(temp_str, delimiters);

    while (token != NULL) {
        num_tokens++;
        token = strtok(NULL, delimiters);
    }

    free(temp_str);

    // Allocate array of String pointers
    String** tokens = malloc(num_tokens * sizeof(String*));
    if (tokens == NULL) {
        printf("Error: Memory allocation failed for tokens in string_tokenize.\n");
        return NULL;
    }

    // Tokenize again to fill the array
    temp_str = ma_string_strdup(str->dataStr);
    if (temp_str == NULL) {
        printf("Error: Memory allocation failed in string_tokenize.\n");
        free(tokens);
        return NULL;
    }

    token = strtok(temp_str, delimiters);
    size_t idx = 0;

    while (token != NULL && idx < num_tokens) {
        tokens[idx] = ma_string_create(token);
        if (tokens[idx] == NULL) {
            printf("Error: string_create failed in string_tokenize.\n");
            for (size_t i = 0; i < idx; ++i) {
                // Assuming a function to free String* is available
                ma_string_deallocate(tokens[i]);
            }
            free(tokens);
            free(temp_str);
            return NULL;
        }
        idx++;
        token = strtok(NULL, delimiters);
    }
    free(temp_str);
    *count = num_tokens;

    return tokens;
}

int ma_string_compare_ignore_case(String* str1, String* str2) {
    if (str1 == NULL || str2 == NULL) {
        if (str1 == str2) {
            return 0;
        }
        return (str1 == NULL) ? -1 : 1;
    }
    if (str1->dataStr == NULL || str2->dataStr == NULL) {
        if (str1->dataStr == str2->dataStr) {
            return 0; // Both dataStr are NULL, considered equal
        }
        return (str1->dataStr == NULL) ? -1 : 1; // One dataStr is NULL, the other is not
    }
    return strcasecmp(str1->dataStr, str2->dataStr);
}

String* ma_string_base64_encode(const String *input) {
    if (input == NULL) {
        printf("Error: The String object is NULL in string_baes64_encode.\n");
        return NULL;
    }
    if (input->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_base64_encode.\n");
        return NULL;
    }
    String *encoded = ma_string_create("");
    int val = 0, valb = -6;
    size_t i;

    for (i = 0; i < input->size; i++) {
        unsigned char c = input->dataStr[i];
        val = (val << 8) + c;
        valb += 8;

        while (valb >= 0) {
            ma_string_push_back(encoded, base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        ma_string_push_back(encoded, base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (encoded->size % 4) {
        ma_string_push_back(encoded, '=');
    }
    return encoded;
}

String* ma_string_base64_decode(const String* encodedStr) {
    if (encodedStr == NULL) {
        printf("Error: encodedStr param is null in string_base64_decode\n");
        return NULL;
    }

    if (encodedStr->dataStr == NULL) {
        printf("Error: dataStr item of encodedStr object is null in string_base64_decode\n");
        return NULL;
    }

    char* decodedStr = (char*)malloc(encodedStr->size * 3 / 4 + 1);

    if (decodedStr == NULL) {
        printf("Error: Failed to allocate memory for base64 decoding");
        return NULL;
    }

    int val = 0, valb = -8;
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < encodedStr->size; i++) {
        char c = encodedStr->dataStr[i];
        if (c == '=')
            break;

        if (c >= 'A' && c <= 'Z') {
            c -= 'A';
        } else if (c >= 'a' && c <= 'z') {
            c = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            c = c - '0' + 52;
        } else if (c == '+') {
            c = 62;
        } else if (c == '/') {
            c = 63;
        } else {
            continue;
        }

        val = (val << 6) | c;
        valb += 6;

        if (valb >= 0) {
            decodedStr[j++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    decodedStr[j] = '\0';

    String* decodedStringObject = ma_string_create(decodedStr);
    free(decodedStr);

    return decodedStringObject;
}

void ma_string_format(String* str, const char* format, ...) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_format.\n");
        return;
    }
    if (format == NULL) {
        printf("Error: The format string is NULL in string_format.\n");
        return;
    }
    // Start variadic argument processing
    va_list args;
    va_start(args, format);

    // Calculate the required length of the result string
    int length = vsnprintf(NULL, 0, format, args);
    if (length < 0) {
        printf("Error: vsnprintf failed in string_format.\n");
        va_end(args);
        return;
    }

    // Allocate memory for the formatted string
    char* buffer = (char*)malloc(length + 1);
    if (!buffer) {
        printf("Error: Failed to allocate memory in string_format.\n");
        va_end(args);
        return;
    }

    // Actually format the string
    vsnprintf(buffer, length + 1, format, args);

    // Assign the formatted string to the String object
    // Assuming you have a function like string_assign to replace the string's content
    ma_string_assign(str, buffer);

    // Clean up
    free(buffer);
    va_end(args);
}

String* ma_ma_string_repeat(const String* str, size_t count) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_repeat.\n");
        return NULL;
    }
    if (str->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_repeat.\n");
        return NULL;
    }

    size_t newLength = str->size * count;
    char* repeatedStr = (char*)malloc(newLength + 1);

    if (repeatedStr == NULL) {
        printf("Failed to allocate memory in string_repeat\n");
        return NULL;
    }

    char* current = repeatedStr;
    for (size_t i = 0; i < count; ++i) {
        memcpy(current, str->dataStr, str->size);
        current += str->size;
    }
    *current = '\0';

    String* result = ma_string_create(repeatedStr);
    free(repeatedStr);

    return result;
}

String* ma_string_join_variadic(size_t count, ...) {
    va_list args;
    va_start(args, count);

    size_t totalLength = 0;
    for (size_t i = 0; i < count; ++i) {
        String* str = va_arg(args, String*);
        totalLength += str->size;
    }
    va_end(args);

    char* joinedStr = (char*)malloc(totalLength + 1);
    if (joinedStr == NULL) {
        perror("Failed to allocate memory in string_join_variadic");
        return NULL;
    }

    char* current = joinedStr;
    va_start(args, count);
    for (size_t i = 0; i < count; ++i) {
        String* str = va_arg(args, String*);

        memcpy(current, str->dataStr, str->size);
        current += str->size;
    }
    *current = '\0';
    va_end(args);

    String* result = ma_string_create(joinedStr);
    free(joinedStr);

    return result;
}

void ma_string_trim_characters(String* str, const char* chars) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_trim_characters.\n");
        return;
    }
    if (str->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_trim_characters.\n");
        return;
    }
    if (chars == NULL) {
        printf("Error: The chars parameter is NULL in string_trim_characters.\n");
        return;
    }
    char* start = str->dataStr;
    char* end = str->dataStr + str->size - 1;

    while (start <= end && strchr(chars, *start)) {
        start++;
    }
    while (end > start && strchr(chars, *end)) {
        end--;
    }
    size_t newLength = end - start + 1;

    memmove(str->dataStr, start, newLength);
    str->dataStr[newLength] = '\0';
    str->size = newLength;
}

void ma_string_shuffle(String* str){
    if (str == NULL) {
        printf("Error: The String object is NULL in string_shuffle.\n");
        return;
    }
    if (str->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_shuffle.\n");
        return;
    }

    srand(time(NULL));
    size_t length = strlen(str->dataStr);
    for (size_t i = length - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);

        // Swap characters at positions i and j
        char temp = str->dataStr[i];
        str->dataStr[i] = str->dataStr[j];
        str->dataStr[j] = temp;
    }
}

void ma_string_to_title(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_to_title.\n");
        return;
    }
    if (str->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_to_title.\n");
        return;
    }

    bool capitalize = true;
    for (size_t i = 0; i < str->size; i++) {
        if (capitalize && isalpha(str->dataStr[i])) {
            str->dataStr[i] = toupper(str->dataStr[i]);
            capitalize = false;
        }
        else if (!isalpha(str->dataStr[i])) {
            capitalize = true;
        }
        else {
            str->dataStr[i] = tolower(str->dataStr[i]);
        }
    }
}

void ma_string_to_capitalize(String* str) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_to_capitalize.\n");
        return;
    }
    if (str->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_to_capitalize.\n");
        return;
    }
    if (str->size == 0) {
        printf("Error: The size of String object is zero in string_to_capitalize.\n");
        return;
    }
    str->dataStr[0] = toupper(str->dataStr[0]);
}

void ma_string_to_casefold(String* str) {
     if (str == NULL || str->dataStr == NULL) {
        printf("Error: Invalid string input in string_to_casefold.\n");
        return;
    }
    for (size_t i = 0; i < str->size; i++) {
        str->dataStr[i] = tolower(str->dataStr[i]);
    }
}

bool ma_string_starts_with(const String* str, const char* substr) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_starts_with.\n");
        return false;
    }
    if (str->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_starts_with.\n");
        return false;
    }
    if (substr == NULL) {
        printf("Error: The substring is NULL in string_starts_with.\n");
        return false;
    }

    size_t substrLen = strlen(substr);
    if (substrLen > str->size) {
        return false;
    }
    return strncmp(str->dataStr, substr, substrLen) == 0;
}

bool ma_string_ends_with(const String* str, const char* substr) {
    if (str == NULL) {
        printf("Error: The String object is NULL in string_ends_with.\n");
        return false;
    }
    if (str->dataStr == NULL) {
        printf("Error: The dataStr of String object is NULL in string_ends_with.\n");
        return false;
    }
    if (substr == NULL) {
        printf("Error: The substring is NULL in string_ends_with.\n");
        return false;
    }

    size_t substrLen = strlen(substr);
    size_t strLen = str->size;
    if (substrLen > strLen) {
        return false;
    }

    return strncmp(str->dataStr + strLen - substrLen, substr, substrLen) == 0;
}

void ma_string_swap_case(String* str) {
    if (str == NULL) {
        printf("Error: str is NULL in string_swap_case\n");
        return;
    }
    if (str->dataStr == NULL) {
        printf("Error: str->dataStr is NULL in string_swap_case\n");
        return;
    }

    for (size_t i = 0; i < str->size; i++) {
        if (islower(str->dataStr[i])) {
            str->dataStr[i] = toupper(str->dataStr[i]);
        }
        else if (isupper(str->dataStr[i])) {
            str->dataStr[i] = tolower(str->dataStr[i]);
        }
    }
}

wchar_t* ma_string_to_unicode(const char* str) {
    if (str == NULL) {
        printf("Error: Input string is NULL in string_to_unicode.\n");
        return NULL;
    }
    // Calculate the length of the wide string
    size_t len = mbstowcs(NULL, str, 0) + 1;
    if (len == (size_t)-1) {
        printf("Error: Conversion failed in string_to_unicode.\n");
        return NULL;
    }
    wchar_t* wstr = malloc(len * sizeof(wchar_t));
    if (!wstr) {
        printf("Error: Memory allocation failed in string_to_unicode.\n");
        return NULL;
    }

    mbstowcs(wstr, str, len);
    return wstr;
}

String* ma_string_from_unicode(const wchar_t* wstr) {
    if (wstr == NULL) {
        printf("Error: Input wide string is NULL in string_from_unicode.\n");
        return NULL;
    }
    // Calculate the length of the string
    size_t len = wcstombs(NULL, wstr, 0);
    if (len == (size_t)-1) {
        printf("Error: Conversion failed in string_from_unicode.\n");
        return NULL;
    }

    char* str = malloc(len + 1); // +1 for null terminator
    if (!str) {
        printf("Error: Memory allocation failed in string_from_unicode.\n");
        return NULL;
    }
    wcstombs(str, wstr, len + 1); // Convert and include the null terminator

    String* stringObj = ma_string_create(str);
    free(str); // Free the temporary char* buffer

    return stringObj;
}

String** ma_string_create_from_initializer(size_t count, ...) {
    if (count == 0) {
        printf("Error: count is zero in string_create_from_initializer.\n");
        return NULL;
    }

    va_list args;
    va_start(args, count);

    // Allocate memory for the array of String pointers
    String** strings = (String**)malloc(sizeof(String*) * (count + 1)); // +1 for NULL termination
    if (!strings) {
        printf("Error: Memory allocation failed for strings array in string_create_from_initializer.\n");
        va_end(args);
        return NULL;
    }

    // Create each string and add it to the array
    for (size_t i = 0; i < count; i++) {
        char* str = va_arg(args, char*);
        strings[i] = ma_string_create(str);
        if (!strings[i]) {
            printf("Error: string_create failed for string: %s in string_create_from_initializer.\n", str);

            // Handle allocation failure: cleanup and exit
            for (size_t j = 0; j < i; j++) {
                ma_string_deallocate(strings[j]);
            }
            free(strings);
            va_end(args);
            return NULL;
        }
    }

    // Null-terminate the array
    strings[count] = NULL;

    va_end(args);
    return strings;
}

char* ma_string_strdup(const char* s)
{
    if (s == NULL) {
        printf("Error: Parameter 's' is NULL in string_strdup.\n");
        return NULL;
    }

    char* new_str = malloc(strlen(s) + 1);
    if (new_str == NULL) {
        printf("Error: Memory allocation failed in string_strdup for string: %s\n", s);
        return NULL;
    }
    strcpy(new_str, s);

    return new_str;
}

size_t ma_string_length_cstr(const char* str) {
    if (!str) {
        printf("Error: str is null in string_length_cstr.\n");
        return 0;
    }
    return (size_t)strlen(str);
}

size_t ma_string_length_utf8(const char* str) {
    if (!str) {
        printf("Error: str is null in string_length_cstr.\n");
        return 0;
    }
    size_t length = 0;

    while (*str) {
        if ((*str & 0xC0) != 0x80) {
            length++;
        }
        str++;
    }
    return length;
}

bool ma_string_to_bool_from_cstr(const char* boolstr) {
    if (!boolstr) {
        printf("Error: bool str is NULL and invalid in string_to_bool_cstr.\n");
        return false;
    }

    if (strcmp(boolstr, "true") == 0) {
        return true;
    } else if (strcmp(boolstr, "false") == 0) {
        return false;
    }

    return false;
}

size_t ma_string_utf8_char_len(char c) {
    if ((c & 0x80) == 0) {
        return 1;
    }

    if ((c & 0xE0) == 0xC0) {
        return 2;
    }

    if ((c & 0xF0) == 0xE0) {
        return 3;
    }

    if ((c & 0xF8) == 0xF0) {
        return 4;
    }

    return 0;
}

// ------------------------------------------------------------------------- //
//                              File IO                                      //
// ------------------------------------------------------------------------- //

// File Writer

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <io.h> // _get_osfhandle
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <errno.h>
#endif

FileWriter* file_writer_open(const char* filename, const WriteMode mode) {
    if (!filename) {
        printf("Error: filename is null in file_writer_open.\n");
        exit(-1);
    }

    FileWriter* writer = (FileWriter*) malloc(sizeof(FileWriter));
    if (!writer) {
        printf("Error: Can not allocate memory for FileWriter in file_writer_open.\n");
        exit(-1);
    }

    const char* modeStr = NULL;

    switch (mode){
        case WRITE_TEXT:
            modeStr = "w";
            break;
        case WRITE_BINARY:
            modeStr = "wb";
            break;
        case WRITE_UNICODE:
            #if defined(_WIN32) || defined(_WIN64)
                modeStr = "w, ccs=UTF-8";
            #else
                modeStr = "w";
            #endif
            break;
        case WRITE_BUFFERED:
            modeStr = "w";
            break;
        case WRITE_UNBUFFERED:
            modeStr = "w";
            break;
        case WRITE_APPEND:
            #if defined(_WIN32) || defined(_WIN64)
                modeStr = "a, ccs=UTF-8";
            #else
                modeStr = "a";
            #endif
            break;
        default:
            printf("Warning: Not Valid mode for writing in file_writer_open i initialize default mode that is 'w'.\n");

            #if defined(_WIN32) || defined(_WIN64)
                modeStr = "w, ccs=UTF-8";
            #else
                modeStr = "w";
            #endif
            break;
    }

    #if defined(_WIN32) || defined(_WIN64)
        wchar_t* wFileName = encoding_utf8_to_wchar(filename);
        wchar_t* wMode = encoding_utf8_to_wchar(modeStr);

        if (!wMode) {
            printf("Error: Can not convert mode to wchar in file_writer_open.\n");
            exit(-1);
        }
        if (!wFileName) {
            printf("Error: Can not convert filename to wchar in file_writer_open.\n");
            exit(-1);
        }
        writer->file_writer = _wfopen(wFileName, wMode);
        free(wMode);
        free(wFileName);
    #else
        writer->file_writer = fopen(filename, modeStr);
    #endif

    if (writer->file_writer == NULL) {
        printf("Error: Can not open file in file_writer_open.\n");
        free(writer);
        exit(-1);
    }

    writer->mode = mode;
    writer->is_open = true;
    writer->encoding = WRITE_ENCODING_UTF16;
    writer->file_path = ma_string_strdup(filename);

    return writer;
}

// Open an existing file for appending. If the file does not exist, it will be created.
FileWriter* ma_file_writer_append(const char *filename, const WriteMode mode) {
    if (!filename) {
        printf("Error: filename is null in file_writer_open.\n");
        return NULL;
    }

    FileWriter* writer = (FileWriter*) malloc(sizeof(FileWriter));
    if (!writer) {
        printf("Error: Can not allocate memory for FileWriter in file_writer_open.\n");
        return NULL;
    }

    const char* modeStr = NULL;
    switch (mode){
        case WRITE_TEXT:
            modeStr = "a";
            break;
        case WRITE_BINARY:
            modeStr = "ab";
            break;
        case WRITE_UNICODE:
            #if defined(_WIN32) || defined(_WIN64)
                modeStr = "a, ccs=UTF-8";
            #else
                modeStr = "a";
            #endif
            break;
        case WRITE_BUFFERED:
            modeStr = "a";
            break;
        case WRITE_UNBUFFERED:
            modeStr = "a";
            break;
        case WRITE_APPEND:
            #if defined(_WIN32) || defined(_WIN64)
                modeStr = "a, ccs=UTF-8";
            #else
                modeStr = "a";
            #endif
            break;
        default:
            printf("Warning: Not Valid mode for writing in file_writer_open i initialize default mode that is 'w'.\n");
            break;
    }

    #if defined(_WIN32) || defined(_WIN64)
        wchar_t* wFileName = ma_encoding_utf8_to_wchar(filename);
        wchar_t* wMode = ma_encoding_utf8_to_wchar(modeStr);

        if (!wMode) {
            printf("Error: Can not convert mode to wchar in file_writer_open.\n");
            return NULL;
        }

        if (!wFileName) {
            printf("Error: Can not convert filename to wchar in file_writer_open.\n");
            return NULL;
        }

        writer->file_writer = _wfopen(wFileName, wMode);
        free(wMode);
        free(wFileName);
    #else
        writer->file_writer = fopen(filename, modeStr);
    #endif

    if (writer->file_writer == NULL) {
        printf("Error: Can not open file in file_writer_open.\n");
        free(writer);
        return NULL;
    }

    writer->mode = mode;
    writer->is_open = true;
    writer->encoding = WRITE_ENCODING_UTF16;
    writer->file_path = ma_string_strdup(filename);

    return writer;
}

bool ma_file_writer_close(FileWriter *writer) {
    if (writer->file_writer == NULL) {
        printf("Warning: Right now the file is NULL no need to close it in file_writer_close.\n");
        return false;
    }
    if (fclose(writer->file_writer)) {
        printf("Error: Failed to close file in file_writer_close.\n");
        return false;
    }
    writer->is_open = false;
    return true;
}

size_t ma_file_writer_get_position(FileWriter *writer) {
    if (writer->file_writer == NULL) {
        printf("Error: FileWriter object is null and not valid in file_writer_get_position.\n");
        return (size_t)-1;
    }

    long cursor_position = ftell(writer->file_writer);

    if (cursor_position == -1L) {
        printf("Error: Could not determine file position.\n");
        return (size_t)-1;
    }

    return (size_t)cursor_position;
}

size_t ma_file_writer_write(void *buffer, size_t size, size_t count, FileWriter *writer) {
    if (!writer || !writer->file_writer || !buffer) {
        printf("Error: Invalid argument in file_writer_write.\n");
        return 0;
    }

    // Directly write binary data without conversion
    if (writer->mode == WRITE_BINARY) {
        return fwrite(buffer, size, count, writer->file_writer);
    }

    size_t written = 0;

    // Handle text and unicode data with conversion if necessary
    switch (writer->encoding) {
        case WRITE_ENCODING_UTF32: {
            // Convert UTF-8 to UTF-32 and then write
            uint32_t* utf32Buffer = ma_encoding_utf8_to_utf32((const uint8_t*)buffer, size * count);
            if (!utf32Buffer) {
                printf("Error: Conversion to UTF-32 failed in file_writer_write.\n");
                return 0;
            }
            written = fwrite(utf32Buffer, sizeof(uint32_t), wcslen((wchar_t*)utf32Buffer), writer->file_writer);
            free(utf32Buffer);
            break;
        }

        case WRITE_ENCODING_UTF16: {
            #if defined(_WIN32) || defined(_WIN64)
            // For Windows, if mode requires UTF-16, convert and write
            if (writer->mode == WRITE_UNICODE || writer->mode == WRITE_APPEND) {
                wchar_t* wBuffer = encoding_utf8_to_wchar((const char*)buffer);
                if (!wBuffer) {
                    printf("Error: Conversion to wchar_t failed in file_writer_write.\n");
                    return 0;
                }
                written = fwrite(wBuffer, sizeof(wchar_t), wcslen(wBuffer), writer->file_writer);
                free(wBuffer);
            }
            else {
                // For non-Unicode modes, write directly
                written = fwrite(buffer, size, count, writer->file_writer);
            }
            #else
            // For non-Windows systems, convert UTF-8 to UTF-16 if required and write
            if (writer->encoding == WRITE_ENCODING_UTF16) {
                uint16_t* utf16Buffer = ma_encoding_utf8_to_utf16((const uint8_t*)buffer, size * count);
                if (!utf16Buffer) {
                    printf("Error: Conversion to UTF-16 failed in file_writer_write.\n");
                    return 0;
                }
                written = fwrite(utf16Buffer, sizeof(uint16_t), wcslen((wchar_t*)utf16Buffer), writer->file_writer);
                free(utf16Buffer);
            }
            else {
                // For non-Unicode modes, write directly
                written = fwrite(buffer, size, count, writer->file_writer);
            }
            #endif
            break;
        }

        // Other encoding types or default handling can be added here
        default:
            // For safety, default to direct writing for undefined encoding types
            written = fwrite(buffer, size, count, writer->file_writer);
            break;
    }

    return written;
}

bool ma_file_writer_write_line(char *buffer, size_t size, FileWriter *writer) {
    if (writer->file_writer == NULL || !writer) {
        printf("Error: FileWriter object is NULL and not valid in file_writer_write_line.\n");
        return false;
    }
    if (buffer == NULL) {
        printf("Error: Invalid arg 'buffer is NULL' in file_writer_write_line.\n");
        return false;
    }

    size_t written = 0;
    size_t elementToWriteSize = size;

    #if defined(_WIN32) || defined(_WIN64)
        if (writer->mode == WRITE_UNICODE) {
            wchar_t* wBuffer = encoding_utf8_to_wchar(buffer);
            if (!wBuffer) {
                printf("Error: Can not convert buffer to wchar in file_writer_write_line.\n");
                return false;
            }

            elementToWriteSize = wcslen(wBuffer);
            written = fwrite(wBuffer, sizeof(wchar_t), elementToWriteSize, writer->file_writer);
            free(wBuffer);
        } else {
            written = fwrite(buffer, sizeof(char), elementToWriteSize, writer->file_writer);
        }
    #else
        written = fwrite(buffer, sizeof(char), size, writer->file_writer);
    #endif

    if (written < elementToWriteSize) {
        printf("Error: could not write entire buffer in file in file_writer_write_line.\n");
        return false;
    }

    #if defined(_WIN32) || defined(_WIN64)
        if (writer->mode == WRITE_UNICODE) {
            wchar_t newLine[] = L"\n";
            written = fwrite(newLine, sizeof(wchar_t), 1, writer->file_writer);
        } else {
            char newLine[] = "\n";
            written = fwrite(newLine, sizeof(char), 1, writer->file_writer);
        }
    #else
        char newLine[] = "\n";
        written = fwrite(newLine, sizeof(char), 1, writer->file_writer);
    #endif

    return written == 1;
}

bool ma_file_writer_is_open(FileWriter* writer) {
    if (!writer) {
        printf("Error: FileWriter pointer is NULL in file_writer_is_open.\n");
        return false;
    }

    if (writer->file_writer == NULL) {
        printf("Error: FileWriter object is NULL and its not open in file_writer_is_open.\n");
        return false;
    }

    return writer->is_open;
}

// This function will flush the buffer of the file writer, ensuring that all written data is physically stored in the file.
bool ma_file_writer_flush(FileWriter* writer) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is NULL and not valid in file_writer_flush");
        return false;
    }

    // fflush will flush the write buffer associated with the file writer.
    // This is necessary for both text and binary modes.
    // It works correctly for Unicode text as well, as it does not interpret the buffer's content.
    if (fflush(writer->file_writer) == EOF) {
        printf("Error: Failed to flush the writer in file_writer_flush.\n");
        return false;
    }

    return true;
}

// Set the character encoding for writing to the file.
bool ma_file_writer_set_encoding(FileWriter* writer, const WriteEncodingType encoding) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: Filewriter object is invalid or NULL in file_writer_set_encoding.\n");
        return false;
    }

    if (!(encoding >= WRITE_ENCODING_UTF16 && encoding <= WRITE_ENCODING_UTF32)) {
        printf("Error: Encoding type is Invalid in file_writer_set_encoding.\n");
        return false;
    }

    writer->encoding = encoding;

    return true;
}

// Copy content from one file to another.
bool ma_file_writer_copy(FileWriter *src_writer, FileWriter *dest_writer){
    if (!src_writer || src_writer->file_writer == NULL || src_writer->file_path == NULL) {
        printf("Error: src_writer object or file_path or both them are null and not valid in file_writer_copy.\n");
        return false;
    }

    if (!src_writer || src_writer->file_writer == NULL || src_writer->file_path == NULL) {
        printf("Error: des_writer object or file_path or both them are null and not valid in file_writer_copy.\n");
        return false;
    }

    FILE* src_file = fopen(src_writer->file_path, "rb");
    if (!src_file) {
        printf("Error: Can not reopen source file for reading in file_writer_copy.\n");
        return false;
    }

    FILE* dest_file = fopen(dest_writer->file_path, "wb");
    if (!dest_file) {
        printf("Error: Can not reopen destination file for writing in file_writer_copy.\n");
        return false;
    }

    char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, sizeof(char), sizeof(buffer), src_file))) {
        if (fwrite(buffer, sizeof(char), bytes_read, dest_file) != bytes_read) {
            printf("Error: Write Error occurred in file_writer_copy.\n");

            fclose(src_file);
            fclose(dest_file);
            return false;
        }
    }
    fclose(src_file);
    fclose(dest_file);

    return true;
}

// get absolute path of FileWriter object
const char* ma_file_writer_get_file_name(FileWriter *writer){
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is null and not valid in file_writer_get_file_name.\n");
        return NULL;
    }
    if (!writer->file_path) {
        printf("Error: file path for FileWriter is null in file_writer_get_file_name.\n");
        return NULL;
    }

    return (const char*)writer->file_path;
}

// get encoding type of FileWriter
const char* ma_file_writer_get_encoding(FileWriter *writer) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is null and not valid in file_writer_get_encoding.\n");
        return NULL;
    }

    if (!(writer->encoding >= WRITE_ENCODING_UTF16 && writer->encoding <= WRITE_ENCODING_UTF32)) {
        printf("Error: Encoding type is Invalid in file_writer_get_encoding.\n");
        return NULL;
    }

    char *encoding = NULL;
    switch (writer->encoding){
        case WRITE_ENCODING_UTF16:
            encoding = ma_string_strdup("ENCODING_UTF16");
            break;
        case WRITE_ENCODING_UTF32:
            encoding = ma_string_strdup("ENCODING_UTF32");
            break;
    }

    return encoding;
}

// Write formatted data to the file, similar to `fprintf`.
size_t ma_file_writer_write_fmt(FileWriter* writer, const char* format, ...) {
    if (!writer || !writer->file_writer || !format) {
        printf("Error: Invalid argument in file_writer_write_fmt.\n");
        return 0;
    }

    va_list args;
    va_start(args, format);

    char buffer[2048]; // Adjust the buffer size as necessary
    vsnprintf(buffer, sizeof(buffer), format, args);

    // Write the formatted string to the file
    size_t written = ma_file_writer_write(buffer, strlen(buffer), 1, writer);

    va_end(args);

    return written;
}

size_t ma_file_writer_get_size(FileWriter* writer) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is not valid and NULL in file_writer_get_size.\n");
        return 0;
    }

    if (!ma_file_writer_flush(writer)) {
        printf("Error: Failed in flushing the data in file_writer_get_size.\n");
        return 0;
    }

    size_t current_position = ma_file_writer_get_position(writer);
    if (fseek(writer->file_writer, 0, SEEK_END) != 0) {
        printf("Error: fseek failed to seek to end of file in file_writer_get_size.\n");
        return 0;
    }

    size_t size = ma_file_writer_get_position(writer);
    if (fseek(writer->file_writer, current_position, SEEK_SET) != 0) {
        printf("Error: fseek failed to return to original position in file_writer_get_position.\n");
    }

    return size;
}

// Lock the file to prevent other processes from modifying it while it's being written to
bool ma_file_writer_lock(FileWriter* writer) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is NULL in file_writer_lock.\n");
        return false;
    }

    #if defined(_WIN32) || defined(_WIN64)
        HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(writer->file_writer));
        OVERLAPPED overlapped = {0};
        if (LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped) == 0) {
            printf("Error: Unable to lock file in Windows.\n");
            return false;
        }
    #else
        struct flock fl = {0};
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0; // Lock the whole file

        if (fcntl(fileno(writer->file_writer), F_SETLKW, &fl) == -1) {
            printf("Error: Unable to lock file in Unix.\n");
            return false;
        }
    #endif

    return true;
}

// Unlock the file once operations are done.
bool ma_file_writer_unlock(FileWriter* writer) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is NULL in file_writer_unlock.\n");
        return false;
    }

    #if defined(_WIN32) || defined(_WIN64)
        HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(writer->file_writer));
        OVERLAPPED overlapped = {0};
        if (UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &overlapped) == 0) {
            printf("Error: Unable to unlock file in Windows.\n");
            return false;
        }
    #else
        struct flock fl = {0};
        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0; // Unlock the whole file

        if (fcntl(fileno(writer->file_writer), F_SETLK, &fl) == -1) {
            printf("Error: Unable to unlock file in Unix.\n");
            return false;
        }
    #endif

    return true;
}

// Move the file pointer to a specific location for random access writing
bool ma_file_writer_seek(FileWriter *writer, long offset, const CursorPosition cursor_pos) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is null and invalid in file_writer_seek.\n");
        return false;
    }
    int pos;

    switch (cursor_pos) {
        case POS_BEGIN:
            pos = SEEK_SET;
            break;
        case POS_END:
            pos = SEEK_END;
            break;
        case POS_CURRENT:
            pos = SEEK_CUR;
            break;
        default:
            printf("Warning: Cursor position is Invalid defailt pos is POS_BEGIN in file_writer_seek.\n");
            pos = SEEK_SET;
            break;
    }

    if (fseek(writer->file_writer, offset, pos) != 0) {
        printf("Error: fseek failed in file_writer_seek.\n");
        return false;
    }

    return true;
}

bool ma_file_writer_truncate(FileWriter *writer, size_t size) {
    if (!writer || writer->file_writer == NULL) {
        printf("Error: FileWriter object is null and invalid in file_writer_truncate.\n");
        return false;
    }
    if (!ma_file_writer_flush(writer)) {
        printf("Error: Failed to flush the file in file_writer_truncate.\n");
        return false;
    }
    int fd;

    #if defined(_WIN32) || defined(_WIN64)
        fd = _fileno(writer->file_writer);
        if (_chsize_s(fd, size) != 0) {
            printf("Error: Could not truncate file in file_writer_truncate.\n");
            return false;
        }
    #else
        fd = fileno(writer->file_writer);
        if (ftruncate(fd, size) == -1) {
            printf("Error: Could not truncate file in file_writer_truncate.\n");
            return false;
        }
    #endif

    return true;
}

// Allows writing multiple buffers in a single operation, potentially optimizing I/O operations by reducing the number of system calls
bool ma_file_writer_write_batch(FileWriter* writer, const void** buffers, const size_t* sizes, size_t count) {
    if (!writer || !writer->file_writer || !buffers || !sizes) {
        printf("Error: Invalid arguments in file_writer_write_batch.\n");
        return false;
    }

    size_t all_bytes = 0;
    size_t total_written = 0;
    for (size_t i = 0; i < count; ++i) {
        const void* buffer = buffers[i];
        size_t size = sizes[i];
        all_bytes += size;
        if (!buffer || size == 0) {
            printf("Error: Invalid buffer or size in file_writer_write_batch at index %zu.\n", i);
            continue;
        }

        size_t written = 0;
        void* convertedBuffer = NULL; // Pointer for holding converted data
        size_t convertedSize = 0;     // Size of the converted data

        // Convert buffer based on encoding
        switch (writer->encoding) {
            case WRITE_ENCODING_UTF32: {
                uint32_t* utf32Buffer = ma_encoding_utf8_to_utf32((const uint8_t*)buffer, size);
                if (!utf32Buffer) {
                    printf("Error: Conversion to UTF-32 failed in file_writer_write_batch.\n");
                    continue;
                }
                convertedBuffer = utf32Buffer;
                convertedSize = wcslen((wchar_t*)utf32Buffer) * sizeof(uint32_t);
                break;
            }
            default: // Default case is ENCODING_UTF16
            case WRITE_ENCODING_UTF16: {
                #if defined(_WIN32) || defined(_WIN64)
                    wchar_t* wBuffer = encoding_utf8_to_wchar((const char*)buffer);
                    if (!wBuffer) {
                        printf("Error: Conversion to wchar_t failed in file_writer_write_batch.\n");
                        continue;
                    }
                    convertedBuffer = wBuffer;
                    convertedSize = wcslen(wBuffer) * sizeof(wchar_t);
                #else
                    uint16_t* utf16Buffer = ma_encoding_utf8_to_utf16((const uint8_t*)buffer, size);
                    if (!utf16Buffer) {
                        printf("Error: Conversion to UTF-16 failed in file_writer_write_batch.\n");
                        continue;
                    }
                    convertedBuffer = utf16Buffer;
                    convertedSize = wcslen((wchar_t*)utf16Buffer) * sizeof(uint16_t);
                #endif
                break;
            }
        }

        // Write the buffer to the file
        written = fwrite(convertedBuffer, 1, convertedSize, writer->file_writer);
        free(convertedBuffer);

        if (written != convertedSize) {
            printf("Error: Partial or failed write in file_writer_write_batch at index %zu.\n", i);
            return false;
        }

        total_written += written;
    }
    if (writer->mode == WRITE_UNICODE)
        all_bytes *= 2; // because we use wchar_t in unicode

    return total_written == all_bytes;
}

// Similar to file_writer_write_fmt, but specifically for appending formatted text to a file.
bool ma_file_writer_append_fmt(FileWriter* writer, const char* format, ...) {
    if (!writer || !writer->file_writer || !format) {
        printf("Error: Invalid argument in file_writer_append_fmt.\n");
        return false;
    }
    if (writer->mode != WRITE_APPEND) {
        printf("Error: FileWriter object must be in append mode in file_writer_write_fmt.\n");
        return false;
    }

    va_list args;
    va_start(args, format);

    char buffer[2048]; // Adjust the buffer size as necessary
    vsnprintf(buffer, sizeof(buffer), format, args);

    size_t written = ma_file_writer_write(buffer, strlen(buffer), 1, writer);

    va_end(args);

    return written > 0;
}

// ------------------------------------------------------------------------- //
//                  CPP vector implementation in C                           //
// ------------------------------------------------------------------------- //

Vector* ma_vector_create(size_t itemSize) {
    Vector* vec = (Vector*)malloc(sizeof(Vector));

    if (!vec){
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Can not allocate memory for Vector structure");
        #endif
        exit(-1);
    }

    vec->size = 0;
    vec->capacitySize = 32; // Initial capacity
    vec->itemSize = itemSize;

    size_t initialPoolSize = 100000;
    vec->pool = ma_vector_memory_pool_create(initialPoolSize);
    if (!vec->pool) {
        free(vec);
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Can not allocate memory for Vector pool");
        #endif
        exit(-1);
    }

    // Instead of malloc, use memory pool for initial allocation
    vec->items = ma_vector_memory_pool_allocate(vec->pool, vec->capacitySize * itemSize);
    if (!vec->items) {
        ma_vector_memory_pool_destroy(vec->pool);
        free(vec);
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Can not allocate memory for Vector items");
        #endif
        exit(-1);
    }
    return vec;
}

bool vector_is_equal(const Vector* vec1, const Vector* vec2) {
    if (vec1 == NULL || vec2 == NULL) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: One or both vector pointers are NULL in vector_is_equal.\n");
        #endif
        return false; // One or both vectors are NULL, so they cannot be equal
    }
    if (vec1->size != vec2->size) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vectors have different sizes in vector_is_equal.\n");
        #endif
        return false; // Vectors with different sizes cannot be equal
    }
    return memcmp(vec1->items, vec2->items, vec1->size * vec1->itemSize) == 0;
}

bool ma_vector_is_less(const Vector* vec1, const Vector* vec2) {
    if (!vec1 || !vec2) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: One or both vector pointers are NULL in vector_is_less.\n");
        #endif
        return false;
    }

    size_t minSize = vec1->size < vec2->size ? vec1->size : vec2->size;
    int cmp = memcmp(vec1->items, vec2->items, minSize * vec1->itemSize);

    return cmp < 0 || (cmp == 0 && vec1->size < vec2->size);
}

bool ma_vector_is_greater(const Vector* vec1, const Vector* vec2) {
    if (!vec1 || !vec2) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: One or both vector pointers are NULL in vector_is_greater.\n");
        #endif
        return false;
    }

    size_t minSize = vec1->size < vec2->size ? vec1->size : vec2->size;
    int cmp = memcmp(vec1->items, vec2->items, minSize * vec1->itemSize);

    return cmp > 0 || (cmp == 0 && vec1->size > vec2->size);
}

bool ma_vector_is_not_equal(const Vector* vec1, const Vector* vec2) {
    if (!vec1 || !vec2) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: One or both vector pointers are NULL in vector_is_not_equal.\n");
        #endif
        return true;
    }
    if (vec1->size != vec2->size) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vectors have different sizes in vector_is_not_equal.\n");
        #endif
        return true;
    }
    return memcmp(vec1->items, vec2->items, vec1->size * vec1->itemSize) != 0;
}

bool ma_vector_is_greater_or_equal(const Vector* vec1, const Vector* vec2) {
    if (!vec1 || !vec2) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: One or both vector pointers are NULL in vector_is_greater_or_equal.\n");
        #endif
        return false; // Handle the error as per your application's needs
    }
    return !ma_vector_is_less(vec1, vec2);
}

bool ma_vector_is_less_or_equal(const Vector* vec1, const Vector* vec2) {
    if (!vec1 || !vec2) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: One or both vector pointers are NULL in vector_is_less_or_equal.\n");
        #endif
        return false; // Handle the error as per your application's needs
    }
    return !ma_vector_is_greater(vec1, vec2);
}

bool ma_vector_is_empty(Vector *vec) {
    if (vec == NULL) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_is_empty_impl.\n");
        #endif
        return true; // or handle the error as per your application's needs
    }
    return vec->size == 0;
}

void ma_vector_erase(Vector *vec, size_t pos, size_t len) {
    if (vec == NULL) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_erase.\n");
        #endif
        return; // Handle the error as per your application's needs
    }

    if (pos >= vec->size) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Position is out of bounds in vector_erase.\n");
        #endif
        return; // Handle the error as per your application's needs
    }

    if (pos + len > vec->size) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Length is too large in vector_erase.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    char *base = (char *)vec->items;
    memmove(base + pos * vec->itemSize,
            base + (pos + len) * vec->itemSize,
            (vec->size - pos - len) * vec->itemSize);

    vec->size -= len;
}

void ma_vector_insert(Vector *vec, size_t pos, void *item) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_insert.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    if (pos > vec->size) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Position is out of bounds in vector_insert.\n");
        #endif
        return; // Handle the error as per your application's needs
    }

    if (vec->size == vec->capacitySize) {
        // Allocate new space from the memory pool
        size_t newCapacity = vec->capacitySize * 2; // Double the capacity
        void *newItems = ma_vector_memory_pool_allocate(vec->pool, newCapacity * vec->itemSize);

        if (!newItems) {
            #ifdef VECTOR_LOGGING_ENABLE
                printf("Error: Failed to allocate memory for vector_insert.\n");
            #endif
            return; // Handle allocation failure, maybe by resizing the pool
        }

        // Copy existing items to the new space
        memcpy(newItems, vec->items, pos * vec->itemSize); // Copy elements before insertion position
        memcpy((char *)newItems + (pos + 1) * vec->itemSize,
               (char *)vec->items + pos * vec->itemSize,
               (vec->size - pos) * vec->itemSize); // Copy elements after insertion position

        vec->items = newItems;
        vec->capacitySize = newCapacity;
    }
    else {
        char *base = (char *)vec->items;  // Shift elements to make space for the new element
        memmove(base + (pos + 1) * vec->itemSize,
                base + pos * vec->itemSize,
                (vec->size - pos) * vec->itemSize);
    }

    // Insert the new element
    memcpy((char *)vec->items + pos * vec->itemSize, item, vec->itemSize);
    vec->size++;
}

bool ma_vector_reserve(Vector *vec, size_t size) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_reserve.\n");
        #endif
        return false;
    }
    if (vec->capacitySize >= size) {
        return true;
    }

    void *newItems = ma_vector_memory_pool_allocate(vec->pool, size * vec->itemSize);
    if (!newItems) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Failed to allocate memory for vector_reserve.\n");
        #endif
        return false;
    }
    if (vec->size > 0) {
        memcpy(newItems, vec->items, vec->size * vec->itemSize);
    }

    vec->items = newItems;
    vec->capacitySize = size;
    return true;
}

void ma_vector_resize(Vector *vec, size_t size) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_resize.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    if (size > vec->capacitySize) {
        ma_vector_reserve(vec, size); // Resize capacity if new size exceeds current capacity
    }
    if (vec->size < size) {
        memset((char *)vec->items + vec->size * vec->itemSize, 0, (size - vec->size) * vec->itemSize);  // Initialize new elements to 0 if size is increased
    }
    vec->size = size;
}

void ma_vector_shrink_to_fit(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_shrink_to_fit.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    if (vec->size == vec->capacitySize) {
        return; // No need to shrink if size equals capacity
    }

    if (vec->size == 0) {
        free(vec->items); // Assuming this memory is not part of the pool
        vec->items = NULL;
        vec->capacitySize = 0;

        return;
    }

    void *newItems = ma_vector_memory_pool_allocate(vec->pool, vec->size * vec->itemSize);
    if (!newItems) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Failed to allocate memory for vector_shrink_to_fit.\n");
        #endif
        return; // Handle allocation failure, maybe by resizing the pool or another appropriate action
    }

    memcpy(newItems, vec->items, vec->size * vec->itemSize);
    vec->items = newItems;
    vec->capacitySize = vec->size;
}

void ma_vector_swap(Vector *vec1, Vector *vec2) {
    if (!vec1 || !vec2) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: One or both vectors are NULL in vector_swap.\n");
        #endif
        return; // Handle the error as per your application's needs
    }

    void *tempItems = vec1->items;
    vec1->items = vec2->items;
    vec2->items = tempItems;

    size_t tempSize = vec1->size;
    vec1->size = vec2->size;
    vec2->size = tempSize;

    size_t tempCapacity = vec1->capacitySize;
    vec1->capacitySize = vec2->capacitySize;
    vec2->capacitySize = tempCapacity;

    size_t tempItemSize = vec1->itemSize;
    vec1->itemSize = vec2->itemSize;
    vec2->itemSize = tempItemSize;
}

void ma_vector_assign(Vector *vec, size_t pos, void *item) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_assign.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    if (pos >= vec->size) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Position is out of bounds in vector_assign.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    memcpy((char *)vec->items + pos * vec->itemSize, item, vec->itemSize);
}

void ma_vector_emplace(Vector *vec, size_t pos, void *item, size_t itemSize) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_emplace.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    if (pos > vec->size || itemSize != vec->itemSize) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Invalid position or item size in vector_emplace.\n");
        #endif
        return; // Handle the error as per your application's needs
    }
    if (vec->size == vec->capacitySize) {
        ma_vector_reserve(vec, vec->capacitySize * 2); // Use the modified version
    }

    char *base = (char *)vec->items;
    memmove(base + (pos + 1) * vec->itemSize,
            base + pos * vec->itemSize,
            (vec->size - pos) * vec->itemSize);

    memcpy(base + pos * vec->itemSize, item, vec->itemSize);
    vec->size++;
}

bool ma_vector_emplace_back(Vector *vec, void *item, size_t itemSize) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_emplace_back.\n");
        #endif
        return false; // Indicate failure
    }
    if (itemSize != vec->itemSize) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Invalid item size in vector_emplace_back.\n");
        #endif
        return false; // Indicate failure
    }
    if (vec->size >= vec->capacitySize) {
        if (!ma_vector_reserve(vec, vec->capacitySize * 2)) {
            return false; // vector_reserve failed, indicate failure
        }
    }

    memcpy((char *)vec->items + vec->size * vec->itemSize, item, vec->itemSize);
    vec->size++;
    return true; // Indicate success
}

bool ma_vector_push_back(Vector *vec, const void *item) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_push_back.\n");
        #endif
        return false; // Indicate failure
    }

    if (vec->size >= vec->capacitySize) {
        size_t newCapacity = vec->capacitySize * 2; // Example growth strategy
        // Allocate new space from the memory pool
        void *newItems = ma_vector_memory_pool_allocate(vec->pool, newCapacity * vec->itemSize);
        if (!newItems) {
            #ifdef VECTOR_LOGGING_ENABLE
                printf("Error: Failed to allocate memory in vector_push_back.\n");
            #endif
            return false; // Indicate failure
        }

        memcpy(newItems, vec->items, vec->size * vec->itemSize); // Copy existing items to the new space
        vec->items = newItems;
        vec->capacitySize = newCapacity;
    }

    // Proceed with adding the new item
    memcpy((char *)vec->items + (vec->size * vec->itemSize), item, vec->itemSize);
    vec->size++;

    return true; // Indicate success
}

void ma_vector_deallocate(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_deallocate.\n");
        #endif
        return; // Handle the error as per your application's needs
    }

    if (vec->pool != NULL) {
        ma_vector_memory_pool_destroy(vec->pool);
        vec->pool = NULL;
    }

    if (vec->items != NULL) {
        vec->items = NULL;   // The items are part of the pool, so no need to free them separately
    }
    free(vec);
}

void *vector_at(const Vector *vec, size_t pos) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_at.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }

    if (pos < vec->size) {
        return (char *)vec->items + (pos * vec->itemSize); // Calculate the address of the item at position 'pos'
    }
    else {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Position is out of bounds in vector_at.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
}

void* ma_vector_rbegin(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_rbegin.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_rbegin.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }

    return (void *)((char *)vec->items + (vec->size - 1) * vec->itemSize); // Last element
}

void* ma_vector_rend(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_rend.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return (void *)((char *)vec->items - vec->itemSize); // One before the first element
}

const void* ma_vector_cbegin(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_cbegin.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_cbegin.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return (const void *)vec->items;
}

const void *ma_vector_cend(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_cend.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_end.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return (const void *)((char *)vec->items + (vec->size * vec->itemSize)); // One past the last element, as a read-only pointer
}

const void *ma_vector_crbegin(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_crbegin.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_crbegin.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return (const void *)((char *)vec->items + (vec->size - 1) * vec->itemSize); // Last element, as a read-only pointer
}

const void* ma_vector_crend(Vector *vec) {
    if (vec == NULL) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_crend.\n");
        #endif
        return NULL;
    }
    return (const void *)((char *)vec->items - vec->itemSize); // One before the first element, as a read-only pointer
}

void* ma_vector_begin(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_crend.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return vec->items; // Pointer to the first element
}

void* ma_vector_end(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_end.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_end.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return (char *)vec->items + (vec->size * vec->itemSize); // One past the last element
}

void* ma_vector_pop_back(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_pop_back.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_pop_back.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }

    vec->size--;
    return (char *)vec->items + (vec->size * vec->itemSize);
}

void ma_vector_clear(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_clear.\n");
        #endif
        return; // Handle the error as per your application's needs
    }

    vec->size = 0;
    // Optionally reduce capacity. Choose an appropriate size for your use case.
    size_t reducedCapacity = 4; // Or some other small size
    if (vec->capacitySize > reducedCapacity) {
        void *newItems = ma_vector_memory_pool_allocate(vec->pool, reducedCapacity * vec->itemSize);
        if (newItems != NULL || reducedCapacity == 0) {
            vec->items = newItems;
            vec->capacitySize = reducedCapacity;
        }
        else {
            #ifdef VECTOR_LOGGING_ENABLE
                printf("Error: Cannot reallocate the Vector in vector_clear.\n");
            #endif
        }
    }
}

void* ma_vector_front(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_front.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_front.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return vec->items; // The first element is at the beginning of the items array
}

void* ma_vector_back(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_back.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    if (vec->size == 0) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is empty in vector_back.\n");
        #endif
        return NULL; // Handle the error as per your application's needs
    }
    return (char *)vec->items + (vec->size - 1) * vec->itemSize; // The last element is at (size - 1) * itemSize offset from the beginning
}

void*  ma_vector_data(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_data.\n");
        #endif
        return NULL;
    }
    return vec->items; // The underlying array
}

void* ma_vector_at(const Vector* vec, size_t index) {
    // Check if the index is within bounds
    if (index >= vec->size) {
        return NULL;
    }

    // Calculate the offset into the items array
    size_t offset = index * vec->itemSize;

    // Return a pointer to the item at the calculated offset
    return ((char*)vec->items) + offset;
}

size_t ma_vector_size(const Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_size.\n");
        #endif
        return 0;
    }
    return vec->size;
}

size_t ma_vector_capacity(Vector *vec) {
    if (!vec) {
        #ifdef VECTOR_LOGGING_ENABLE
            printf("Error: Vector is NULL in vector_capacity.\n");
        #endif
        return 0; // Handle the error as per your application's needs
    }
    return vec->capacitySize;
}

size_t ma_vector_max_size(Vector *vec) {
    if (!vec) {
        #ifdef MA_UTILS_DEBUGGER
            printf("Error: Vector is NULL in vector_max_size.\n");
        #endif
        return 0; // Handle the error as per your application's needs
    }
    return vec->itemSize;
}


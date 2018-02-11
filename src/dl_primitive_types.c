/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)

#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
#include <sys/endian.h>
#endif

#ifdef _KERNEL
#include <sys/libkern.h>
#else
#include <string.h>
#endif

#include <stddef.h>

#include "dl_assert.h"
#include "dl_primitive_types.h"

/* NULLABLE Strings and arrays of Bytes are represented with the value -1. */
static const int16_t DL_STRING_NULL = -1;
static const int32_t DL_BYTES_NULL = -1;

/**
 * Encoded strings are prefixed with their length (int16);
 * a value of -1 indicates a NULL string.
 */
int
dl_decode_string(char const * const source, char * const string)
{
	int string_len, decoded_len = 0;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");
	DL_ASSERT(string != NULL, "String cannot be NULL");

	/* Strings are NULLABLE.
	 * Therefore first check whether there is a value to decode.
	 */
	if (DL_STRING_NULL == dl_decode_int32(source)) {
		decoded_len += sizeof(int32_t);
	} else {
		/* Decode the string length */
		string_len = dl_decode_int16(source);
		decoded_len += sizeof(int16_t);

		strlcpy(string, &source[sizeof(int16_t)], string_len+1);
		decoded_len += string_len;
	}

	return decoded_len;
}

/**
 * Encoded arrays are prefixed with their length (int32);
 * a value of -1 indicates a NULL string.
 */
int
dl_decode_bytes(char const * const source, char * const target)
{
	int bytes_len, decoded_len = 0;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Bytes are NULLABLE.
	 * therefore first check whether there is a value to decode.
	 */
	if (DL_BYTES_NULL == dl_decode_int32(source)) {
		decoded_len += sizeof(int32_t);
	} else {
		/* Decode the bytes length */
		bytes_len = dl_decode_int32(source);
		decoded_len += sizeof(int16_t);

		memcpy(target, &source[sizeof(int32_t)], bytes_len);
		decoded_len += bytes_len;
	}

	return decoded_len;
}

/**
 * Encoded strings are prefixed with their length (int16).
 */
int32_t
dl_encode_string(char * const target, char const * const source,
    const size_t max_len)
{
	int32_t encoded_size = 0;
	char const *string_len = target;
	char const *string_value = &target[sizeof(uint16_t)];

	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");
	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Prepended a 16bit value indicating the length (in bytes). */
	encoded_size += dl_encode_int16(string_len, strlen(source));

#ifdef _KERNEL
	// TODO: In kernel strlcpy?
#else
	encoded_size += strlcpy(string_value, source, max_len);
#endif
	return encoded_size;
}

/**
 * Encoded byte arrays are prefixed with their length (int32).
 */
int32_t
dl_encode_bytes(char * const target, char const * const source,
    const int32_t source_len)
{
	int32_t encoded_len_bytes = 0;
	char const *bytes_len = target;
	char const *bytes_value = &target[sizeof(uint32_t)];

	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");
	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Prepend a 32bit value indicating the length (in bytes). */
	encoded_len_bytes = dl_encode_int32(bytes_len, source_len);

	/* Copy source_len bytes into the target buffer. */
	memcpy(bytes_value, source, source_len);
	encoded_len_bytes += source_len;

	return encoded_len_bytes;
}

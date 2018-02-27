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

#ifndef _DL_PRIMITIVE_TYPES_H
#define _DL_PRIMITIVE_TYPES_H

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

#include "dl_assert.h"

/* Functions for decoding primitive types (bytes and strings). */
extern int dl_decode_string(char const * const, char * const);
extern int dl_decode_bytes(char const * const, char * const);

/* Functions for encoding primitive types (bytes and strings). */
extern int32_t dl_encode_string(char * const, char const * const,
    const size_t);
extern int32_t dl_encode_bytes(char * const, char const * const,
    const int32_t);

/**
 * Decode a int8_t (big endian) from the source buffer.
 */
inline int8_t
dl_decode_int8(char const * const source)
{

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	return *((int8_t *) source);
}

/**
 * Decode a int16_t (big endian) from the source buffer.
 */
inline int16_t
dl_decode_int16(char const * const source)
{

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	return be16toh(*((int16_t *) source));
}

/**
 * Decode a int32_t (big endian) from the source buffer.
 */
inline int32_t
dl_decode_int32(char const * const source)
{

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	return be32toh(*((int32_t *) source));
}

/**
 * Decode a int64_t (big endian) from the source buffer.
 */
inline int64_t
dl_decode_int64(char const * const source)
{

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	return be64toh(*((int64_t *) source));
}

/**
 * Encoded a int8_t value into the source (be).
 */
inline int32_t
dl_encode_int8(char const *target, const int8_t value)
{

	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	(*(int8_t *) target) = value;
	return sizeof(int8_t);
}

/**
 * Encoded a int16_t value into the source (be).
 */
inline int32_t
dl_encode_int16(char const *source, const int16_t value)
{

	DL_ASSERT(source != NULL, "source cannot be NULL");

	(*(int16_t *) source) = htobe16(value);
	return sizeof(int16_t);
}

/**
 * Encoded a int32_t value into the source (be).
 */
inline int32_t
dl_encode_int32(char const *source, const int32_t value)
{

	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	(*(int32_t *) source) = htobe32(value);
	return sizeof(int32_t);
}

/**
 * Encoded a int64_t value into the source (be).
 */
inline int32_t
dl_encode_int64(char const *source, const int64_t value)
{

	DL_ASSERT(source != NULL, "source cannot be NULL");

	(*(int64_t *) source) = htobe64(value);
	return sizeof(int64_t);
}

#endif

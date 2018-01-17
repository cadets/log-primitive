/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef _DL_PROTOCOL_ENCODER_H
#define _DL_PROTOCOL_ENCODER_H

#include <sys/types.h>

#define DISTLOG_API_V1 1
#define DISTLOG_API_VERSION DISTLOG_API_V1

#define DL_ENCODE_API_KEY(buffer, value) dl_encode_int16(buffer, value)
#define DL_ENCODE_API_VERSION(buffer) \
    dl_encode_int16(buffer, DISTLOG_API_VERSION)
#define DL_ENCODE_CLIENT_ID(buffer, value) \
    dl_encode_string(buffer, value, DL_MAX_CLIENT_ID)
#define DL_ENCODE_CORRELATION_ID(buffer, value) dl_encode_int32(buffer, value)
#define DL_ENCODE_PARTITION(buffer, value) dl_encode_int32(buffer, value)
#define DL_ENCODE_REPLICAID(buffer, value) dl_encode_int32(buffer, value)
#define DL_ENCODE_SIZE(buffer, value) dl_encode_int32(buffer, value)
#define DL_ENCODE_TIMESTAMP(buffer, value) dl_encode_int64(buffer, value)
#define DL_ENCODE_TOPIC_NAME(buffer, value) \
    dl_encode_string(buffer, value, DL_MAX_TOPIC_NAME_LEN)


/* Functions for encoding primitive types. */
extern int32_t dl_encode_int8(char *, const int8_t);
extern int32_t dl_encode_int16(char *, const int16_t);
extern int32_t dl_encode_int32(char *, const int32_t);
extern int32_t dl_encode_int64(char *, const int64_t);
extern int32_t dl_encode_string(char *, char const * const, size_t);
extern int32_t dl_encode_bytes(char *, char *, const int32_t);

#endif

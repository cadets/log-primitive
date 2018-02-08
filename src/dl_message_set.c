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

// TODO: temp
// #include <time.h>
//
#include <sys/time.h>

#include <stddef.h>

// In kernel
#include <zlib.h>

#include "dl_assert.h"
#include "dl_primitive_types.h"
#include "dl_message_set.h"

static const int8_t DL_MESSAGE_MAGIC_BYTE = 0x01;
static const int8_t DL_MESSAGE_ATTRIBUTES = 0x00;
static const int64_t DL_DEFAULT_OFFSET = 0;

#define DL_ATTRIBUTES_SIZE sizeof(int8_t)
#define DL_CRC_SIZE sizeof(int32_t)
#define DL_MAGIC_BYTE_SIZE sizeof(int8_t)
#define DL_TIMESTAMP_SIZE sizeof(int64_t)

#define DL_MESSAGE_SET_SIZE_SIZE sizeof(int32_t)
#define DL_OFFSET_SIZE sizeof(int64_t)

#define DL_ENCODE_ATTRIBUTES(target) dl_encode_int8(target, 0)
#define DL_ENCODE_CRC(target, value) dl_encode_int32(target, value)
#define DL_ENCODE_MAGIC_BYTE(target) \
    dl_encode_int8(target, DL_MESSAGE_MAGIC_BYTE)
#define DL_ENCODE_MESSAGE_SIZE(target, value) dl_encode_int32(target, value)
#define DL_ENCODE_OFFSET(target, value) dl_encode_int64(target, value)
#define DL_ENCODE_TIMESTAMP(target, value) dl_encode_int64(target, value)

static int32_t dl_message_encode(struct dl_message *, char const *);
static int32_t dl_message_get_size(struct dl_message *);

struct dl_message_set *
dl_message_set_decode(char const * const source)
{
	struct dl_message_set message_set;
	int32_t message_it, nmessages;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Decode the MessageSet. */
	nmessages = dl_decode_int32(source);

	for (message_it = 0; message_it < nmessages; message_it++) {

		/* Encode the MessageSet Offset into the buffer. */
		//msg_set_size += DL_ENCODE_OFFSET(&target[msg_set_size],
		//    DL_DEFAULT_OFFSET);

		/* Encode the MessageSize. */
		//msg_set_size += DL_ENCODE_MESSAGE_SIZE(&target[msg_set_size],
		//    dl_message_get_size(message));

		/* Encode the Message. */
		//msg_set_size += dl_message_encode(message,
		//    &target[msg_set_size]);
	}

	return NULL;
}

/**
 * N.B. MessageSets are not preceded by an int32 like other array elements.
 */
int32_t
dl_message_set_encode(struct dl_message_set *message_set, char const *target)
{
	struct dl_message const *message;
	int32_t msg_set_size = 0;

	DL_ASSERT(message_set != NULL, "MessageSet cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	SLIST_FOREACH(message, message_set, dlm_entries) {
	
		/* Encode the MessageSet Offset into the buffer. */
		msg_set_size += DL_ENCODE_OFFSET(&target[msg_set_size],
		    DL_DEFAULT_OFFSET);

		/* Encode the MessageSize. */
		msg_set_size += DL_ENCODE_MESSAGE_SIZE(&target[msg_set_size],
		    dl_message_get_size(message));

		/* Encode the Message. */
		msg_set_size += dl_message_encode(message,
		    &target[msg_set_size]);
	}
		
	return msg_set_size;
}

static int32_t
dl_message_encode(struct dl_message *message, char const *target)
{
	int32_t msg_size = 0;
	unsigned long crc_value, timestamp;

	DL_ASSERT(message != NULL, "Message cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

#ifdef _KERNEL
	// TODO: In-kernel timestamp ms since epoch?
#else
	timestamp = time(NULL);
#endif

	/* Encode the CRC (placeholder value). */
	msg_size += DL_ENCODE_CRC(target, 0);

	/* Encode the MagicByte */
	msg_size += DL_ENCODE_MAGIC_BYTE(&target[msg_size]);
	
	/* Encode the Attributes */
	msg_size+= DL_ENCODE_ATTRIBUTES(&target[msg_size]);
	
	/* Encode the Timestamp */
	msg_size += DL_ENCODE_TIMESTAMP(&target[msg_size], timestamp);
	
	/* Encode the Key */
	msg_size += dl_encode_bytes(&target[msg_size], message->dlm_key,
	    message->dlm_key_len);
	
	/* Encode the Value */
	msg_size += dl_encode_bytes(&target[msg_size], message->dlm_value,
	    message->dlm_value_len);

	/* Encode the CRC, with the correct value. */
	crc_value = crc32(0L, Z_NULL, 0);
	crc_value = crc32(crc_value, &target[DL_CRC_SIZE], msg_size-DL_CRC_SIZE);
	DL_ENCODE_CRC(target, crc_value);

	return msg_size;
}

int32_t dl_message_set_get_size(struct dl_message_set *message_set)
{
	struct dl_message const *message;
	int32_t msg_set_size = 0;

	msg_set_size += DL_MESSAGE_SET_SIZE_SIZE + DL_OFFSET_SIZE;
	
	SLIST_FOREACH(message, message_set, dlm_entries) {
		msg_set_size += dl_message_get_size(message);
	}
	return msg_set_size;
}

static int32_t dl_message_get_size(struct dl_message *message)
{
	DL_ASSERT(message != NULL, "Message cannot be NULL");

	return DL_CRC_SIZE + DL_MAGIC_BYTE_SIZE + DL_ATTRIBUTES_SIZE +
	    DL_TIMESTAMP_SIZE + sizeof(int32_t) + message->dlm_key_len +
	    sizeof(int32_t) + message->dlm_value_len;
}


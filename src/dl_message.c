/*-
 * Copyright (c) 2017 (Graeme Jenkinson)
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

#include "dl_message.h"

static const int ATTRIBUTES_FIELD_SIZE = 12;
static const int CRC_FIELD_SIZE = 16;
static const int KEY_SIZE_FIELD_SIZE = 4;
static const int TIMESTAMP_FIELD_SIZE = 16;
static const int VALUE_SIZE_FIELD_SIZE = 4;

int
dl_encode_message(struct dl_message *inp, char **st)
{
	char *saveto = *st;
	const char *format="%.*lu%.*lu%.*d%.*d%s%.*d%s";

	return sprintf(saveto, format, CRC_FIELD_SIZE, inp->crc,
	    TIMESTAMP_FIELD_SIZE,inp->timestamp,
	    inp->attributes < 0 ? ATTRIBUTES_FIELD_SIZE-1 : ATTRIBUTES_FIELD_SIZE,
	    inp->attributes, KEY_SIZE_FIELD_SIZE, strlen(inp->key), inp->key,
	    VALUE_SIZE_FIELD_SIZE, strlen(inp->value), inp->value);
}

int
dl_parse_message(struct dl_message *inp, char *beg)
{
	unsigned long temp_var_crc = get_long(beg, CRC_FIELD_SIZE);
	inp->crc = temp_var_crc;
	unsigned long temp_var_timestamp = get_long(beg+CRC_FIELD_SIZE,
	    TIMESTAMP_FIELD_SIZE);
	inp->timestamp = temp_var_timestamp;
	int temp_var_attributes =
	    get_int(beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE,
		ATTRIBUTES_FIELD_SIZE);
	inp->attributes = temp_var_attributes;
	int read_var_key =
	    get_int(beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+
		ATTRIBUTES_FIELD_SIZE, KEY_SIZE_FIELD_SIZE);
	char* krya_key = inp->key;
	get_val(&krya_key, beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+
	    ATTRIBUTES_FIELD_SIZE+KEY_SIZE_FIELD_SIZE, read_var_key);
	krya_key[read_var_key] = '\0';
	int read_var_value = get_int(beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+
	    ATTRIBUTES_FIELD_SIZE+KEY_SIZE_FIELD_SIZE+read_var_key,
	    VALUE_SIZE_FIELD_SIZE);
	char* krya_value = inp->value;
	get_val(&krya_value, beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+
	    ATTRIBUTES_FIELD_SIZE+KEY_SIZE_FIELD_SIZE+read_var_key+
	    VALUE_SIZE_FIELD_SIZE, read_var_value);
	krya_value[read_var_value] = '\0';

	return CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+ATTRIBUTES_FIELD_SIZE+
	    KEY_SIZE_FIELD_SIZE+read_var_key+VALUE_SIZE_FIELD_SIZE+
	    read_var_value;
}



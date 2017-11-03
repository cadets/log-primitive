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

#include <stdio.h>
#include <assert.h>
#include <strings.h>

#include <string.h>
#include <time.h>

#include "caml_common.h"
#include "protocol_common.h"
#include "protocol.h"
#include "protocol_parser.h"
#include "protocol_encoder.h"
#include "utils.h"

unsigned short PRIO_LOG = PRIO_HIGH; 
extern int MTU;

void
gen_random_string(char *s, const int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}


int
main()
{    
	struct Message inmsg, outmsg;

	char* out = (char*) malloc(sizeof(char) * MTU);
	gen_random_string(inmsg.key, 10);
	gen_random_string(inmsg.value, 10);

	encode_message(&inmsg, &out);

	parse_message(&outmsg, out);

	assert(inmsg.CRC == outmsg.CRC);
	assert(inmsg.Attributes == outmsg.Attributes);

	assert(strcmp(inmsg.key, outmsg.key) == 0);
	assert(strcmp(inmsg.value, outmsg.value) == 0);

	    return 1;
}

/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#include <zlib.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "message.h"
#include "protocol.h"
#include "protocol_common.h"
#include "protocol_encoder.h"
#include "utils.h"

extern segment ptr_seg;

int
read_msg(int fd, char **saveto)
{
    char* buffer = *saveto;

    int ret = recv(fd, buffer, overall_msg_field_size, 0);
    buffer[overall_msg_field_size] = '\0';
    debug(PRIO_LOW, "Read %d bytes (%s)...\n", ret, buffer);
    if(ret > 0){
        int msg_num_bytes = atoi(buffer);
        int expected_num = msg_num_bytes - overall_msg_field_size;
        debug(PRIO_LOW, "\tNumber of bytes: %d\n", msg_num_bytes);

        ret = recv(fd, buffer, expected_num, 0);
        debug(PRIO_LOW, "\tRead %d characters; expected %d\n", ret, expected_num);
        buffer[ret] = '\0';
        debug(PRIO_LOW, "\tREAD TEXT: '%s'\n", buffer);
		return expected_num;
    }else{
        return -1;
    }
}


unsigned long
get_crc(char* text_message, int message_size)
{
    unsigned long crc = crc32(0L, Z_NULL, 0);

    const unsigned char* t = (const unsigned char*) text_message;

    crc = crc32(crc, t, message_size);

    debug(PRIO_LOW, "crc('%s'[%d])=%lu\n", text_message, message_size, crc);
    return crc;
}

void get_val(char** saveto, char* beg, int field_size){
    debug(PRIO_LOW, "GETTING VAL FROM '%s' of size %d\n", beg, field_size);
    memcpy(*saveto, beg, field_size);
}

// The logic is the following:
// The message is followed by the size written in from of it.
int
get_int(char* beg, int field_size){
    debug(PRIO_LOW, "GETTING INT FROM '%s' of size %d\n", beg, field_size);
    char temp[field_size+1];
    char* tt = temp;
    temp[field_size] = '\0';

    get_val(&tt, beg, field_size);
    int i = atoi(tt);

    return i;
}

long
get_long(char * beg, int field_size)
{
    debug(PRIO_LOW, "GETTING LONG FROM '%s' of size %d\n", beg, field_size);
    char temp[field_size+1];
    char* tt = temp;
    temp[field_size] = '\0';

    get_val(&tt, beg, field_size);
    long i = atol(tt);

    return i;
}

unsigned long
toul(char * to)
{
    unsigned long tcrc;
    sscanf(to, "%lu", &tcrc);
    return tcrc;
}

int
wrap_with_size(struct ResponseMessage *rm, char **buf, char *send_out_buf,
	enum request_type rt)
{
	int req_size = encode_responsemessage(rm, buf, match_requesttype(rt));
	int fi = sprintf(send_out_buf, "%.*d%s", OVERALL_MSG_FIELD_SIZE,
		req_size+OVERALL_MSG_FIELD_SIZE, *buf);
	return fi;
}

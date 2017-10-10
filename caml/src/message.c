#include <zlib.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../headers/message.h"
#include "../headers/protocol.h"
#include "../headers/protocol_common.h"
#include "../headers/protocol_encoder.h"
#include "../headers/utils.h"

extern segment ptr_seg;

int read_msg(int fd, char** saveto){

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


unsigned long get_crc(char* text_message, int message_size){
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
int get_int(char* beg, int field_size){
    debug(PRIO_LOW, "GETTING INT FROM '%s' of size %d\n", beg, field_size);
    char temp[field_size+1];
    char* tt = temp;
    temp[field_size] = '\0';

    get_val(&tt, beg, field_size);
    int i = atoi(tt);

    return i;
}

long get_long(char* beg, int field_size){

    debug(PRIO_LOW, "GETTING LONG FROM '%s' of size %d\n", beg, field_size);
    char temp[field_size+1];
    char* tt = temp;
    temp[field_size] = '\0';

    get_val(&tt, beg, field_size);
    long i = atol(tt);

    return i;
}

unsigned long toul(char* to){
    unsigned long tcrc;
    sscanf(to, "%lu", &tcrc);
    return tcrc;
}

int wrap_with_size(struct ResponseMessage* rm, char** buf, char* send_out_buf, enum request_type rt){
    int req_size = encode_responsemessage(rm, buf, match_requesttype(rt));
    int fi = sprintf(send_out_buf, "%.*d%s", OVERALL_MSG_FIELD_SIZE, req_size+OVERALL_MSG_FIELD_SIZE, *buf);
    return fi;
}


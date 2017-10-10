#ifndef MESSAGE_H
#define MESSAGE_H
#include "../headers/protocol.h"

static int      clientId_field_size = 4;
static int   overall_msg_field_size = 4;
static int correlationId_field_size = 4;
static int          type_field_size = 3;

// Insert request variables.
static int           crc_field_size = 20;
static int           msg_field_size = 4;

static int MTU = 2000;
static int MSG_POOL_SIZE = 16;

unsigned long get_crc(char* text_message, int message_size);
void get_val(char** saveto, char* beg, int field_size);
int get_int(char* beg, int field_size);
long get_long(char* beg, int field_size);

int read_msg(int fd, char** saveto);

int wrap_with_size(struct ResponseMessage* rm, char** buf, char* send_out_buf, enum request_type rt);

#endif

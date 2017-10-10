#ifndef CAML_COMMON_H
#define CAML_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../headers/protocol.h" 

static int MAX_NUM_REQUESTS_PER_PROCESSOR  = 128; // Maximum outstanding requests per processor.
static int NUM_PROCESSORS                  = 10;   // Number of processors.
static int MAX_NUM_RESPONSES_PER_PROCESSOR = 128; // Maximum outstanding responses per processor.
static int CONNECTIONS_PER_PROCESSOR       = 10; // Number of connections per processor.
static int MAX_NUM_UNFSYNCED = 20; // Maximum number of unfsynced inserts

typedef void* (*mallocfunctiontype)(unsigned long);
typedef void (*freefunctiontype)(void*);

typedef void (*ack_function)(unsigned long);
typedef void (*response_function)(struct RequestMessage *rm, struct ResponseMessage *rs);

static mallocfunctiontype ilia_alloc = &malloc;
static freefunctiontype ilia_free = &free;

typedef int correlationId_t;

enum broker_confs{
    BROKER_SEND_ACKS= 1 << 1,
    BROKER_FSYNC_ALWAYS= 1 << 2,
};

struct broker_configuration{
    int fsync_thread_sleep_length;
    int processor_thread_sleep_length;
    int val;
};

struct client_configuration{
    int to_resend;
    int resender_thread_sleep_length;
    int request_notifier_thread_sleep_length;

    int reconn_timeout;
    int poll_timeout;

    ack_function on_ack;
    response_function on_response;
};

void print_configuration(struct broker_configuration* bc);
#endif

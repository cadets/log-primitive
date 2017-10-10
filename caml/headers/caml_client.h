#ifndef CAML_CLIENT_H
#define CAML_CLIENT_H
#define MAX_SIZE_HOSTNAME 16

#include "pthread.h"
#include "../headers/protocol.h"
#include "../headers/protocol_common.h"
#include "../headers/caml_common.h"

static int NUM_NOTIFIERS = 5;
static int NUM_READERS   = 1;
static int REQUESTS_PER_NOTIFIER = 10;
static int NODE_POOL_SIZE = 128; // number of maximum outstanding un-acked messages


struct notifier_argument{
    int index;
    pthread_t* tid;
    struct client_configuration *config;

    ack_function on_ack;
    response_function on_response;
};

struct reader_argument{
    int index;
    pthread_t* tid;
    struct client_configuration *config;

    char hostname[MAX_SIZE_HOSTNAME];
    int portnumber;
};


typedef struct notifier_argument notifier_argument;
typedef struct reader_argument reader_argument;

void client_busyloop(const char *hostname, int portnumber, struct client_configuration* cc);

int send_request(int server_id, enum request_type rt, int correlationId, char* clientId, int should_resend, int resend_timeout, ...);
#endif

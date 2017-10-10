#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <pthread.h>
#include "../headers/caml_common.h" 

struct processor_argument{
    int index;
    pthread_t *tid;
    struct broker_configuration *config;
};

typedef struct processor_argument processor_argument;

#endif

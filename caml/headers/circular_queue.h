
#include <stdlib.h>
#include <pthread.h>

struct CircularQueue{
    int rear, front, size, num_elems;
    void **arr;
    pthread_mutex_t mtx;
};

typedef struct CircularQueue CircularQueue;

void create_circular_queue(CircularQueue* pcq, int size);
int enqueue(CircularQueue* pcq, void* elem, size_t elem_size);
int dequeue(CircularQueue* pcq, void* saveto, size_t elem_size);
void display_queue(CircularQueue* cq);
CircularQueue* allocate_circ_queue_per_num_processors(int top_arr_size, int low_arr_size, int arr_elem_size);
void lock_cq(CircularQueue* cq);
void ulock_cq(CircularQueue* cq);

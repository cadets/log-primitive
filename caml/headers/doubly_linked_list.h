
#ifndef DDL_H
#define DDL_H

#include <stddef.h>
#include <pthread.h>

#include "../headers/utils.h"

struct DLLNode{
  void* val;
  struct DLLNode *next;
  struct DLLNode *prev;
  int fd;
};

typedef struct DLLNode DLLNode;

struct DLL{
    int cur_num;
    DLLNode *head;
    DLLNode *last_valid;
    size_t elem_size;
    pthread_mutex_t mtx;
};

typedef struct DLL DLL;

DLLNode* append_to_dll(DLL* dll, void* val, int val_size);
void remove_from_dll(DLL* dll, DLLNode* ppcn);
void print_dll(DLL* dll);
DLL* allocate_dlls_per_num_processors(int top_arr_size, int low_arr_size);

void preallocate_with(DLL* mdll, int top_arr_size, int low_arr_size, size_t alloc_size);
DLLNode* borrow(DLL* pdll);
void returnObj(DLL* pdll, DLLNode* pcn);
void ulock_dll(DLL* pdll);
void lock_dll(DLL* pdll);
void lretu_dll(DLL* pool, DLLNode* obj);
DLLNode* lboru_dll(DLL* pool);
int lboru_dlls(DLLNode** nodes, int num_nodes, ...);

#endif

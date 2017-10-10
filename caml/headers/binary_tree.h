#ifndef BT_H
#define BT_H

#include "../headers/caml_common.h"
#include "../headers/doubly_linked_list.h"

struct bt_node{

    void *val;
	DLLNode* me;

	int height;
	correlationId_t key;

    struct bt_node *left;
    struct bt_node *right;

    int should_resend;
    unsigned long last_sent, resend_timeout;
};

typedef struct bt_node bt_node;

struct bt_holder{
    bt_node* bt;
    pthread_mutex_t mtx;
};

typedef struct bt_holder bt_holder;

void init_bt_holder(struct bt_holder *h);

bt_node* new_node(correlationId_t key, DLLNode** dnode, void *grq);
bt_node* insert(bt_node *node, correlationId_t key, DLLNode** dnode, void *grq);

bt_node *delete_node(bt_node *root, correlationId_t key);
void print_bt(bt_node *root);

int height(bt_node* n);
bt_node* search(bt_node* root, correlationId_t key);

void lock_bth(struct bt_holder* bth);
void ulock_bth(struct bt_holder* bth);
#endif


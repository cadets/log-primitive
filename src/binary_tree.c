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

#include <pthread.h>

#include "binary_tree.h"
#include "doubly_linked_list.h"
#include "caml_common.h"

int
height(bt_node *n)
{
	if (!n)
		return 0;
	return n->height;
}

void
lock_bth(struct bt_holder *bth)
{
	pthread_mutex_lock(&bth->mtx);
}

void
ulock_bth(struct bt_holder *bth)
{
	pthread_mutex_unlock(&bth->mtx);
}

void
init_bt_holder(struct bt_holder *h)
{
	if (pthread_mutex_init(&h->mtx, NULL) != 0){
		debug(PRIO_HIGH, "Binary tree mutex init failed\n");
	}
}


bt_node *
new_node(correlationId_t key, DLLNode **dnode_ptr, void *grq)
{
	DLLNode* dnode = *dnode_ptr;
	bt_node *nnode = (bt_node*)dnode->val;

	nnode->key = key;
	nnode->left = NULL;
	nnode->right = NULL;
	nnode->height = 1;
	nnode->me = dnode;
	nnode->val = grq;

	return nnode;
}

int
max(int a, int b)
{
	return (a > b)? a : b;
}

// A utility function to right rotate subtree rooted with y
// See the diagram given above.
bt_node *
right_rotate(bt_node *y)
{
	bt_node *x  = y->left;
	bt_node *T2 = x->right;

	// Perform rotation
	x->right = y;
	y->left = T2;

	// Update heights
	y->height = max(height(y->left), height(y->right))+1;
	x->height = max(height(x->left), height(x->right))+1;

	// Return new root
	return x;
}

bt_node *
left_rotate(bt_node *x)
{
	bt_node *y = x->right;
	bt_node *T2 = y->left;

	// Perform rotation
	y->left = x;
	x->right = T2;

	//  Update heights
	x->height = max(height(x->left), height(x->right))+1;
	y->height = max(height(y->left), height(y->right))+1;

	// Return new root
	return y;
}

int
get_balance_factor(bt_node *N)
{
	if(!N)
		return 0;
	return height(N->left) - height(N->right);
}

// Recursive function to insert key in subtree rooted
// with node and returns new root of subtree.
bt_node *
insert(bt_node *node, correlationId_t key, DLLNode **dnode, void *grq)
{
	if (!node)
		return(new_node(key, dnode, grq));

	if (key < node->key) {
		node->left  = insert(node->left, key, dnode, grq);
	} else if (key > node->key) {
		node->right = insert(node->right, key, dnode, grq);
	} else { // Equal keys are not allowed in BST
		return node;
	}

	/* 2. Update height of this ancestor node */
	node->height = 1 + max(height(node->left), height(node->right));

	/* 3. Get the balance factor of this ancestor
	  node to check whether this node became
	  unbalanced */
	int balance = get_balance_factor(node);

	// If this node becomes unbalanced, then
	// there are 4 cases

	// Left Left Case
	if (balance > 1 && key < node->left->key)
		return right_rotate(node);

	// Right Right Case
	if (balance < -1 && key > node->right->key)
		return left_rotate(node);

	// Left Right Case
	if (balance > 1 && key > node->left->key) {
		node->left =  left_rotate(node->left);
		return right_rotate(node);
	}

	// Right Left Case
	if (balance < -1 && key < node->right->key) {
		node->right = right_rotate(node->right);
		return left_rotate(node);
	}

	/* return the (unchanged) node pointer */
	return node;
}

// A utility function to print preorder traversal
// of the tree.
// The function also prints height of every node
void
pre_order(bt_node *root)
{
	if (root) {
		printf("%d(Bt: %p/Val: %p/Me: %p)\n",
			root->key, root, root->val, root->me);
		pre_order(root->left);
		pre_order(root->right);
	}
}

void
print_bt(bt_node *root)
{
	printf("===============\n");
	pre_order(root);
	printf("===============\n");
}


/* Given a non-empty binary search tree, return the
   node with minimum key value found in that tree.
   Note that the entire tree does not need to be
   searched. */
bt_node *
get_min_value_node(bt_node *node)
{
	bt_node *current = node;

	/* loop down to find the leftmost leaf */
	while (current->left)
		current = current->left;

	return current;
}

// Recursive function to delete a node with given key
// from subtree with given root. It returns root of
// the modified subtree.
bt_node *
delete_node(bt_node *root, correlationId_t key)
{
	// STEP 1: PERFORM STANDARD BST DELETE
	if (!root)
		return root;

	// If the key to be deleted is smaller than the
	// root's key, then it lies in left subtree
	if (key < root->key) {
		root->left = delete_node(root->left, key);
	// If the key to be deleted is greater than the
	// root's key, then it lies in right subtree
	} else if( key > root->key ) {
		root->right = delete_node(root->right, key);
	// if key is same as root's key, then This is
	// the node to be deleted
	} else {
		// node with only one child or no child
		if((!root->left) || (!root->right)) {
			bt_node *temp = root->left ? root->left : root->right;

			// No child case
			if(!temp){
				temp = root;
				root = NULL;
			} else { // One child case
				*root = *temp; // Copy the contents of
					    // the non-empty child
				//TODO Need to dicede what to do in this case;
				//Basically if it is in already maybe you want to return in here to
				//the pool. For now assuming it cant happen;
				//free(temp);
					//returnObj(val_return_pool, (DLLNode*) temp->val);
					//returnObj(node_pool, temp->me);
			}
		} else {
			// node with two children: Get the inorder
			// successor (smallest in the right subtree)
			bt_node *temp = get_min_value_node(root->right);

			// Copy the inorder successor's data to this node
			root->key = temp->key;
			root->me  = temp->me;
			root->val = temp->val;

			// Delete the inorder successor
			root->right = delete_node(root->right, temp->key);
		}
	}

	// If the tree had only one node then return
	if (!root)
		return root;

	// STEP 2: UPDATE HEIGHT OF THE CURRENT NODE
	root->height = 1 + max(height(root->left), height(root->right));

	// STEP 3: GET THE BALANCE FACTOR OF THIS NODE (to
	// check whether this node became unbalanced)
	int balance = get_balance_factor(root);

	// If this node becomes unbalanced, then there are 4 cases

	// Left Left Case
	if (balance > 1 && get_balance_factor(root->left) >= 0)
		return right_rotate(root);

	// Left Right Case
	if (balance > 1 && get_balance_factor(root->left) < 0) {
		root->left =  left_rotate(root->left);
		return right_rotate(root);
	}

	// Right Right Case
	if (balance < -1 && get_balance_factor(root->right) <= 0)
		return left_rotate(root);

	// Right Left Case
	if (balance < -1 && get_balance_factor(root->right) > 0) {
		root->right = right_rotate(root->right);
		return left_rotate(root);
	}

	return root;
}

bt_node *
search(bt_node* root, correlationId_t key){
	if(!root){
		return NULL;
	}

	if(root->key == key){
		return root;
	}

	if(root->key > key){
		return search(root->left, key);
	}

	if(root->key < key){
		return search(root->right, key);
	}

	return NULL;
}

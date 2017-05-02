#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "queue.h"

/* KEY QUEUE STRUCT */
struct queue_t {
    struct node *head;
    struct node *tail;
    int size;
};
/* NODE */
struct node {
    unsigned long key;
    struct node *next;
    struct node *prev;
};

/* QUEUE METHODS */
struct queue_t * 
queue_init () {
	struct queue_t *queue = malloc(sizeof(struct queue_t));
	queue->head = NULL;
	queue->tail = NULL;
	queue->size = 0;
	return queue;
}
struct node * 
pop(struct queue_t *queue) {
	// error check
	assert(queue);

	struct node *node = queue->head;
	if (node == NULL)
		return NULL;
	// no sibling
	if (node->next == NULL)
	{
		queue->head = NULL;
		queue->tail = NULL;
	}
	else
	{
		queue->head = node->next;
		queue->head->prev = NULL;
		node->next = NULL;
	}
	queue->size--;

	return node;
}
void 
push(struct queue_t *queue, struct node *node) {
	// error checks
	assert(queue);

	if (queue->head == NULL)
	{
		// check for first push to head
		queue->head = node;
		queue->tail = node;
		node->prev = NULL;
		node->next = NULL;
	} else {
		// else push to end of queue (tail)
		node->prev = queue->tail;
		queue->tail->next = node;
		node->next = NULL;
		queue->tail = node;
	}
	queue->size++;
	return;
}
void 
queue_destroy (struct queue_t *queue) {
	struct node *node = pop(queue);
	while (node!=NULL) {
		free(node);
		node = pop(queue);
	}
	free(queue);
	return;
}
void
print_queue (struct queue_t *queue) {
	struct node *node = queue->head;
	printf("<");
	while (node!=NULL) {
		printf("-%lu-", node->key);
		node = node->next;
	}
	printf(">\n");
	return;	
}

/* NODE METHODS */
struct node *
node_init (unsigned long key) {
	struct node *node = malloc(sizeof(struct node));
	node->key = key;
	node->next = NULL;
	node->prev = NULL;
	return node;
}
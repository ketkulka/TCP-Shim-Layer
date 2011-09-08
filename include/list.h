#ifndef __LIST_H__
#define __LIST_H__

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "utype.h"

struct queue_node
{
  struct queue_node *next;
  void *data;
};

struct queue
{
  int len;
  struct queue_node *first;
  struct queue_node *last;
};

/* Exported APIs for FIFO/Queue */

int enqueue(struct queue *q, void *value);

int dequeue(struct queue *q, void **value);

void init_queue(struct queue *q);

int queue_len(const struct queue *q);

void *queue_node_next(struct queue_node *node);

struct queue_node* get_qhead(struct queue *qptr);
struct queue_node* get_qtail(struct queue *qptr);


/* Doubly Linked List */

struct dll_node
{
  struct dll_node *prev;
  struct dll_node *next;
  void *data;
};

struct dll
{
  int len;
  struct dll_node *head;
  struct dll_node *tail;
};


/* Exported APIs  for Doubly Linked List */
void              init_dll (struct dll *dll);
struct dll_node * dll_insert_at_tail (struct dll *dll, void *data);
void *            dll_delete_from_head (struct dll *dll);
int               dll_unlink (struct dll *dll, struct dll_node *node);
int               dll_link_at_tail (struct dll *dll, struct dll_node *node);
int               dll_delete_node (struct dll *dll, struct dll_node *node);


#endif

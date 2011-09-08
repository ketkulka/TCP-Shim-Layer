#include <list.h>

int enqueue(struct queue *q, void *value)
{
  struct queue_node *node = malloc(sizeof(struct queue_node));
  if (node == NULL) {
    errno = ENOMEM;
    return 1;
  }
  node->data = value;
  if (q->first == NULL)
    q->first = q->last = node;
  else {
    q->last->next = node;
    q->last = node;
  }
  q->len++;
  node->next = NULL;
  return 0;
}

int dequeue(struct queue *q, void **value)
{
  if (!q->first) {
    *value = NULL;
    return 1;
  }
  *value = q->first->data;
  struct queue_node *tmp = q->first;
  if (q->first == q->last)
    q->first = q->last = NULL;
  else
    q->first = q->first->next;

  q->len--;
  free(tmp);
  return 0;
}

void init_queue(struct queue *q)
{
  q->first = q->last = NULL;
  q->len = 0;
}

int queue_len(const struct queue *q)
{
  return q->len;
}

void *queue_node_next(struct queue_node *node)
{
  void *retptr = NULL;

  retptr = (node->next)?node->next:NULL;

  return retptr;
}

struct queue_node* get_qhead(struct queue *qptr)
{
  return(qptr?qptr->first:NULL);
}

struct queue_node* get_qtail(struct queue *qptr)
{
  return(qptr?qptr->last:NULL);
}

/**** Doubly Linked List **********/
void init_dll(struct dll *dll)
{
  dll->len = 0;
  dll->head = NULL;
  dll->tail = NULL;
}

static inline dll_enqueue (struct dll *dll, struct dll_node *node)
{
    node->prev = node->next = NULL;
    dll->len++;
    if (!dll->tail) {
        dll->tail = dll->head = node;
    } else {
        dll->tail->next = node;
        node->prev = dll->tail;
        dll->tail = node;
    }
}

static inline struct dll_node * dll_dequeue (struct dll *dll)
{
   struct dll_node *ret = dll->head;
   if (unlikely(dll->len <= 0)) {
     return NULL;
   }
   if (ret->next) {
     ret->next->prev = NULL;
     dll->head = ret->next;
     dll->head->prev = NULL;
   } else {
     dll->head = dll->tail = NULL;
   }
   dll->len--;
   ret->next = ret->prev = NULL;
   return ret;
}

struct dll_node * dll_insert_at_tail(struct dll *dll, void *data)
{
  struct dll_node *newnode = malloc(sizeof(struct dll_node));

  if(unlikely(newnode == NULL))
  {
    return NULL;
  }
  dll_enqueue(dll, newnode);
  newnode->data = data;
  return newnode;
}

void * dll_delete_from_head(struct dll *dll)
{
  struct dll_node *node;
  void *data = NULL;
  if (NULL != (node = dll_dequeue(dll))) {
    data = node->data;
    free(node);
  }
  return data;
}

int dll_unlink (struct dll *dll, struct dll_node *node)
{
  if (unlikely(!node || (dll->len <= 0))) {
    return -1;
  }
  if (node->prev) {
    node->prev->next = node->next;
  }
  if (node->next) {
    node->next->prev = node->prev;
  }
  if (dll->head == node) {
    dll->head = node->next;
    if (dll->head) {
        dll->head->prev = NULL;
    }
  }
  if (dll->tail == node) {
    dll->tail = node->prev;
    if (dll->tail) {
        dll->tail->next = NULL;
    }
  }
  dll->len--;
  return 0;
}

int dll_link_at_tail (struct dll *dll, struct dll_node *node)
{
  if (!dll || !node) {
    return -1;
  }
  dll_enqueue(dll, node);
  return 0;
}

int dll_delete_node(struct dll *dll, struct dll_node *node)
{
  if (unlikely(!dll || !node || (dll->len <= 0))) {
      printf("dll %p node %p dll->len %d\n",dll,node,(dll)?dll->len:-8888);
    return -1;
  }
  dll_unlink(dll,node);
  free(node);
  return 0; 
}

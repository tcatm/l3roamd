/**
 * A very simple doubly linked list.
 *
 * @author Nils Schneider
 */

#include <stdlib.h>
#include <assert.h>
#include "linkedlist.h"

void list_new(LinkedList *list) {
  list->head = NULL;
  list->tail = NULL;
}

void list_free(LinkedList *list) {
  ListNode *i = list->head;
  ListNode *next;

  while (i != NULL) {
    next = i->next;
    list_remove(list, i);
    i = next;
  }
}

ListNode *list_new_node(void *e) {
  ListNode *node;

  node = malloc(sizeof(ListNode));

  if (node == NULL)
    return NULL;

  node->e = e;
  node->prev = NULL;
  node->next = NULL;

  return node;
}

ListNode *list_insert(LinkedList *list, ListNode *node, void *e) {
  ListNode *new_node;

  if (list == NULL)
    return NULL;

  new_node = list_new_node(e);

  // Check whether malloc succeeded.
  // Return NULL in case of failure.
  if (new_node == NULL)
    return NULL;

  // Update tail when inserting after the last element the list
  if (node == list->tail)
    list->tail = new_node;

  if (list->head == NULL)
    list->head = new_node;

  // Update pointers to adjacent nodes
  new_node->prev = node;

  if (node != NULL) {
    new_node->next = node->next;

    if (node->next != NULL)
      node->next->prev = new_node;

    // Insert node into existent list.
    node->next = new_node;
  }

  return new_node;
}

bool list_remove(LinkedList *list, ListNode *node) {
  if (list == NULL || node == NULL)
    return false;

  if (list->head == node)
    list->head = node->next;

  if (list->tail == node)
    list->tail = node->prev;

  if (node->prev != NULL)
    node->prev->next = node->next;

  if (node->next != NULL)
    node->next->prev = node->prev;

  free(node);

  return true;
}

ListNode *list_push(LinkedList *list, void *e) {
  return list_insert(list, list->tail, e);
}

ListNode *list_unshift(LinkedList *list, void *e) {
  ListNode *node;

  if (list == NULL)
    return NULL;

  node = list_new_node(e);

  if (node == NULL)
    return NULL;

  node->next = list->head;

  if (list->head)
    list->head->prev = node;

  list->head = node;

  if (list->tail == NULL)
    list->tail = node;

  return node;
}

void *list_pop(LinkedList *list) {
  bool ret;
  void *e;

  if (list->tail == NULL)
    return NULL;

  e = list->tail->e;

  ret = list_remove(list, list->tail);

  if (ret == false)
    return NULL;

  return e;
}

void *list_shift(LinkedList *list) {
  bool ret;
  void *e;

  if (list->head == NULL)
    return NULL;

  e = list->head->e;

  ret = list_remove(list, list->head);

  if (ret == false)
    return NULL;

  return e;
}

bool list_is_empty(LinkedList *list) {
  if (list == NULL)
    return true;

  if (list->head == NULL && list->tail == NULL)
    return true;

  return false;
}

/* This function performs a merge sort with O(n log n) */
bool list_sort(LinkedList *list, int(*compar)(const void *, const void *)) {
  LinkedList *new_list;
  ListNode *node_a, *node_b;
  void *e;
  int merges, slice_size, slice_b, slice_a;

  if (list_is_empty(list))
    return true;

  slice_size = 1;

  do {
    merges = 0;
    node_a = list->head;

    new_list = malloc(sizeof(LinkedList));
    assert(new_list != NULL);
    list_new(new_list);

    while (node_a != NULL) {
      merges++;
      node_b = node_a;

      slice_a = 0;
      slice_b = slice_size;

      while (slice_a < slice_size && node_b != NULL) {
        node_b = node_b->next;
        slice_a++;
      }

      while (slice_a > 0 || (slice_b > 0 && node_b != NULL)) {
        if (slice_a == 0) {
          e = node_b->e;
          node_b = node_b->next;
          slice_b--;
        } else if (slice_b == 0 || node_b == NULL) {
          e = node_a->e;
          node_a = node_a->next;
          slice_a--;
        } else if (compar(node_a->e, node_b->e) <= 0) {
          e = node_a->e;
          node_a = node_a->next;
          slice_a--;
        } else {
          e = node_b->e;
          node_b = node_b->next;
          slice_b--;
        }

        list_push(new_list, e);
      }

      node_a = node_b;
    }

    list_free(list);
    list->head = new_list->head;
    list->tail = new_list->tail;
    free(new_list);

    slice_size *= 2;
  } while (merges > 1);

  return true;
}

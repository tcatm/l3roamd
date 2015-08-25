/**
 * A very simple doubly linked list.
 *
 * @author Nils Schneider
 */

#pragma once

#include <stdbool.h>

/*! List element */
typedef struct _node {
  // Pointer to content of this node
  void *e;

  // Pointer to next and previous elements in list
  struct _node *next;
  struct _node *prev;
} ListNode;

/*! List */
typedef struct _list {
  ListNode *head;
  ListNode *tail;
} LinkedList; 

/**
 * Creates a new LinkedList
 *
 * @return Pointer to new LinkedList, or NULL in case of error.
 */
void list_new(LinkedList *list);

/**
 * Deletes a LinkedList by freeing up all memory allocated
 * by the list.
 *
 * This function does not free memory allocated by pointers to
 * each node's content!
 *
 * @param list  List to be freed.
 */
void list_free(LinkedList *list);

/**
 * Create a new ListNode
 *
 * @param e   Pointer to element associated with new node
 *
 * @return Pointer to new ListNode, or NULL in case of error
 */
ListNode *list_new_node(void *e);

/**
 * Create a new list node and insert it to after
 * a given node. If the pointer is NULL a new list is created
 * and the pointer is updated to point to the list's head.
 *
 * @param list  List
 * @param node  Pointer to node after which this element is inserted.
 * @param e     Pointer to content of new node.
 *
 * @return The inserted node or NULL in case of error.
 */
ListNode *list_insert(LinkedList *list, ListNode *node, void *e);

/**
 * Remove a given node from the list.
 *
 * @param list    List
 * @param node    Node to remove.
 *
 * @return true on success, false on failure
 */
bool list_remove(LinkedList *list, ListNode *node);

/**
 * Adds a given element to the end of the list.
 *
 * @param list  List
 * @param e     Pointer of element to be added
 * 
 * @return The new ListNode or NULL in case of error.
 */
ListNode *list_push(LinkedList *list, void *e);

/**
 * Adds a given element in front of the list.
 *
 * @param list  List
 * @param e     Pointer of element to be added
 * 
 * @return The new ListNode or NULL in case of error.
 */
ListNode *list_unshift(LinkedList *list, void *e);

/**
 * Removes the first element from the list and returns it.
 *
 * @param list  List
 * 
 * @return Pointer to element, or NULL in case of error.
 */
void *list_shift(LinkedList *list);

/**
 * Removes the last element from the list and returns it.
 *
 * @param list  List
 * 
 * @return Pointer to element, or NULL in case of error.
 */
void *list_pop(LinkedList *list);

/**
 * Test whether a list is empty.
 *
 * @return true if list is empty, false if not
 */
bool list_is_empty(LinkedList *list);

/**
 * Sorts a list in-place.
 *
 * @param list    List to be sorted
 * @param compar  Comparison function
 *
 * @return true if sorting was successful, otherwise false
 */
bool list_sort(LinkedList *list, int(*compar)(const void *, const void *));

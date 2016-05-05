#pragma once

#include <time.h>
#include <stdbool.h>

typedef struct taskqueue taskqueue_t;

typedef struct {
	struct l3ctx *l3ctx;
	int fd;
	taskqueue_t *queue;
} taskqueue_ctx;

/** Element of a priority queue */
struct taskqueue {
	taskqueue_t **pprev;		/**< \e next element of the previous element (or \e children of the parent) */
	taskqueue_t *next;		/**< Next sibling in the heap */

	taskqueue_t *children;	/**< Heap children */

	struct timespec due;			/**< The priority */

	int refcnt;

	void (*function)(void*);
	void (*cleanup)(void*);
	void *data;
};

/** Checks if an element is currently part of a priority queue */
static inline bool taskqueue_linked(taskqueue_t *elem) {
	return elem->pprev;
}

void taskqueue_insert(taskqueue_t **queue, taskqueue_t *elem);
void taskqueue_remove(taskqueue_t *elem);

void taskqueue_init(taskqueue_ctx *ctx);
void taskqueue_run(taskqueue_ctx *ctx);
void taskqueue_schedule(taskqueue_ctx *ctx);
void take_task(taskqueue_t *task);
bool put_task(taskqueue_t *task);
taskqueue_t * post_task(taskqueue_ctx *ctx, unsigned int timeout, void (*function)(void*), void (*cleanup)(void*), void *data);
taskqueue_t * replace_task(taskqueue_ctx *ctx, taskqueue_t * task, unsigned int timeout, void (*function)(void*), void (*cleanup)(void*), void *data);

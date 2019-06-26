/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <stdbool.h>
#include <time.h>

typedef struct taskqueue taskqueue_t;

typedef struct {
	taskqueue_t *queue;
	int fd;
} taskqueue_ctx;

/** Element of a priority queue */
struct taskqueue {
	taskqueue_t **pprev; /**< \e next element of the previous element (or \e
				children of the parent) */
	taskqueue_t *next;   /**< Next sibling in the heap */

	taskqueue_t *children; /**< Heap children */

	struct timespec due; /**< The priority */

	void (*function)(void *);
	void (*cleanup)(void *);
	void *data;
};

/** Checks if an element is currently part of a priority queue */
static inline bool taskqueue_linked(taskqueue_t *elem) { return elem->pprev; }

void taskqueue_insert(taskqueue_t **queue, taskqueue_t *elem);
void taskqueue_remove(taskqueue_t *elem);

void taskqueue_init(taskqueue_ctx *ctx);
void taskqueue_run(taskqueue_ctx *ctx);
void taskqueue_schedule(taskqueue_ctx *ctx);
taskqueue_t *post_task(taskqueue_ctx *ctx, time_t timeout,
		       long millisecs, void (*function)(void *),
		       void (*cleanup)(void *), void *data);
void drop_task(taskqueue_t *task);
bool reschedule_task(taskqueue_ctx *ctx, taskqueue_t *task,
		     time_t timeout, long millisecs);

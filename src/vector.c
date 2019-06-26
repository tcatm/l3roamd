/*
 * Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
   \file

   Typesafe dynamically sized arrays
*/

#include "vector.h"
#include "alloc.h"

#include <string.h>

/** The minimum number of elements to allocate even when less elements are used
 */
#define MIN_VECTOR_ALLOC 4

/**
   Resizes a vector

   Vector allocations are always powers of 2.

   Internal function, use VECTOR_RESIZE() instead.
*/
void _l3roamd_vector_resize(l3roamd_vector_desc_t *desc, void **data, size_t n, size_t elemsize) {
	desc->length = n;

	size_t alloc = desc->allocated;

	if (!alloc) {
		alloc = MIN_VECTOR_ALLOC;
		n = n * 3 / 2;
	}

	while (alloc < n) alloc <<= 1;

	if (alloc != desc->allocated) {
		desc->allocated = alloc;
		*data = l3roamd_realloc(*data, alloc * elemsize);
	}
}

/**
   Inserts an element into a vector

   Internal function, use VECTOR_INSERT() and VECTOR_ADD() instead.
*/
void *_l3roamd_vector_insert(l3roamd_vector_desc_t *desc, void **data, void *element, size_t pos, size_t elemsize) {
	_l3roamd_vector_resize(desc, data, desc->length + 1, elemsize);

	void *p = *data + pos * elemsize;

	memmove(p + elemsize, p, (desc->length - pos - 1) * elemsize);
	memcpy(p, element, elemsize);
	return (p);
}

/**
   Deletes an element from a vector

   Internal function, use VECTOR_DELETE() instead.
*/
void _l3roamd_vector_delete(l3roamd_vector_desc_t *desc, void **data, size_t pos, size_t elemsize) {
	void *p = *data + pos * elemsize;
	memmove(p, p + elemsize, (desc->length - pos - 1) * elemsize);

	_l3roamd_vector_resize(desc, data, desc->length - 1, elemsize);
}

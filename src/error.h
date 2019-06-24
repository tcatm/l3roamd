/*
 * Copyright (c) 2015, Matthias Schiffer <mschiffer@universe-factory.net>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define exit_errno(message) _exit_error(1, errno, "%s", message)

static inline void _exit_error(int status, int errnum, const char *format,
			       ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	if (errnum)
		fprintf(stderr, ": %s\n", strerror(errnum));
	else
		fprintf(stderr, "\n");
	if (status == -1)
		abort();
	exit(status);
}

static inline void exit_error(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	_exit_error(1, 0, format, ap);
	va_end(ap);
}

static inline void exit_bug(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	_exit_error(-1, 0, format, ap);
	va_end(ap);
}

/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once
#include <time.h>

struct timespec timeAdd(struct timespec *t1, struct timespec *t2);
int timespec_cmp(struct timespec a, struct timespec b);

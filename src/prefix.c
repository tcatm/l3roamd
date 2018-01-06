/*
  Copyright (c) 2017, Christof Schulze <christof.schulze@gmx.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "prefix.h"
#include <string.h>

/* this will parse the string str and return a prefix struct
*/
bool parse_prefix(struct prefix *prefix, const char *str) {
	char *saveptr;
	char *tmp = strdupa(str);
	char *ptr = strtok_r(tmp, "/", &saveptr);

	if (ptr == NULL)
		return false;

	int rc = inet_pton(AF_INET6, ptr, &(prefix->prefix));
	if (rc != 1)
		return false;

	ptr = strtok_r(NULL, "/", &saveptr);
	if (ptr == NULL)
		return false;

	prefix->plen = atoi(ptr);
	if (prefix->plen < 0 || prefix->plen > 128)
		return false;

	return true;
}


/* this will add a prefix to the prefix vector, causing l3roamd  to
** accept packets to this prefix as client-prefix
*/
bool add_prefix(void *prefixes, struct prefix _prefix) {
	VECTOR(struct prefix) *_prefixes = prefixes;
	VECTOR_ADD(*_prefixes, _prefix);

	return true;
}

/* this will remove a prefix from the prefix vector, causing l3roamd not to
** accept packets to this prefix as client-prefix
*/
bool del_prefix(void *prefixes, struct prefix _prefix) {
	VECTOR(struct prefix) *_prefixes = prefixes;
	for (int i=0;i<VECTOR_LEN(*_prefixes);i++) {
		if ( !memcmp(&VECTOR_INDEX(*_prefixes, i), &_prefix, sizeof(_prefix) ) ) {
			VECTOR_DELETE(*_prefixes, i);
			return true;
		}
	}

	return false;
}

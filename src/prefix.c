#include "prefix.h"

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


bool add_prefix(void *prefixes, struct prefix _prefix) {
	VECTOR(struct prefix) *_prefixes = prefixes;
	VECTOR_ADD(*_prefixes, _prefix);

	return true;
}

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


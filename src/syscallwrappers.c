#include "syscallwrappers.h"
#include "error.h"

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int obtainrandom(void *buf, size_t buflen, unsigned int flags) {
	int rc = 0;
	while (rc != buflen) {
		rc = (int)syscall(SYS_getrandom, buf, buflen, flags);
		if (rc == -1) {
			if (errno != ENOSYS) {
				exit_error("syscall SYS_getrandom.");
			}
			perror("syscall SYS_getrandom failed. retrying");
		}
	}
	return rc;
}

#include "config.h"
void parse_line(char *line) {
	char delimiter[] = " ";
	char *ptr;
	char *saveptr;
	ptr = strtok_r(line, delimiter, &saveptr);
	printf("key: %s\n", ptr);
	ptr = strtok_r(NULL, delimiter, &saveptr);
	printf("value: %s", ptr);

	// TODO: how to turn key and value into
	// parameters that can actually be used by
	// l3roamd?
	//
	//  attach-mesh-interface
	//  detach-mesh-interface
	//  attach-client-interface
	//  detach-client-interface
	//  add-prefix
	//  remove-prefix
	//  set-export-table
}

bool parse_config(const char *filename) {
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen(filename, "r");
	if (fp == NULL)
		return false;

	while ((read = getline(&line, &len, fp)) != -1)
		parse_line(line);

	fclose(fp);
	free(line);

	return true;
}

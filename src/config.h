#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_line(char *line);
bool parse_config(const char *filename);

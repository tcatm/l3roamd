#pragma once

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

void parse_line(char *line);
  
bool parse_config(const char *filename);

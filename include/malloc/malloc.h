#pragma once

#include <sys/types.h>

void* malloc(size_t size);
void* calloc(size_t len, size_t size_of);
void free(void* p);

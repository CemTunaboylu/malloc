#pragma once

#include <sys/types.h>

void free(void* p);
void* calloc(size_t len, size_t size_of);
void* malloc(size_t size);
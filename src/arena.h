#pragma once

#include <block.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct Arena *ArenaPtr;

struct Arena {
  BlockPtr top;
  ArenaPtr next;
  BlockPtr head;
  BlockPtr tail;
  size_t total_bytes_allocated;
  size_t total_free_bytes;
} Arena;

int is_addr_valid_heap_addr(ArenaPtr, void *);
void allocated_bytes_update(ArenaPtr, int);

extern void debug_write_str(const char *);
extern void debug_write_ptr(const void *);

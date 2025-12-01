#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "block.h"
#include "mm_debug.h"

extern size_t SIZE_OF_BLOCK;

// in case update < 0, it is assumed that |update| bytes are released i.e.
// returned to OS/munmapped
void allocated_bytes_update(ArenaPtr ar_ptr, int update) {
  size_t allocated_bytes = ar_ptr->total_bytes_allocated;
  if (update >= 0) {
    allocated_bytes += update;
  } else {
    size_t decrement = (size_t)(-update);
    MM_ASSERT(allocated_bytes >= decrement);
    allocated_bytes -= decrement;
  }
  ar_ptr->total_bytes_allocated = allocated_bytes;
}

int is_addr_valid_heap_addr(ArenaPtr ar_ptr, void *p) {
  BlockPtr head = ar_ptr->head;
  BlockPtr tail = ar_ptr->tail;
  if (head == NULL)
    return 0;

  void *the_end_of_arena_tail =
      (char *)tail + (get_true_size(tail) + SIZE_OF_BLOCK);
  if ((void *)head > p || the_end_of_arena_tail < p)
    return 0;

  BlockPtr blk = reconstruct_from_user_memory(p);
  if (!do_ends_hold(blk))
    return 0;
  return (p == (void *)allocated_memory(blk));
}

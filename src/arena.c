#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "block.h"
#include "mm_debug.h"

extern size_t SIZE_OF_BLOCK;

// in case update < 0, it is assumed that |update| bytes are released i.e.
// returned to OS/munmapped
void allocated_bytes_update(size_t *total_bytes_allocated, const int update) {
  size_t allocated_bytes = *total_bytes_allocated;
  if (update >= 0) {
    allocated_bytes += update;
  } else {
    size_t decrement = (size_t)(-update);
    MM_ASSERT(allocated_bytes >= decrement);
    allocated_bytes -= decrement;
  }
  *total_bytes_allocated = allocated_bytes;
}

static int sbrked_header_validation(const BlockPtr cand) {
  if (is_at_brk(cand))
    return 0;
  const BlockPtr fw = next(cand);
  return is_at_brk(fw) || (is_free(cand) == is_prev_free(fw));
}

BlockPtr reconstruct_valid_header(void *p) {
  BlockPtr blk = reconstruct_from_user_memory(p);
  // TODO: add hardening here
  if (!is_mmapped(blk)) {
    if (!sbrked_header_validation(blk))
      return NULL;
  } else {
    // TODO: mmapped validation
  }
  if (p != (void *)allocated_memory(blk)) {
    blk = NULL;
  }
  return blk;
}

BlockPtr get_block_from_mmapped_arena(const MMapArenaPtr ar_ptr, void *p) {
  BlockPtr b = ar_ptr->head;
  if (b == NULL)
    return NULL;

  int possibly_a_valid_chunk = 0;
  do {
    if (((void *)b < p) || ((void *)(b)) > p) {
      possibly_a_valid_chunk = 1;
      break;
    }
    b = b->next;
  } while (b->next);

  if (!possibly_a_valid_chunk) {
    return NULL;
  }

  return reconstruct_valid_header(p);
}

BlockPtr get_block_from_main_arena(const ArenaPtr ar_ptr, void *p) {
  const BlockPtr head = ar_ptr->head;
  const BlockPtr tail = ar_ptr->tail;
  if (head == NULL)
    return NULL;

  void *the_end_of_arena_tail =
      (char *)tail + (get_true_size(tail) + SIZE_OF_BLOCK);
  if ((void *)head > p || the_end_of_arena_tail < p)
    return NULL;

  return reconstruct_valid_header(p);
}

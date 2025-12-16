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
  if (is_mmapped(blk)) {
    if (get_true_size(blk) < MIN_CAP_FOR_MMAP)
      return NULL;
  } else {
    if (!sbrked_header_validation(blk))
      return NULL;
  }
  if ((void *)allocated_memory(blk) != p) {
    blk = NULL;
  }
  return blk;
}

BlockPtr get_block_from_mmapped_arena(const MMapArenaPtr ar_ptr, void *p) {
  const size_t total_bytes = ar_ptr->total_bytes_allocated;
  if (0 == ar_ptr->num_mmapped_regions && 0 == total_bytes)
    return NULL;

  BlockPtr blk = reconstruct_valid_header(p);
  if (get_true_size(blk) > total_bytes)
    return NULL;
  if (!is_mmapped(blk))
    return NULL;
  return blk;
}

BlockPtr get_block_from_main_arena(const ArenaPtr ar_ptr, void *p) {
  const BlockPtr head = ar_ptr->head;
  const BlockPtr tail = ar_ptr->tail;
  if (NULL == head)
    return NULL;

  void *the_end_of_arena_tail =
      (char *)tail + (get_true_size(tail) + SIZE_OF_BLOCK);
  if ((void *)head > p || the_end_of_arena_tail < p)
    return NULL;

  return reconstruct_valid_header(p);
}

#ifdef TESTING

size_t num_blocks_in_unsorted_bin(const ArenaPtr ar) {
  const BlockPtr head = BLK_PTR_OF_UNSORTED((*ar));
  BlockPtr cursor = head->next;
  size_t counter = 0;
  while (head != cursor) {
    counter++;
    cursor = cursor->next;
  }
  return counter;
}

extern void print_blk_to_stderr(const BlockPtr b);
extern void print_arrow_to_stderr(void);

void print_bin(ArenaPtr ar, const size_t idx) {
  debug_write_str("--- Bin print ---\n");
  BlockPtr sentinel = BLK_PTR_IN_BIN_AT((*ar), idx);
  if (IS_LONE_SENTINEL(sentinel)) {
    debug_write_str("Bin[");
    debug_write_u64(idx);
    debug_write_str("] is empty\n");
    return;
  }

  BlockPtr b = sentinel->next;
  print_blk_to_stderr(b);
  b = b->next;

  for (; b && sentinel != b; b = b->next) {
    print_arrow_to_stderr();
    print_blk_to_stderr(b);
  }
  debug_write_str("--- Bin print end ---\n");
}
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "block.h"
#include "internal.h"
#include "mm_debug.h"

#define MIN_REQUIRED_SPLIT_SIZE (MAX_ALIGNMENT)

size_t SIZE_OF_BLOCK;

__attribute__((constructor)) void init_aligned_size_of_block(void) {
  SIZE_OF_BLOCK = align(sizeof(struct SBlock));
}

/* ----- LSB encoding ------ */

static size_t LSB_ENCODABLE_CAP;
static size_t LSB_ENCODABLE_MASK;

__attribute__((constructor)) void init_lsb_encodable_cap_and_mask(void) {
  LSB_ENCODABLE_CAP = 1 << NUM_BITS_SPARED_FROM_ALIGNMENT;
  LSB_ENCODABLE_MASK = ~(LSB_ENCODABLE_CAP - 1);
}

size_t get_true_size(BlockPtr b) { return (b->size & LSB_ENCODABLE_MASK); }

#define SET 1
#define UNSET 0

static void encode(BlockPtr b, enum LSB_Flag __LSB_ENCODABLE flag, int set) {
  MM_ASSERT(flag < LSB_ENCODABLE_CAP);
  if (set)
    b->size |= (size_t)flag;
  else
    b->size &= (~(size_t)flag);
}

int is_mmapped(BlockPtr b) { return (b->size & (size_t)MMAPPED) > 0; }

void mark_as_mmapped(BlockPtr b) { encode(b, MMAPPED, SET); }

int is_free(BlockPtr b) { return (b->size & (size_t)FREE) > 0; }

void mark_as_free(BlockPtr b) { encode(b, FREE, SET); }

void mark_as_used(BlockPtr b) { encode(b, FREE, UNSET); }

/* ----- mmap support ----- */

void *allocated_memory(BlockPtr b) {
  char *e = (char *)b + SIZE_OF_BLOCK;
  return ((void *)e);
}

void *end(BlockPtr b) {
  return (void *)((char *)allocated_memory(b) + b->size);
}

int do_ends_hold(BlockPtr b) { return (end(b) == b->end_of_alloc_mem); }

void deep_copy_block(BlockPtr src, BlockPtr to) {
  // int* seems to be UB, to be safe and truly type agnostic, we treat it byte
  // by byte
  unsigned char *src_user_mem = (unsigned char *)allocated_memory(src);
  unsigned char *to_user_mem = (unsigned char *)allocated_memory(to);

  size_t src_size = get_true_size(src);
  size_t to_size = get_true_size(to);

  size_t min = src_size < to_size ? src_size : to_size;
  // hopefully the compiler will vectorize this loop, unroll it and use wider
  // loads/stores internally to optimize
  for (size_t i = 0; i < min; i++) {
    to_user_mem[i] = src_user_mem[i];
  }
}

/* ----- fusion ----- */

int fuse_next(BlockPtr b) {
  if (b->next == NULL) {
    return -1;
  }
  BlockPtr next = b->next;
  if (!is_free(next)) {
    return -1;
  }
  b->size += SIZE_OF_BLOCK + get_true_size(next);
  b->next = next->next;
  b->end_of_alloc_mem = end(b);
  if (next->next)
    next->next->prev = b;
  return 0;
}

void fuse_fwd(BlockPtr b) {
  if (!is_free(b)) {
    return;
  }
  if (b->next == NULL || !is_free(b->next)) {
    return;
  }
  BlockPtr cursor = b;
  do {
    b->size += SIZE_OF_BLOCK + get_true_size(cursor->next);
    cursor = cursor->next;
    MM_FUSE_FWD_CALL();
  } while (cursor->next && is_free(cursor->next));
  b->next = cursor->next;
  b->end_of_alloc_mem = end(b);
  if (cursor->next)
    cursor->next->prev = b;
}

void fuse_bwd(BlockPtr *b) {
  if (!is_free(*b)) {
    return;
  }
  if ((*b)->prev == NULL) {
    return;
  }
  BlockPtr cursor = *b;
  BlockPtr next = (*b)->next;
  while (cursor->prev && is_free(cursor->prev)) {
    BlockPtr prev = cursor->prev;
    prev->size += SIZE_OF_BLOCK + get_true_size(cursor);
    cursor = prev;
    MM_FUSE_BWD_CALL();
  }
  cursor->next = next;
  if (next)
    next->prev = cursor;
  *b = cursor;
  (*b)->end_of_alloc_mem = end(*b);
}

int is_next_fusable(BlockPtr b) {
  BlockPtr next = b->next;
  return ((next != NULL) && (is_free(next)));
}

/* ----- splitting ------ */

int is_splittable(BlockPtr blk, size_t aligned_size) {
  size_t remaining_size = get_true_size(blk) - aligned_size;
  size_t min_splittable_total_block_size =
      SIZE_OF_BLOCK + MIN_REQUIRED_SPLIT_SIZE;
  return (remaining_size > min_splittable_total_block_size);
}

void split_block(BlockPtr b, size_t aligned_size_to_shrink) {
  BlockPtr rem_free =
      (BlockPtr)((char *)allocated_memory(b) + aligned_size_to_shrink);
  rem_free->size = get_true_size(b) - aligned_size_to_shrink - SIZE_OF_BLOCK;
  rem_free->next = b->next;
  rem_free->prev = b;
  if (b->next) {
    b->next->prev = rem_free;
  }
  mark_as_free(rem_free);
  rem_free->end_of_alloc_mem = end(rem_free);
  // TODO: set the flags of b again, below we overwrite them
  int mark_b_as_free = is_free(b);
  b->size = aligned_size_to_shrink;
  b->next = rem_free;
  if (mark_b_as_free)
    mark_as_free(b);

  b->end_of_alloc_mem = end(b);
}

BlockPtr reconstruct_from_user_memory(const void *p) {
  char *b = (char *)p - SIZE_OF_BLOCK;
  return ((BlockPtr)b);
}

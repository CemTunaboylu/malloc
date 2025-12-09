#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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
static size_t LSB_ENCODABLE_ERASURE_MASK;
static size_t LSB_ENCODABLE_ONLY_MASK;

__attribute__((constructor)) void init_lsb_encodable_cap_and_masks(void) {
  LSB_ENCODABLE_CAP = 1 << NUM_BITS_SPARED_FROM_ALIGNMENT;
  LSB_ENCODABLE_ERASURE_MASK = ~(LSB_ENCODABLE_CAP - 1);
  LSB_ENCODABLE_ONLY_MASK = LSB_ENCODABLE_CAP - 1;
}

size_t get_true_size(BlockPtr b) {
  return (b->size & LSB_ENCODABLE_ERASURE_MASK);
}

static inline size_t *get_footer_of(BlockPtr b) {
  size_t *fw = (size_t *)next(b);
  return fw - 1;
}

// Assuming we know that the previous block is free
size_t prev_size(BlockPtr b) { return *((size_t *)b - 1); }

// Assuming we know that the previous block is free
BlockPtr prev(BlockPtr b) {
  int p_size = (int)prev_size(b);
  return (BlockPtr)((char *)b - (p_size + (int)SIZE_OF_BLOCK));
}

#define SET 1
#define UNSET 0

static void encode(BlockPtr b, enum LSB_Flag __LSB_ENCODABLE flag, int set) {
  MM_ASSERT(flag < LSB_ENCODABLE_CAP);
  if (set)
    b->size |= (size_t)flag;
  else
    b->size &= (~(size_t)flag);
}

size_t get_flags(BlockPtr b) { return (b->size & LSB_ENCODABLE_ONLY_MASK); }

void set_flags(BlockPtr b, size_t flags) { encode(b, flags, SET); }

int is_mmapped(BlockPtr b) { return (b->size & (size_t)MMAPPED) > 0; }

void mark_as_mmapped(BlockPtr b) { encode(b, MMAPPED, SET); }

int is_free(BlockPtr b) { return (b->size & (size_t)FREE) > 0; }

int is_prev_free(BlockPtr b) { return (b->size & (size_t)PREV_FREE) > 0; }

static inline void put_size_in_footer(BlockPtr b) {
  size_t *footer = get_footer_of(b);
  *footer = get_true_size(b);
}

static inline void mark_prev_as_free(BlockPtr b) { encode(b, PREV_FREE, SET); }

static inline void mark_prev_as_used(BlockPtr b) {
  encode(b, PREV_FREE, UNSET);
}

void propagate_free_to_next(BlockPtr b) {
  put_size_in_footer(b);

  BlockPtr nxt = next(b);
  if (!is_at_brk(nxt)) {
    mark_prev_as_free(nxt);
  }
}

void propagate_used_to_next(BlockPtr b) {
  BlockPtr nxt = next(b);
  if (!is_at_brk(nxt)) {
    mark_prev_as_used(nxt);
  }
}

void mark_as_free(BlockPtr b) {
  encode(b, FREE, SET);
  propagate_free_to_next(b);
}

void mark_as_used(BlockPtr b) {
  encode(b, FREE, UNSET);
  BlockPtr nxt = next(b);
  if (!is_at_brk(nxt)) {
    mark_prev_as_used(nxt);
  }
}

void transfer_flags(BlockPtr from, BlockPtr to) {
  size_t flags = get_flags(from);
  set_flags(to, flags);
}

void *allocated_memory(BlockPtr b) {
  char *e = (char *)b + SIZE_OF_BLOCK;
  return ((void *)e);
}

void *next(BlockPtr b) {
  return (void *)((char *)allocated_memory(b) + get_true_size(b));
}

int is_at_brk(BlockPtr b) { return (void *)b >= CURRENT_BRK; }

// NOTE: Does not handle head/tail of arenas, those have to be handled within
// the arena
void switch_places_in_list(BlockPtr rem, BlockPtr put) {
  put->next = rem->next;
  put->prev = rem->prev;
  if (put->prev)
    put->prev->next = put;
  if (put->next)
    put->next->prev = put;
}

void deep_copy_user_memory(BlockPtr src, BlockPtr to) {
  // int* seems to be UB, to be safe and truly type agnostic, we treat it byte
  // by byte
  unsigned char *src_user_mem = (unsigned char *)allocated_memory(src);
  unsigned char *to_user_mem = (unsigned char *)allocated_memory(to);

  size_t src_size = get_true_size(src);
  size_t to_size = get_true_size(to);

  size_t min = src_size < to_size ? src_size : to_size;
  memmove(to_user_mem, src_user_mem, min);
}

/* ----- fusion ----- */

int fuse_next(BlockPtr b) {
  if (!is_next_fusable(b))
    return -1;
  BlockPtr nxt = next(b);
  b->size += SIZE_OF_BLOCK + get_true_size(nxt);

  if (is_free(b)) {
    propagate_free_to_next(b);
  } else {
    propagate_used_to_next(b);
  }

  return 0;
}

void fuse_fwd(BlockPtr b) {
  while (fuse_next(b) == 0) {
    MM_MARK(FUSE_FWD_CALLED);
  }
}

// Head always has its prev_free marker unset.
extern void print_list_into_stderr(void);

void fuse_bwd(BlockPtr *b) {
  // TODO: cannot assert this, realloc may fuse with a prev block
  if (!is_free(*b)) {
    return;
  }
  if (!is_prev_free(*b)) {
    return;
  }
  BlockPtr cursor = *b;
  do {
    BlockPtr bk = prev(cursor);
    bk->size += SIZE_OF_BLOCK + get_true_size(cursor);
    cursor = bk;
    MM_MARK(FUSE_BWD_CALLED);
  } while (is_prev_free(cursor));

  // TODO: cannot assert this , realloc may fuse with a prev block
  MM_ASSERT(is_free(cursor));
  if (is_free(cursor))
    propagate_free_to_next(cursor);
  else
    propagate_used_to_next(cursor);
  *b = cursor;
}

int is_next_fusable(BlockPtr b) {
  BlockPtr fw = next(b);
  return (!is_at_brk(fw) && (is_free(fw)));
}

/* ----- splitting ------ */

int is_splittable(BlockPtr blk, size_t aligned_size) {
  if (is_mmapped(blk))
    return 0;
  size_t remaining_size = get_true_size(blk) - aligned_size;
  size_t min_splittable_total_block_size =
      SIZE_OF_BLOCK + MIN_REQUIRED_SPLIT_SIZE;
  return (remaining_size > min_splittable_total_block_size);
}

void split_block(BlockPtr b, size_t aligned_size_to_shrink) {
  size_t bs_flags = get_flags(b);
  BlockPtr rem_free =
      (BlockPtr)((char *)allocated_memory(b) + aligned_size_to_shrink);
  rem_free->size = get_true_size(b) - aligned_size_to_shrink - SIZE_OF_BLOCK;
  mark_as_free(rem_free);

  b->size = aligned_size_to_shrink;
  set_flags(b, bs_flags);

  if (is_free(b))
    propagate_free_to_next(b);
  else
    propagate_used_to_next(b);
}

BlockPtr reconstruct_from_user_memory(const void *p) {
  char *b = (char *)p - SIZE_OF_BLOCK;
  return ((BlockPtr)b);
}
